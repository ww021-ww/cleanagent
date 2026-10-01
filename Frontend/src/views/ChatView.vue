<template>
  <div class="page chat-page">
    <div class="chat-main-panel">
      <div class="chat-header">
        <div class="chat-header-left">
          <el-button link @click="goBack">
            <el-icon><ArrowLeft /></el-icon> 返回检索
          </el-button>
          <h1>漏洞智能问答</h1>
          <p>支持自然语言查询漏洞信息、统计数据与知识检索</p>
        </div>
        <div class="chat-header-right">
          <el-tag :type="wsConnected ? 'success' : 'info'" size="small">
            {{ wsConnected ? '实时模式' : 'REST 模式' }}
          </el-tag>
          <div class="chat-header-subtext">
            {{ activeSessionTitle }}
          </div>
        </div>
      </div>

      <div class="chat-body" ref="bodyRef">
        <div v-if="messages.length === 0" class="chat-empty">
          <el-icon size="48" color="#c0ccda"><ChatDotSquare /></el-icon>
          <p>试着问我：「最近有哪些高危漏洞？」或「CVE-2024-1234 的详情」</p>
        </div>

        <div
          v-for="(msg, i) in messages"
          :key="`${msg.role}-${i}-${msg.ts}`"
          :class="['chat-msg', msg.role]"
        >
          <div class="bubble">
            <span v-if="msg.role === 'assistant'" class="sender">AI</span>
            <span v-else class="sender">你</span>
            <div class="content" v-html="formatContent(msg.content)"></div>
            <span class="ts">{{ msg.ts }}</span>
          </div>
        </div>

        <div v-if="loading" class="chat-msg assistant">
          <div class="bubble">
            <span class="sender">AI</span>
            <div class="content typing">
              <span></span><span></span><span></span>
            </div>
          </div>
        </div>
      </div>

      <div class="chat-input-area">
        <el-input
          v-model="inputText"
          type="textarea"
          :autosize="{ minRows: 1, maxRows: 4 }"
          placeholder="输入问题，Enter 发送，Shift+Enter 换行"
          @keydown.enter.exact.prevent="sendMessage"
          resize="none"
        />
        <el-button
          type="primary"
          :loading="loading"
          :disabled="loading || !inputText.trim()"
          @click="sendMessage"
        >
          发送
        </el-button>
        <el-button
          v-if="loading"
          @click="stopCurrentRequest()"
        >
          停止
        </el-button>
      </div>
    </div>

    <aside class="chat-sidebar">
      <div class="chat-sidebar-header">
        <div>
          <div class="chat-sidebar-title">会话记录</div>
          <div class="chat-sidebar-subtitle">刷新后可恢复，支持切换历史会话</div>
        </div>
        <el-button type="primary" plain @click="createNewSessionAndSelect">
          新建会话
        </el-button>
      </div>

      <div class="chat-session-list">
        <div
          v-for="session in sessions"
          :key="session.session_id"
          :class="['chat-session-item', { active: session.session_id === sessionId }]"
          @click="selectSession(session.session_id)"
        >
          <div class="chat-session-main">
            <div class="chat-session-title-row">
              <span class="chat-session-title">{{ session.title || '新对话' }}</span>
              <span class="chat-session-time">{{ formatSessionTime(session.updated_at) }}</span>
            </div>
            <div class="chat-session-preview">
              {{ session.last_user_message || session.summary || session.last_assistant_message || '还没有消息，开始提问吧' }}
            </div>
          </div>
          <div class="chat-session-actions" @click.stop>
            <el-button link type="primary" @click="renameSession(session.session_id, session.title)">重命名</el-button>
            <el-button link type="danger" @click="removeSession(session.session_id)">删除</el-button>
          </div>
        </div>
      </div>
    </aside>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, nextTick, onMounted, onBeforeUnmount } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { ArrowLeft, ChatDotSquare } from '@element-plus/icons-vue';
import {
  sendChatMessage,
  createChatWebSocket,
  createChatSession,
  deleteChatSession,
  getChatSession,
  listChatSessions,
  renameChatSession,
  type ChatHistoryMessage,
  type ChatSessionSummary,
} from '../api/chat';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  ts: string;
}

const router = useRouter();
const messages = ref<Message[]>([]);
const sessions = ref<ChatSessionSummary[]>([]);
const inputText = ref('');
const loading = ref(false);
const bodyRef = ref<HTMLElement | null>(null);
const wsConnected = ref(false);
const sessionId = ref('');
const userId = 'default';
let ws: WebSocket | null = null;
let wsResponseTimer: number | null = null;
let restAbortController: AbortController | null = null;
let activeRequestToken = 0;
const activeSessionStorageKey = 'cleanagent.chat.activeSession';
const sessionListStorageKey = 'cleanagent.chat.sessions';
const sessionCachePrefix = 'cleanagent.chat.cache.';

const now = () => new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });

const activeSessionTitle = computed(() => {
  const current = sessions.value.find(item => item.session_id === sessionId.value);
  return current?.title || '新对话';
});

const clearWsResponseTimer = () => {
  if (wsResponseTimer !== null) {
    window.clearTimeout(wsResponseTimer);
    wsResponseTimer = null;
  }
};

const scrollToBottom = () => {
  nextTick(() => {
    if (bodyRef.value) {
      bodyRef.value.scrollTop = bodyRef.value.scrollHeight;
    }
  });
};

const formatContent = (text: string) =>
  text.replace(/\n/g, '<br/>').replace(/`([^`]+)`/g, '<code>$1</code>');

const pushMsg = (role: Message['role'], content: string) => {
  messages.value.push({ role, content, ts: now() });
  syncSessionPreview();
  saveCurrentSessionCache();
  scrollToBottom();
};

const persistActiveSessionId = () => {
  if (sessionId.value) {
    localStorage.setItem(activeSessionStorageKey, sessionId.value);
  }
};

const saveSessionListCache = () => {
  localStorage.setItem(sessionListStorageKey, JSON.stringify(sessions.value));
};

const readSessionListCache = () => {
  try {
    const raw = localStorage.getItem(sessionListStorageKey);
    if (!raw) return [];
    return JSON.parse(raw) as ChatSessionSummary[];
  } catch {
    return [];
  }
};

const cacheKeyOfSession = (id: string) => `${sessionCachePrefix}${id}`;

const saveCurrentSessionCache = () => {
  if (!sessionId.value) return;
  localStorage.setItem(cacheKeyOfSession(sessionId.value), JSON.stringify(messages.value));
};

const readSessionCache = (id: string): Message[] => {
  try {
    const raw = localStorage.getItem(cacheKeyOfSession(id));
    if (!raw) return [];
    return JSON.parse(raw) as Message[];
  } catch {
    return [];
  }
};

const stopCurrentRequest = (silent = false, reconnect = true) => {
  clearWsResponseTimer();
  activeRequestToken += 1;
  if (restAbortController) {
    restAbortController.abort();
    restAbortController = null;
  }
  if (ws && wsConnected.value) {
    ws.onmessage = null;
    ws.onerror = null;
    ws.onclose = null;
    ws.close();
    wsConnected.value = false;
    if (reconnect && sessionId.value) {
      initWebSocket(sessionId.value);
    }
  }
  if (loading.value && !silent) {
    pushMsg('assistant', '⚠️ 已停止本次请求。');
  }
  loading.value = false;
};

const syncSessionPreview = () => {
  if (!sessionId.value) return;
  const index = sessions.value.findIndex(item => item.session_id === sessionId.value);
  if (index < 0) return;
  const lastUserMessage = [...messages.value].reverse().find(item => item.role === 'user')?.content || '';
  const lastAssistantMessage = [...messages.value].reverse().find(item => item.role === 'assistant')?.content || '';
  const current = sessions.value[index];
  sessions.value[index] = {
    ...current,
    title: current.title || (lastUserMessage ? lastUserMessage.slice(0, 18) : '新对话'),
    last_user_message: lastUserMessage,
    last_assistant_message: lastAssistantMessage,
    summary: lastAssistantMessage || lastUserMessage,
    updated_at: new Date().toISOString(),
  };
  sessions.value = [...sessions.value].sort((a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')));
  saveSessionListCache();
};

const ensureSessionId = async () => {
  if (sessionId.value) return sessionId.value;
  const session = await createChatSession(userId);
  sessionId.value = session.session_id;
  sessions.value = [session, ...sessions.value.filter(item => item.session_id !== session.session_id)];
  persistActiveSessionId();
  saveSessionListCache();
  return sessionId.value;
};

const mapHistoryToMessages = (items: ChatHistoryMessage[]): Message[] => {
  return items.map(item => ({
    role: item.role,
    content: item.content,
    ts: item.created_at ? new Date(item.created_at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : now(),
  }));
};

const refreshSessions = async () => {
  try {
    const list = await listChatSessions(userId);
    sessions.value = list;
    saveSessionListCache();
  } catch {
    sessions.value = readSessionListCache();
  }
};

const loadSessionDetail = async (targetSessionId: string) => {
  const cachedMessages = readSessionCache(targetSessionId);
  if (cachedMessages.length) {
    messages.value = cachedMessages;
    scrollToBottom();
  } else {
    messages.value = [];
  }
  try {
    const detail = await getChatSession(targetSessionId, userId);
    if (detail.session) {
      const index = sessions.value.findIndex(item => item.session_id === detail.session?.session_id);
      if (index >= 0) {
        sessions.value[index] = detail.session;
      } else {
        sessions.value.unshift(detail.session);
      }
    }
    messages.value = mapHistoryToMessages(detail.messages || []);
    saveCurrentSessionCache();
    saveSessionListCache();
    scrollToBottom();
  } catch {
    if (!cachedMessages.length) {
      messages.value = [];
    }
  }
};

const selectSession = async (targetSessionId: string) => {
  if (!targetSessionId) return;
  if (loading.value) {
    stopCurrentRequest(true, false);
  }
  sessionId.value = targetSessionId;
  persistActiveSessionId();
  await loadSessionDetail(targetSessionId);
  initWebSocket(targetSessionId);
};

const createNewSessionAndSelect = async () => {
  try {
    const session = await createChatSession(userId);
    sessions.value = [session, ...sessions.value.filter(item => item.session_id !== session.session_id)];
    saveSessionListCache();
    sessionId.value = session.session_id;
    messages.value = [];
    persistActiveSessionId();
    saveCurrentSessionCache();
    initWebSocket(session.session_id);
  } catch (error: any) {
    ElMessage.error(error?.message || '创建会话失败');
  }
};

const renameSession = async (targetSessionId: string, currentTitle: string) => {
  try {
    const result = await ElMessageBox.prompt('请输入新的会话标题', '重命名会话', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      inputValue: currentTitle || '新对话',
    });
    const updated = await renameChatSession(targetSessionId, result.value, userId);
    if (!updated) return;
    const index = sessions.value.findIndex(item => item.session_id === targetSessionId);
    if (index >= 0) {
      sessions.value[index] = updated;
      sessions.value = [...sessions.value];
      saveSessionListCache();
    }
  } catch {
  }
};

const removeSession = async (targetSessionId: string) => {
  try {
    await ElMessageBox.confirm('删除后会话将从右侧列表移除，是否继续？', '删除会话', {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning',
    });
    const ok = await deleteChatSession(targetSessionId, userId);
    if (!ok) return;
    sessions.value = sessions.value.filter(item => item.session_id !== targetSessionId);
    localStorage.removeItem(cacheKeyOfSession(targetSessionId));
    if (sessionId.value === targetSessionId) {
      const nextSession = sessions.value[0];
      if (nextSession) {
        await selectSession(nextSession.session_id);
      } else {
        await createNewSessionAndSelect();
      }
    }
    saveSessionListCache();
  } catch {
  }
};

const hydrateFromLocalCache = () => {
  sessions.value = readSessionListCache();
  const storedSessionId = localStorage.getItem(activeSessionStorageKey) || '';
  if (storedSessionId) {
    sessionId.value = storedSessionId;
    const cachedMessages = readSessionCache(storedSessionId);
    if (cachedMessages.length) {
      messages.value = cachedMessages;
    }
  }
};

const formatSessionTime = (value?: string) => {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
};

const sendMessage = async () => {
  const text = inputText.value.trim();
  if (!text || loading.value) return;

  const currentRequestToken = ++activeRequestToken;
  const currentSessionId = await ensureSessionId();
  inputText.value = '';
  pushMsg('user', text);
  loading.value = true;

  try {
    if (ws && wsConnected.value) {
      ws.send(text);
      clearWsResponseTimer();
      wsResponseTimer = window.setTimeout(() => {
        if (loading.value && currentRequestToken === activeRequestToken) {
          pushMsg('assistant', '⚠️ 实时连接等待超时，已结束本次请求。你可以重试，或刷新页面后再试。');
          loading.value = false;
        }
      }, 45000);
    } else {
      restAbortController = new AbortController();
      const response = await sendChatMessage(text, currentSessionId, restAbortController.signal);
      if (currentRequestToken !== activeRequestToken) return;
      if (response.session_id) {
        sessionId.value = response.session_id;
      }
      pushMsg('assistant', response.answer);
      await refreshSessions();
    }
  } catch (e: any) {
    if (currentRequestToken !== activeRequestToken) return;
    if (e?.name === 'CanceledError' || e?.name === 'AbortError' || /aborted|canceled/i.test(String(e?.message || ''))) {
      return;
    }
    const errorMessage = e?.response?.data?.answer || e?.response?.data?.detail || e?.message || '请求失败，请检查后端服务是否启动。';
    pushMsg('assistant', `⚠️ ${errorMessage}`);
  } finally {
    if (currentRequestToken === activeRequestToken) {
      if (!wsConnected.value) loading.value = false;
      restAbortController = null;
    }
  }
};

const initWebSocket = (targetSessionId = sessionId.value) => {
  if (!targetSessionId) return;
  if (ws) {
    ws.onmessage = null;
    ws.onerror = null;
    ws.onclose = null;
    ws.close();
  }
  try {
    ws = createChatWebSocket(targetSessionId, userId);
    ws.onopen = () => { wsConnected.value = true; };
    ws.onmessage = (e) => {
      clearWsResponseTimer();
      pushMsg('assistant', e.data);
      loading.value = false;
      void refreshSessions();
    };
    ws.onerror = () => {
      clearWsResponseTimer();
      wsConnected.value = false;
      loading.value = false;
    };
    ws.onclose = () => {
      clearWsResponseTimer();
      wsConnected.value = false;
      loading.value = false;
    };
  } catch {
    wsConnected.value = false;
    loading.value = false;
  }
};

const goBack = () => router.push('/');

onMounted(async () => {
  hydrateFromLocalCache();
  await refreshSessions();
  if (sessionId.value && sessions.value.some(item => item.session_id === sessionId.value)) {
    await loadSessionDetail(sessionId.value);
    initWebSocket(sessionId.value);
    return;
  }
  if (sessions.value.length > 0) {
    await selectSession(sessions.value[0].session_id);
    return;
  }
  await createNewSessionAndSelect();
});
onBeforeUnmount(() => {
  stopCurrentRequest(true, false);
  clearWsResponseTimer();
  ws?.close();
});
</script>

<style scoped>
.chat-page {
  max-width: 1380px;
  margin: 0 auto;
  display: flex;
  gap: 16px;
  height: 100vh;
  padding: 0 16px;
  box-sizing: border-box;
}

.chat-main-panel {
  min-width: 0;
  flex: 1;
  display: flex;
  flex-direction: column;
}

.chat-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding: 16px 18px;
  margin: 16px 0 10px;
  border-radius: 12px;
  background: linear-gradient(120deg, #f8fbff, #eef5ff);
  border: 1px solid #e2ebff;
  flex-shrink: 0;
}

.chat-header-right {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
}

.chat-header-subtext {
  max-width: 220px;
  font-size: 12px;
  color: #7a8bb3;
  text-align: right;
  line-height: 1.4;
}

.chat-header-left h1 {
  margin: 6px 0 4px;
  font-size: 20px;
  color: #1f2a44;
}

.chat-header-left p {
  margin: 0;
  font-size: 13px;
  color: #5f6f96;
}

.chat-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.chat-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: #909399;
  gap: 12px;
  margin-top: 60px;
}

.chat-msg {
  display: flex;
}

.chat-msg.user {
  justify-content: flex-end;
}

.chat-msg.assistant {
  justify-content: flex-start;
}

.bubble {
  max-width: 72%;
  padding: 10px 14px;
  border-radius: 12px;
  font-size: 14px;
  line-height: 1.7;
  position: relative;
}

.chat-msg.user .bubble {
  background: #409eff;
  color: #fff;
  border-bottom-right-radius: 4px;
}

.chat-msg.assistant .bubble {
  background: #f4f4f5;
  color: #303133;
  border-bottom-left-radius: 4px;
}

.sender {
  font-size: 11px;
  font-weight: 600;
  opacity: 0.6;
  display: block;
  margin-bottom: 4px;
}

.content code {
  background: rgba(0,0,0,0.08);
  padding: 1px 4px;
  border-radius: 3px;
  font-family: monospace;
  font-size: 13px;
}

.ts {
  font-size: 10px;
  opacity: 0.45;
  display: block;
  margin-top: 5px;
  text-align: right;
}

.typing {
  display: flex;
  gap: 4px;
  padding: 4px 0;
}

.typing span {
  width: 7px;
  height: 7px;
  background: #909399;
  border-radius: 50%;
  animation: blink 1.2s infinite;
}

.typing span:nth-child(2) { animation-delay: 0.2s; }
.typing span:nth-child(3) { animation-delay: 0.4s; }

@keyframes blink {
  0%, 80%, 100% { opacity: 0.2; transform: scale(0.8); }
  40% { opacity: 1; transform: scale(1); }
}

.chat-input-area {
  display: flex;
  gap: 8px;
  padding: 12px 0 20px;
  align-items: flex-end;
  flex-shrink: 0;
}

.chat-input-area .el-textarea {
  flex: 1;
}

.chat-input-area .el-button {
  height: 40px;
  padding: 0 20px;
}

.chat-sidebar {
  width: 320px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 32px);
  margin: 16px 0;
  border-radius: 16px;
  border: 1px solid #e5ebf7;
  background: #ffffff;
  box-shadow: 0 10px 30px rgba(31, 42, 68, 0.06);
  overflow: hidden;
}

.chat-sidebar-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 16px;
  border-bottom: 1px solid #eef2fb;
  gap: 12px;
}

.chat-sidebar-title {
  font-size: 16px;
  font-weight: 700;
  color: #22304d;
}

.chat-sidebar-subtitle {
  margin-top: 4px;
  font-size: 12px;
  color: #7d8db3;
  line-height: 1.5;
}

.chat-session-list {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.chat-session-item {
  border: 1px solid #edf1fa;
  border-radius: 12px;
  padding: 12px;
  cursor: pointer;
  transition: all 0.2s ease;
  background: #fafcff;
}

.chat-session-item:hover {
  border-color: #bfd3ff;
  background: #f4f8ff;
}

.chat-session-item.active {
  border-color: #409eff;
  background: #eef5ff;
  box-shadow: 0 4px 16px rgba(64, 158, 255, 0.12);
}

.chat-session-main {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.chat-session-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}

.chat-session-title {
  font-size: 14px;
  font-weight: 600;
  color: #22304d;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chat-session-time {
  font-size: 11px;
  color: #8b97b3;
  white-space: nowrap;
}

.chat-session-preview {
  font-size: 12px;
  line-height: 1.6;
  color: #5f6f96;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.chat-session-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
  margin-top: 8px;
}

@media (max-width: 1080px) {
  .chat-page {
    flex-direction: column;
    height: auto;
    min-height: 100vh;
  }

  .chat-main-panel {
    min-height: 75vh;
  }

  .chat-sidebar {
    width: 100%;
    height: 320px;
    margin-top: 0;
  }
}
</style>
