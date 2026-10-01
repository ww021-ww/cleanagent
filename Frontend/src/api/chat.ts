import client from './client';

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || 'http://127.0.0.1:8001';

export interface ChatResponse {
  answer: string;
  session_id?: string;
}

export interface ChatSessionSummary {
  session_id: string;
  user_id: string;
  project_id: string;
  title: string;
  summary: string;
  last_user_message: string;
  last_assistant_message: string;
  created_at?: string;
  updated_at?: string;
}

export interface ChatHistoryMessage {
  id?: number;
  session_id: string;
  user_id?: string;
  role: 'user' | 'assistant';
  content: string;
  intent_type?: string;
  created_at?: string;
}

export async function sendChatMessage(message: string, sessionId?: string, signal?: AbortSignal): Promise<ChatResponse> {
  const { data } = await client.post('/api/chat', { message, session_id: sessionId }, { timeout: 45000, signal });
  return data as ChatResponse;
}

export async function listChatSessions(userId = 'default'): Promise<ChatSessionSummary[]> {
  const { data } = await client.get('/api/chat/sessions', { params: { user_id: userId } });
  return (data.sessions || []) as ChatSessionSummary[];
}

export async function createChatSession(userId = 'default', title = ''): Promise<ChatSessionSummary> {
  const { data } = await client.post('/api/chat/sessions', { user_id: userId, title });
  return data.session as ChatSessionSummary;
}

export async function getChatSession(sessionId: string, userId = 'default'): Promise<{ session: ChatSessionSummary | null; messages: ChatHistoryMessage[] }> {
  const { data } = await client.get(`/api/chat/sessions/${sessionId}`, { params: { user_id: userId } });
  return {
    session: (data.session || null) as ChatSessionSummary | null,
    messages: (data.messages || []) as ChatHistoryMessage[],
  };
}

export async function renameChatSession(sessionId: string, title: string, userId = 'default'): Promise<ChatSessionSummary | null> {
  const { data } = await client.patch(`/api/chat/sessions/${sessionId}`, { user_id: userId, title });
  return (data.session || null) as ChatSessionSummary | null;
}

export async function deleteChatSession(sessionId: string, userId = 'default'): Promise<boolean> {
  const { data } = await client.delete(`/api/chat/sessions/${sessionId}`, { params: { user_id: userId } });
  return Boolean(data.ok);
}

export function createChatWebSocket(sessionId?: string, userId = 'default'): WebSocket {
  const wsUrl = apiBaseUrl.replace(/^http/i, 'ws').replace(/\/$/, '');
  const params = new URLSearchParams();
  if (sessionId) params.set('session_id', sessionId);
  if (userId) params.set('user_id', userId);
  const query = params.toString();
  return new WebSocket(`${wsUrl}/ws/chat${query ? `?${query}` : ''}`);
}
