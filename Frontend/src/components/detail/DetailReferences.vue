<template>
  <div class="references">
    <div class="summary-card">
      <span>链接总数: {{ allLinks.length }}</span>
      <span>字段来源数: {{ sourceFieldCount }}</span>
    </div>

    <div v-if="allLinks.length > 0" class="ref-section">
      <div class="toolbar">
        <h3 class="section-title">相关链接</h3>
        <el-input
          v-model="keyword"
          size="small"
          clearable
          placeholder="搜索链接或字段名"
          class="search-input"
        />
      </div>

      <ul v-if="filteredLinks.length" class="link-list">
        <li v-for="(item, idx) in filteredLinks" :key="idx" class="link-item">
          <el-icon class="link-icon"><Link /></el-icon>
          <a :href="item.url" target="_blank" rel="noopener noreferrer" class="link-text">
            {{ item.url }}
          </a>
          <span class="field-tag">{{ item.from }}</span>
        </li>
      </ul>
      <el-empty v-else description="无匹配链接" :image-size="52" />
    </div>

    <div v-else class="empty-state">
      <el-empty description="暂无相关链接" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { Link } from '@element-plus/icons-vue';

const props = defineProps<{ data: Record<string, any> }>();

const keyword = ref('');

const URL_REGEX = /https?:\/\/[^\s'"<>]+/g;

const normalizeUrl = (url: string) => {
  return url.trim().replace(/[),.;]+$/g, '');
};

const splitCandidates = (text: string) => {
  return text.split(/\n|\||;/g).map((s) => s.trim()).filter(Boolean);
};

const allLinks = computed(() => {
  const map = new Map<string, string>();

  Object.entries(props.data || {}).forEach(([key, rawVal]) => {
    if (rawVal === null || rawVal === undefined) return;
    const text = String(rawVal);

    const directField = ['reference_url', 'references_url', 'referenceLink', 'containers_cna_references_url', 'vendor_url'].includes(key);
    if (directField) {
      splitCandidates(text)
        .filter((s) => s.startsWith('http://') || s.startsWith('https://'))
        .forEach((u) => {
          const normalized = normalizeUrl(u);
          if (!normalized) return;
          if (!map.has(normalized)) map.set(normalized, key);
        });
    }

    const matches = text.match(URL_REGEX) || [];
    matches.forEach((u) => {
      const normalized = normalizeUrl(u);
      if (!normalized) return;
      if (!map.has(normalized)) map.set(normalized, key);
    });
  });

  return Array.from(map.entries())
    .map(([url, from]) => ({ url, from }))
    .sort((a, b) => a.url.localeCompare(b.url));
});

const filteredLinks = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  if (!k) return allLinks.value;
  return allLinks.value.filter((item) => item.url.toLowerCase().includes(k) || item.from.toLowerCase().includes(k));
});

const sourceFieldCount = computed(() => {
  return new Set(allLinks.value.map((i) => i.from)).size;
});
</script>

<style scoped>
.references {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.summary-card {
  display: flex;
  gap: 18px;
  padding: 10px 12px;
  border-radius: 8px;
  background: #f2f6ff;
  border: 1px solid #dbe7ff;
  color: #455a8a;
  font-size: 13px;
}

.ref-section {
  border-left: 3px solid #2563eb;
  padding-left: 16px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.section-title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: #1f2a44;
}

.search-input {
  width: 260px;
}

.link-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.link-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
}

.link-icon {
  color: #2563eb;
  flex-shrink: 0;
}

.link-text {
  color: #2563eb;
  text-decoration: none;
  word-break: break-all;
}

.link-text:hover {
  text-decoration: underline;
}

.field-tag {
  font-size: 12px;
  color: #7483a8;
  background: #edf3ff;
  border-radius: 10px;
  padding: 2px 8px;
}

.empty-state {
  padding: 40px 20px;
  text-align: center;
}

@media (max-width: 768px) {
  .toolbar {
    flex-direction: column;
    align-items: flex-start;
  }

  .search-input {
    width: 100%;
  }
}
</style>
