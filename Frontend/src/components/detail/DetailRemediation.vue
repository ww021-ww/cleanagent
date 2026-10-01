<template>
  <div class="remediation">
    <div class="summary-card">
      <span>补丁文件: {{ patchItems.length }}</span>
      <span>修复方法: {{ methodItems.length }}</span>
      <span>缓解方案: {{ mitigationItems.length }}</span>
    </div>

    <div class="solution-section">
      <h3 class="section-title">补丁文件</h3>
      <div v-if="patchItems.length" class="content-list">
        <div v-for="(item, idx) in patchItems" :key="idx" class="content-line">
          <a v-if="item.isUrl" :href="item.text" target="_blank" rel="noopener noreferrer" class="url-link">{{ item.text }}</a>
          <span v-else>{{ item.text }}</span>
        </div>
      </div>
      <el-empty v-else description="暂无数据" :image-size="54" />
    </div>

    <div class="solution-section">
      <h3 class="section-title">修复方法</h3>
      <div v-if="methodItems.length" class="content-list">
        <div v-for="(item, idx) in methodItems" :key="idx" class="content-line">
          <a v-if="item.isUrl" :href="item.text" target="_blank" rel="noopener noreferrer" class="url-link">{{ item.text }}</a>
          <span v-else>{{ item.text }}</span>
        </div>
      </div>
      <el-empty v-else description="暂无数据" :image-size="54" />
    </div>

    <div class="solution-section">
      <h3 class="section-title">缓解方案</h3>
      <div v-if="mitigationItems.length" class="content-list">
        <div v-for="(item, idx) in mitigationItems" :key="idx" class="content-line">
          <a v-if="item.isUrl" :href="item.text" target="_blank" rel="noopener noreferrer" class="url-link">{{ item.text }}</a>
          <span v-else>{{ item.text }}</span>
        </div>
      </div>
      <el-empty v-else description="暂无数据" :image-size="54" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{ data: Record<string, any> }>();

type RemediationItem = { text: string; isUrl: boolean };

const URL_REGEX = /^https?:\/\//i;

const splitText = (v: unknown): string[] => {
  if (v === null || v === undefined) return [];
  return String(v)
    .split(/\n|\||;/g)
    .map((s) => s.trim())
    .filter(Boolean);
};

const uniqueItems = (values: unknown[]): RemediationItem[] => {
  const seen = new Set<string>();
  const result: RemediationItem[] = [];

  values.forEach((val) => {
    splitText(val).forEach((line) => {
      if (seen.has(line)) return;
      seen.add(line);
      result.push({ text: line, isUrl: URL_REGEX.test(line) });
    });
  });

  return result;
};

const patchItems = computed(() => {
  return uniqueItems([
    props.data['Vendor Patch'],
    props.data['Vulnerability Attachment'],
    props.data.vendor_url,
    props.data.referenceLink,
  ]);
});

const methodItems = computed(() => {
  return uniqueItems([
    props.data.solutions,
    props.data.requiredAction,
    props.data.resolution,
    props.data.containers_cna_solutions_value,
    props.data['Verification Information'],
    props.data.vulnote,
  ]);
});

const mitigationItems = computed(() => {
  return uniqueItems([
    props.data.workarounds,
    props.data.workaround,
    props.data.containers_cna_workarounds_value,
  ]);
});
</script>

<style scoped>
.remediation {
  display: flex;
  flex-direction: column;
  gap: 20px;
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

.solution-section {
  border: 1px solid #e2ebff;
  border-radius: 8px;
  padding: 14px;
  background: #fbfdff;
}

.section-title {
  margin: 0 0 10px;
  font-size: 14px;
  font-weight: 600;
  color: #1f2a44;
}

.content-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.content-line {
  margin: 0;
  font-size: 14px;
  color: #2b3552;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}

.url-link {
  color: #2563eb;
  text-decoration: none;
}

.url-link:hover {
  text-decoration: underline;
}
</style>
