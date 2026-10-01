<template>
  <div class="basic-info">
    <div v-if="title" class="info-section">
      <h3 class="section-title">漏洞标题</h3>
      <p class="section-content">{{ title }}</p>
    </div>

    <div v-if="description" class="info-section">
      <h3 class="section-title">漏洞描述</h3>
      <p class="section-content">{{ description }}</p>
    </div>

    <div v-if="impact" class="info-section">
      <h3 class="section-title">影响说明</h3>
      <p class="section-content">{{ impact }}</p>
    </div>

    <div v-if="affected" class="info-section">
      <h3 class="section-title">受影响产品/系统</h3>
      <p class="section-content">{{ affected }}</p>
    </div>

    <div v-if="!title && !description && !impact && !affected" class="empty-state">
      <el-empty description="暂无漏洞详情" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  data: Record<string, any>;
}>();

const pickFirstText = (...vals: unknown[]) => {
  for (const v of vals) {
    const t = String(v ?? '').trim();
    if (t) return t;
  }
  return '';
};

const normalizeMultilangDescription = (text: string) => {
  if (!text.includes(' | ')) return text;
  const parts = text.split(' | ').map((p) => p.trim()).filter(Boolean);
  return parts.length ? parts[0] : text;
};

const title = computed(() => {
  return (
    props.data.title ||
    props.data.vulnerabilityName ||
    props.data.vulnerabilitiestype ||
    props.data.containers_cna_title ||
    props.data.name ||
    ''
  );
});

const description = computed(() => {
  const rawDesc = pickFirstText(
    props.data.description,
    props.data.shortDescription,
    props.data.descriptions_value,
    props.data.containers_cna_descriptions_value,
    props.data.clean_desc,
    props.data.overview,
  );

  return normalizeMultilangDescription(rawDesc);
});

const impact = computed(() => {
  return props.data.impact || props.data.notes || props.data.containers_cna_impacts_descriptions_value || '';
});

const affected = computed(() => {
  return (
    props.data.products ||
    props.data.product ||
    props.data.sysaffected ||
    props.data['Affected Systems/Products'] ||
    props.data.containers_cna_affected_product ||
    ''
  );
});
</script>

<style scoped>
.basic-info {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.info-section {
  border-left: 3px solid #2563eb;
  padding-left: 16px;
}

.section-title {
  margin: 0 0 8px;
  font-size: 14px;
  font-weight: 600;
  color: #1f2a44;
}

.section-content {
  margin: 0;
  font-size: 14px;
  color: #2b3552;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}

.empty-state {
  padding: 40px 20px;
  text-align: center;
}
</style>
