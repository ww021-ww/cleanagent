<template>
  <div class="other-info">
    <div class="summary-card">
      <span>总字段: {{ fieldStats.total }}</span>
      <span>前面已展示: {{ fieldStats.categorized }}</span>
      <span>当前展示: {{ filteredEntries.length }}</span>
    </div>

    <div v-if="otherEntries.length" class="info-section">
      <div class="toolbar">
        <h3 class="section-title">其他信息（完整字段）</h3>
        <el-input
          v-model="keyword"
          size="small"
          clearable
          placeholder="搜索字段名或字段值"
          class="search-input"
        />
      </div>

      <div v-if="filteredEntries.length" class="kv-grid">
        <div v-for="item in filteredEntries" :key="item.key" class="kv-item">
          <div class="k">{{ item.key }}</div>
          <div class="v">{{ item.value }}</div>
        </div>
      </div>
      <el-empty v-else description="无匹配字段" :image-size="52" />
    </div>

    <div v-else class="empty-state">
      <el-empty description="暂无其他信息" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';

const props = defineProps<{ data: Record<string, any> }>();

const keyword = ref('');

const hiddenSystemFields = new Set([
  'id', 'status', 'is_deleted', 'create_time', 'modify_time',
]);

const detailKeys = new Set([
  'title', 'vulnerabilityName', 'vulnerabilitiestype', 'containers_cna_title', 'name',
  'description', 'shortDescription', 'descriptions_value', 'containers_cna_descriptions_value', 'clean_desc', 'overview',
  'impact', 'notes', 'containers_cna_impacts_descriptions_value',
  'products', 'product', 'sysaffected', 'Affected Systems/Products', 'containers_cna_affected_product',
]);

const remediationKeys = new Set([
  'Vendor Patch', 'Vulnerability Attachment', 'vendor_url',
  'solutions', 'requiredAction', 'resolution', 'containers_cna_solutions_value', 'Verification Information',
  'workarounds', 'workaround', 'containers_cna_workarounds_value',
]);

const linkKeys = new Set([
  'reference_url', 'references_url', 'referenceLink', 'containers_cna_references_url', 'vendor_url',
]);

const heroKeys = new Set([
  'cveMetadata_cveId', 'cve_id', 'cnvd_id', 'cveID', 'vuid', 'jvn_number',
  'related_cve_ids', 'cveids', 'cveid',
  'critical', 'severity', 'metrics_cvssMetricV2_baseSeverity', 'containers_cna_metrics_cvssV3_0_baseSeverity',
  'published_date', 'Publicdate', 'published', 'publicdate', 'dateAdded', 'cveMetadata_datePublished', 'datefirstpublished',
  'last_updated', 'updateTime', 'lastModified', 'dateupdated', 'dueDate', 'cveMetadata_dateUpdated',
  'vendor_name', 'vendorProject', 'products', 'vendorComments_organization', 'containers_cna_affected_vendor', 'product',
]);

const cvssKeysPattern = /^(cvss_|containers_cna_metrics_cvss|metrics_cvssMetricV2|metrics_cvssMetricV30|metrics_cvssMetricV31|metrics_cvssMetricV40)/;

const categorizedKeys = computed(() => {
  return new Set([
    ...Array.from(hiddenSystemFields),
    ...Array.from(heroKeys),
    ...Array.from(detailKeys),
    ...Array.from(remediationKeys),
    ...Array.from(linkKeys),
  ]);
});

const otherEntries = computed(() => {
  return Object.entries(props.data || {})
    .filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '')
    .filter(([key]) => !categorizedKeys.value.has(key))
    .filter(([key]) => !cvssKeysPattern.test(key))
    .map(([key, value]) => ({ key, value: String(value) }))
    .sort((a, b) => a.key.localeCompare(b.key));
});

const filteredEntries = computed(() => {
  const k = keyword.value.trim().toLowerCase();
  if (!k) return otherEntries.value;
  return otherEntries.value.filter((item) => item.key.toLowerCase().includes(k) || item.value.toLowerCase().includes(k));
});

const fieldStats = computed(() => {
  const allFilled = Object.entries(props.data || {}).filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '');
  const total = allFilled.length;
  const other = otherEntries.value.length;
  const categorized = total - other;
  return { total, categorized, other };
});
</script>

<style scoped>
.other-info {
  display: flex;
  flex-direction: column;
  gap: 24px;
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

.info-section {
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

.kv-grid {
  display: grid;
  gap: 10px;
}

.kv-item {
  border: 1px solid #e8eeff;
  border-radius: 8px;
  background: #fbfdff;
  padding: 10px;
}

.k {
  font-size: 12px;
  color: #6b7ba6;
  margin-bottom: 4px;
}

.v {
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
