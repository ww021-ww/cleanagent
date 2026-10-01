<template>
  <div class="cvss-info">
    <div v-if="hasV3Data" class="cvss-section">
      <h3 class="section-title">{{ cvssV3Title }}</h3>
      <div class="cvss-details">
        <div class="detail-row"><span class="label">基础评分:</span><span class="value">{{ cvssV3Score || '-' }}</span></div>
        <div class="detail-row" v-if="cvssV3Severity"><span class="label">基础严重程度:</span><span class="value">{{ cvssV3Severity }}</span></div>
        <div class="detail-row" v-if="cvssV3VectorString"><span class="label">向量字符串:</span><span class="value">{{ cvssV3VectorString }}</span></div>
        <div class="detail-row" v-if="cvssV3ExploitabilityScore"><span class="label">可利用性评分:</span><span class="value">{{ cvssV3ExploitabilityScore }}</span></div>
        <div class="detail-row" v-if="cvssV3ImpactScore"><span class="label">影响评分:</span><span class="value">{{ cvssV3ImpactScore }}</span></div>
        <div class="detail-row" v-if="cvssV3Source"><span class="label">评分来源:</span><span class="value">{{ cvssV3Source }}</span></div>
        <div class="detail-row" v-if="cvssV3Type"><span class="label">评分类型:</span><span class="value">{{ cvssV3Type }}</span></div>

        <div class="metrics-grid">
          <div v-if="cvssV3AttackVector" class="metric-item"><span class="metric-label">攻击向量 (AV)</span><span class="metric-value">{{ cvssV3AttackVector }}</span></div>
          <div v-if="cvssV3AttackComplexity" class="metric-item"><span class="metric-label">攻击复杂度 (AC)</span><span class="metric-value">{{ cvssV3AttackComplexity }}</span></div>
          <div v-if="cvssV3PrivilegesRequired" class="metric-item"><span class="metric-label">权限要求 (PR)</span><span class="metric-value">{{ cvssV3PrivilegesRequired }}</span></div>
          <div v-if="cvssV3UserInteraction" class="metric-item"><span class="metric-label">用户交互 (UI)</span><span class="metric-value">{{ cvssV3UserInteraction }}</span></div>
          <div v-if="cvssV3Scope" class="metric-item"><span class="metric-label">作用域 (S)</span><span class="metric-value">{{ cvssV3Scope }}</span></div>
          <div v-if="cvssV3ConfidentialityImpact" class="metric-item"><span class="metric-label">机密性影响 (C)</span><span class="metric-value">{{ cvssV3ConfidentialityImpact }}</span></div>
          <div v-if="cvssV3IntegrityImpact" class="metric-item"><span class="metric-label">完整性影响 (I)</span><span class="metric-value">{{ cvssV3IntegrityImpact }}</span></div>
          <div v-if="cvssV3AvailabilityImpact" class="metric-item"><span class="metric-label">可用性影响 (A)</span><span class="metric-value">{{ cvssV3AvailabilityImpact }}</span></div>
        </div>
      </div>
    </div>

    <div v-if="hasV2Data" class="cvss-section">
      <h3 class="section-title">CVSS v2</h3>
      <div class="cvss-details">
        <div class="detail-row"><span class="label">基础评分:</span><span class="value">{{ cvssV2Score || '-' }}</span></div>
        <div class="detail-row" v-if="cvssV2VectorString"><span class="label">向量字符串:</span><span class="value">{{ cvssV2VectorString }}</span></div>
        <div class="metrics-grid">
          <div v-if="cvssV2AccessVector" class="metric-item"><span class="metric-label">访问向量 (AV)</span><span class="metric-value">{{ cvssV2AccessVector }}</span></div>
          <div v-if="cvssV2AccessComplexity" class="metric-item"><span class="metric-label">访问复杂度 (AC)</span><span class="metric-value">{{ cvssV2AccessComplexity }}</span></div>
          <div v-if="cvssV2Authentication" class="metric-item"><span class="metric-label">认证要求 (Au)</span><span class="metric-value">{{ cvssV2Authentication }}</span></div>
          <div v-if="cvssV2ConfidentialityImpact" class="metric-item"><span class="metric-label">机密性影响 (C)</span><span class="metric-value">{{ cvssV2ConfidentialityImpact }}</span></div>
          <div v-if="cvssV2IntegrityImpact" class="metric-item"><span class="metric-label">完整性影响 (I)</span><span class="metric-value">{{ cvssV2IntegrityImpact }}</span></div>
          <div v-if="cvssV2AvailabilityImpact" class="metric-item"><span class="metric-label">可用性影响 (A)</span><span class="metric-value">{{ cvssV2AvailabilityImpact }}</span></div>
        </div>
      </div>
    </div>

    <div v-if="!hasV3Data && !hasV2Data" class="empty-state">
      <el-empty description="暂无CVSS信息" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{ data: Record<string, any> }>();

const pick = (...vals: any[]) => {
  for (const v of vals) {
    if (v !== null && v !== undefined && String(v).trim() !== '') return String(v);
  }
  return '';
};

// 检测 CVSS 版本
const cvssV31Version = computed(() => pick(
  props.data.metrics_cvssMetricV31_cvssData_version,
  props.data.containers_cna_metrics_cvssV3_1_version,
));
const cvssV30Version = computed(() => pick(
  props.data.metrics_cvssMetricV30_cvssData_version,
  props.data.containers_cna_metrics_cvssV3_0_version,
));
const cvssV3Title = computed(() => {
  if (cvssV31Version.value) return 'CVSS v3.1';
  if (cvssV30Version.value) return 'CVSS v3.0';
  return 'CVSS v3.x';
});

// CVSS v3 字段映射（支持 CVE 和 NVD 两种格式）
const cvssV3Score = computed(() => pick(
  props.data.cvss_v3_base_score,
  props.data.containers_cna_metrics_cvssV3_0_baseScore,
  props.data.containers_cna_metrics_cvssV3_1_baseScore,
  props.data.metrics_cvssMetricV31_cvssData_baseScore,
  props.data.metrics_cvssMetricV30_cvssData_baseScore,
));
const cvssV3Severity = computed(() => pick(
  props.data.containers_cna_metrics_cvssV3_0_baseSeverity,
  props.data.containers_cna_metrics_cvssV3_1_baseSeverity,
  props.data.metrics_cvssMetricV31_cvssData_baseSeverity,
  props.data.metrics_cvssMetricV30_cvssData_baseSeverity,
));
const cvssV3VectorString = computed(() => pick(
  props.data.containers_cna_metrics_cvssV3_0_vectorString,
  props.data.containers_cna_metrics_cvssV3_1_vectorString,
  props.data.metrics_cvssMetricV31_cvssData_vectorString,
  props.data.metrics_cvssMetricV30_cvssData_vectorString,
));
const cvssV3ExploitabilityScore = computed(() => pick(
  props.data.metrics_cvssMetricV31_exploitabilityScore,
  props.data.metrics_cvssMetricV30_exploitabilityScore,
));
const cvssV3ImpactScore = computed(() => pick(
  props.data.metrics_cvssMetricV31_impactScore,
  props.data.metrics_cvssMetricV30_impactScore,
));
const cvssV3Source = computed(() => pick(
  props.data.metrics_cvssMetricV31_source,
  props.data.metrics_cvssMetricV30_source,
));
const cvssV3Type = computed(() => pick(
  props.data.metrics_cvssMetricV31_type,
  props.data.metrics_cvssMetricV30_type,
));
const cvssV3AttackVector = computed(() => pick(
  props.data.cvss_v3_attackvector,
  props.data.containers_cna_metrics_cvssV3_0_attackVector,
  props.data.containers_cna_metrics_cvssV3_1_attackVector,
  props.data.metrics_cvssMetricV31_cvssData_attackVector,
  props.data.metrics_cvssMetricV30_cvssData_attackVector,
));
const cvssV3AttackComplexity = computed(() => pick(
  props.data.cvss_v3_attackcomplexity,
  props.data.containers_cna_metrics_cvssV3_0_attackComplexity,
  props.data.containers_cna_metrics_cvssV3_1_attackComplexity,
  props.data.metrics_cvssMetricV31_cvssData_attackComplexity,
  props.data.metrics_cvssMetricV30_cvssData_attackComplexity,
));
const cvssV3PrivilegesRequired = computed(() => pick(
  props.data.cvss_v3_privilegesrequired,
  props.data.containers_cna_metrics_cvssV3_0_privilegesRequired,
  props.data.containers_cna_metrics_cvssV3_1_privilegesRequired,
  props.data.metrics_cvssMetricV31_cvssData_privilegesRequired,
  props.data.metrics_cvssMetricV30_cvssData_privilegesRequired,
));
const cvssV3UserInteraction = computed(() => pick(
  props.data.cvss_v3_userinteraction,
  props.data.containers_cna_metrics_cvssV3_0_userInteraction,
  props.data.containers_cna_metrics_cvssV3_1_userInteraction,
  props.data.metrics_cvssMetricV31_cvssData_userInteraction,
  props.data.metrics_cvssMetricV30_cvssData_userInteraction,
));
const cvssV3Scope = computed(() => pick(
  props.data.cvss_v3_scope,
  props.data.containers_cna_metrics_cvssV3_0_scope,
  props.data.containers_cna_metrics_cvssV3_1_scope,
  props.data.metrics_cvssMetricV31_cvssData_scope,
  props.data.metrics_cvssMetricV30_cvssData_scope,
));
const cvssV3ConfidentialityImpact = computed(() => pick(
  props.data.cvss_v3_confidentialityimpact,
  props.data.containers_cna_metrics_cvssV3_0_confidentialityImpact,
  props.data.containers_cna_metrics_cvssV3_1_confidentialityImpact,
  props.data.metrics_cvssMetricV31_cvssData_confidentialityImpact,
  props.data.metrics_cvssMetricV30_cvssData_confidentialityImpact,
));
const cvssV3IntegrityImpact = computed(() => pick(
  props.data.cvss_v3_integrityimpact,
  props.data.containers_cna_metrics_cvssV3_0_integrityImpact,
  props.data.containers_cna_metrics_cvssV3_1_integrityImpact,
  props.data.metrics_cvssMetricV31_cvssData_integrityImpact,
  props.data.metrics_cvssMetricV30_cvssData_integrityImpact,
));
const cvssV3AvailabilityImpact = computed(() => pick(
  props.data.cvss_v3_availabilityimpact,
  props.data.containers_cna_metrics_cvssV3_0_availabilityImpact,
  props.data.containers_cna_metrics_cvssV3_1_availabilityImpact,
  props.data.metrics_cvssMetricV31_cvssData_availabilityImpact,
  props.data.metrics_cvssMetricV30_cvssData_availabilityImpact,
));

// CVSS v2 字段映射
const cvssV2Score = computed(() => pick(
  props.data.cvss_v2_base_score,
  props.data.containers_cna_metrics_cvssV2_0_baseScore,
  props.data.metrics_cvssMetricV2_cvssData_baseScore,
  props.data.cvss_basescore,
));
const cvssV2VectorString = computed(() => pick(
  props.data.containers_cna_metrics_cvssV2_0_vectorString,
  props.data.metrics_cvssMetricV2_cvssData_vectorString,
  props.data.cvss_basevector,
));
const cvssV2AccessVector = computed(() => pick(
  props.data.cvss_v2_accessvector,
  props.data.containers_cna_metrics_cvssV2_0_accessVector,
  props.data.metrics_cvssMetricV2_cvssData_accessVector,
  props.data.cvss_accessvector,
));
const cvssV2AccessComplexity = computed(() => pick(
  props.data.cvss_v2_accesscomplexity,
  props.data.containers_cna_metrics_cvssV2_0_accessComplexity,
  props.data.metrics_cvssMetricV2_cvssData_accessComplexity,
  props.data.cvss_accesscomplexity,
));
const cvssV2Authentication = computed(() => pick(
  props.data.cvss_v2_authentication,
  props.data.containers_cna_metrics_cvssV2_0_authentication,
  props.data.metrics_cvssMetricV2_cvssData_authentication,
  props.data.cvss_authentication,
));
const cvssV2ConfidentialityImpact = computed(() => pick(
  props.data.cvss_v2_confidentialityimpact,
  props.data.containers_cna_metrics_cvssV2_0_confidentialityImpact,
  props.data.metrics_cvssMetricV2_cvssData_confidentialityImpact,
  props.data.cvss_confidentialityimpact,
));
const cvssV2IntegrityImpact = computed(() => pick(
  props.data.cvss_v2_integrityimpact,
  props.data.containers_cna_metrics_cvssV2_0_integrityImpact,
  props.data.metrics_cvssMetricV2_cvssData_integrityImpact,
  props.data.cvss_integrityimpact,
));
const cvssV2AvailabilityImpact = computed(() => pick(
  props.data.cvss_v2_availabilityimpact,
  props.data.containers_cna_metrics_cvssV2_0_availabilityImpact,
  props.data.metrics_cvssMetricV2_cvssData_availabilityImpact,
  props.data.cvss_availabilityimpact,
));

const hasV3Data = computed(() => Boolean(cvssV3Score.value || cvssV3AttackVector.value || cvssV3VectorString.value));
const hasV2Data = computed(() => Boolean(cvssV2Score.value || cvssV2AccessVector.value || cvssV2VectorString.value));
</script>

<style scoped>
.cvss-info { display: flex; flex-direction: column; gap: 24px; }
.cvss-section { border: 1px solid #e2ebff; border-radius: 8px; padding: 16px; background: #f8fbff; }
.section-title { margin: 0 0 12px; font-size: 14px; font-weight: 600; color: #1f2a44; }
.cvss-details { display: flex; flex-direction: column; gap: 12px; }
.detail-row { display: flex; gap: 12px; font-size: 14px; }
.label { font-weight: 500; color: #7483a8; min-width: 100px; }
.value { color: #2b3552; flex: 1; word-break: break-word; }
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e2ebff; }
.metric-item { display: flex; flex-direction: column; gap: 4px; padding: 8px; background: white; border-radius: 4px; }
.metric-label { font-size: 12px; color: #7483a8; font-weight: 500; }
.metric-value { font-size: 13px; color: #2b3552; font-weight: 500; }
.empty-state { padding: 40px 20px; text-align: center; }
</style>
