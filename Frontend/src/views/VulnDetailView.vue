<template>
  <div class="detail-page">
    <el-skeleton v-if="loading" :rows="5" animated />

    <template v-else-if="detail">
      <DetailHeader :title="normalized.title || vulnId" :source="source" />

      <div class="detail-container">
        <DetailHeroCard
          :vuln-id="vulnId"
          :cve-id="normalized.cveId"
          :severity="normalized.severity"
          :cvss-score="normalized.cvssScore"
          :published-date="normalized.publishedDate"
          :last-updated="normalized.lastUpdated"
          :vendor="normalized.vendor"
        />

        <DetailTabs :data="detail" />
      </div>
    </template>

    <template v-else>
      <el-empty description="漏洞信息加载失败" />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';

import DetailHeader from '../components/detail/DetailHeader.vue';
import DetailHeroCard from '../components/detail/DetailHeroCard.vue';
import DetailTabs from '../components/detail/DetailTabs.vue';
import { getVulnDetail } from '../api/vulns';

const route = useRoute();

const source = String(route.params.source || '');
const vulnId = decodeURIComponent(String(route.params.vulnId || ''));
const detail = ref<Record<string, any> | null>(null);
const loading = ref(true);

const pickFirst = (...values: any[]) => {
  for (const v of values) {
    if (v !== null && v !== undefined && String(v).trim() !== '') return String(v);
  }
  return '';
};

const normalized = computed(() => {
  const d = detail.value || {};
  return {
    title: pickFirst(d.title, d.vulnerabilityName, d.containers_cna_title, d.name, d.vuln_id),
    cveId: pickFirst(d.related_cve_ids, d.cve_id, d.cveID, d.cveids, d.cveid, d.cveMetadata_cveId, d.reference_name),
    severity: pickFirst(d.critical, d.severity, d.metrics_cvssMetricV2_baseSeverity, d.containers_cna_metrics_cvssV3_0_baseSeverity),
    cvssScore: Number(
      pickFirst(
        d.cvss_v3_base_score,
        d.cvss_v2_base_score,
        d.metrics_cvssMetricV2_cvssData_baseScore,
        d.containers_cna_metrics_cvssV3_0_baseScore,
      ) || 0,
    ) || undefined,
    publishedDate: pickFirst(d.published_date, d.Publicdate, d.published, d.publicdate, d.dateAdded, d.cveMetadata_datePublished),
    lastUpdated: pickFirst(d.last_updated, d.updateTime, d.lastModified, d.dateupdated, d.dueDate, d.cveMetadata_dateUpdated),
    vendor: pickFirst(d.vendor_name, d.vendorProject, d.products, d.vendorComments_organization, d.containers_cna_affected_vendor),
  };
});

onMounted(async () => {
  try {
    const res = await getVulnDetail(source, vulnId);
    detail.value = res.data.raw;
  } catch (error) {
    console.error('Failed to load vulnerability detail:', error);
  } finally {
    loading.value = false;
  }
});
</script>

<style scoped>
.detail-page {
  min-height: 100vh;
  background: linear-gradient(180deg, #f5f7fb 0%, #eef2fa 100%);
  padding-bottom: 40px;
}

.detail-container {
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 20px;
}
</style>
