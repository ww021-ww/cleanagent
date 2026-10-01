<template>
  <el-card class="hero-card">
    <div class="hero-content">
      <div class="info-section">
        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">漏洞ID</span>
            <span class="info-value">{{ vulnId }}</span>
          </div>
          <div v-if="cveId" class="info-item">
            <span class="info-label">关联CVE</span>
            <span class="info-value">{{ cveId }}</span>
          </div>
          <div v-if="publishedDate" class="info-item">
            <span class="info-label">发布日期</span>
            <span class="info-value">{{ formatDate(publishedDate) }}</span>
          </div>
          <div v-if="lastUpdated" class="info-item">
            <span class="info-label">更新日期</span>
            <span class="info-value">{{ formatDate(lastUpdated) }}</span>
          </div>
          <div v-if="vendor" class="info-item">
            <span class="info-label">厂商/产品</span>
            <span class="info-value">{{ vendor }}</span>
          </div>
          <div v-if="severity" class="info-item">
            <span class="info-label">严重级别</span>
            <el-tag size="small" :type="getSeverityTagType(severity)">
              {{ severity }}
            </el-tag>
          </div>
        </div>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
defineProps<{
  vulnId: string;
  cveId?: string;
  severity?: string;
  cvssScore?: number;
  publishedDate?: string;
  lastUpdated?: string;
  vendor?: string;
}>();

const formatDate = (date?: string) => {
  if (!date) return '-';
  if (typeof date === 'string' && date.includes('T')) {
    return date.split('T')[0];
  }
  return date;
};

const getSeverityTagType = (severity?: string) => {
  if (!severity) return 'info';
  const s = severity.toLowerCase();
  if (s.includes('critical')) return 'danger';
  if (s.includes('high')) return 'warning';
  if (s.includes('medium')) return 'primary';
  if (s.includes('low')) return 'success';
  return 'info';
};
</script>

<style scoped>
.hero-card {
  margin-bottom: 20px;
}

.hero-card :deep(.el-card__body) {
  padding: 24px;
}

.hero-content {
  display: flex;
  align-items: flex-start;
}

.info-section {
  flex: 1;
  min-width: 0;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 12px;
  color: #7483a8;
  font-weight: 500;
}

.info-value {
  font-size: 14px;
  color: #2b3552;
  font-weight: 500;
  word-break: break-word;
}

@media (max-width: 768px) {
  .hero-content {
    flex-direction: column;
    gap: 20px;
  }

  .info-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
