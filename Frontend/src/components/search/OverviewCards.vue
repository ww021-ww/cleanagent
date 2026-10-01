<template>
  <el-card class="overview-card">
    <el-row :gutter="12">
      <el-col :span="6">
        <div class="metric-block">
          <div class="metric-label">漏洞总量</div>
          <div class="metric-value">{{ stats.total }}</div>
        </div>
      </el-col>
      <el-col :span="6">
        <div class="metric-block">
          <div class="metric-label">今日更新</div>
          <div class="metric-value highlight">{{ stats.updated_today }}</div>
        </div>
      </el-col>
      <el-col :span="6">
        <div class="metric-block">
          <div class="metric-label">高危数量</div>
          <div class="metric-value danger">{{ stats.high_risk_total }}</div>
        </div>
      </el-col>
      <el-col :span="6">
        <div class="metric-block">
          <div class="metric-label">来源分布</div>
          <div class="source-tags">
            <el-tag v-for="(value, key) in stats.by_source" :key="key" size="small" effect="plain">{{ key.toUpperCase() }} {{ value }}</el-tag>
          </div>
        </div>
      </el-col>
    </el-row>
  </el-card>
</template>

<script setup lang="ts">
defineProps<{
  stats: {
    total: number;
    updated_today: number;
    high_risk_total: number;
    by_source: Record<string, number>;
  };
}>();
</script>

<style scoped>
.overview-card :deep(.el-card__body) {
  padding: 14px 16px;
}

.metric-block {
  min-height: 68px;
}

.metric-label {
  font-size: 12px;
  color: #7c8aa8;
}

.metric-value {
  margin-top: 8px;
  font-size: 24px;
  font-weight: 700;
  color: #243452;
}

.metric-value.highlight {
  color: #2563eb;
}

.metric-value.danger {
  color: #dc2626;
}

.source-tags {
  margin-top: 8px;
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
</style>
