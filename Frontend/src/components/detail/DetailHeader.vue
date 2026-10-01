<template>
  <div class="detail-header">
    <div class="header-content">
      <el-button type="primary" text @click="goBack" class="back-btn">
        <el-icon><ArrowLeft /></el-icon>
        返回
      </el-button>
      <div class="title-section">
        <h1 class="detail-title">{{ title }}</h1>
        <el-tag size="large" class="source-tag" :type="getSourceTagType(source)">
          {{ source.toUpperCase() }}
        </el-tag>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import { ArrowLeft } from '@element-plus/icons-vue';

defineProps<{
  title: string;
  source: string;
}>();

const router = useRouter();

const goBack = () => {
  router.back();
};

const getSourceTagType = (source: string) => {
  const typeMap: Record<string, string> = {
    cve: 'info',
    nvd: 'info',
    cnvd: 'warning',
    cisa: 'danger',
    cert: 'success',
    jvn: 'primary',
  };
  return typeMap[source.toLowerCase()] || 'info';
};
</script>

<style scoped>
.detail-header {
  background: linear-gradient(120deg, #f8fbff, #eef5ff);
  border-bottom: 1px solid #e2ebff;
  padding: 16px 20px;
  margin-bottom: 20px;
}

.header-content {
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  gap: 16px;
}

.back-btn {
  flex-shrink: 0;
}

.title-section {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.detail-title {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #1f2a44;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.source-tag {
  flex-shrink: 0;
}
</style>
