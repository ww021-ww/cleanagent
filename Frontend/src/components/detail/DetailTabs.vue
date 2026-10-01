<template>
  <div class="tabs-container">
    <el-tabs v-model="activeTab" @tab-change="onTabChange" class="detail-tabs">
      <el-tab-pane label="漏洞详情" name="detail">
        <DetailBasicInfo :data="data" />
      </el-tab-pane>
      <el-tab-pane label="修复方案" name="remediation">
        <DetailRemediation :data="data" />
      </el-tab-pane>
      <el-tab-pane label="CVSS" name="cvss">
        <DetailCvssInfo :data="data" />
      </el-tab-pane>
      <el-tab-pane label="相关链接" name="references">
        <DetailReferences :data="data" />
      </el-tab-pane>
      <el-tab-pane label="其他信息" name="other">
        <DetailOtherInfo :data="data" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import DetailBasicInfo from './DetailBasicInfo.vue';
import DetailRemediation from './DetailRemediation.vue';
import DetailCvssInfo from './DetailCvssInfo.vue';
import DetailReferences from './DetailReferences.vue';
import DetailOtherInfo from './DetailOtherInfo.vue';

defineProps<{
  data: Record<string, any>;
}>();

const activeTab = ref('detail');

const onTabChange = (tabName: string) => {
  activeTab.value = tabName;
};
</script>

<style scoped>
.tabs-container {
  background: white;
  border-radius: 8px;
  overflow: hidden;
}

.detail-tabs :deep(.el-tabs__header) {
  margin: 0;
  border-bottom: 1px solid #e2ebff;
}

.detail-tabs :deep(.el-tabs__nav-wrap) {
  padding: 0 20px;
}

.detail-tabs :deep(.el-tabs__content) {
  padding: 20px;
}
</style>
