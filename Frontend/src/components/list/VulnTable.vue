<template>
  <el-card class="table-card">
    <el-table :data="items" stripe @sort-change="onSortChange">
      <el-table-column prop="source" label="来源" width="90">
        <template #default="scope">
          <el-tag size="small" effect="plain">{{ String(scope.row.source || '').toUpperCase() }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column prop="severity" label="级别" width="90">
        <template #default="scope">
          <el-tag size="small" :type="severityTagType(scope.row.severity)">{{ scope.row.severity || '-' }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column prop="title" label="漏洞名称" min-width="340">
        <template #default="scope">
          <div class="title-cell">{{ scope.row.title || scope.row.vuln_id }}</div>
          <div class="desc-cell">{{ scope.row.description || '暂无描述' }}</div>
        </template>
      </el-table-column>

      <el-table-column prop="vuln_id" label="漏洞ID" width="210" />
      <el-table-column prop="cve_id" label="关联CVE" width="170" />
      <el-table-column prop="vendor" label="厂商/产品" width="150" show-overflow-tooltip />
      <el-table-column prop="last_updated" label="更新时间" width="170" sortable="custom" />
      <el-table-column prop="published_date" label="发布日期" width="170" sortable="custom" />

      <el-table-column label="操作" width="90" fixed="right">
        <template #default="scope">
          <el-button link type="primary" @click="openDetail(scope.row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import type { VulnItem } from '../../types/vuln';

defineProps<{ items: VulnItem[] }>();
const emit = defineEmits<{
  (e: 'detail', item: VulnItem): void;
  (e: 'sort', payload: { sort_by: 'published_date' | 'last_updated'; sort_order: 'asc' | 'desc' }): void;
}>();

const openDetail = (item: VulnItem) => emit('detail', item);

const severityTagType = (severity?: string | null) => {
  const s = String(severity || '').toLowerCase();
  if (s.includes('critical') || s.includes('严重')) return 'danger';
  if (s.includes('high') || s.includes('高')) return 'warning';
  if (s.includes('medium') || s.includes('中')) return 'primary';
  if (s.includes('low') || s.includes('低')) return 'success';
  return 'info';
};

const onSortChange = ({ prop, order }: { prop: string; order: 'ascending' | 'descending' | null }) => {
  if (!order || (prop !== 'last_updated' && prop !== 'published_date')) return;
  emit('sort', {
    sort_by: prop as 'published_date' | 'last_updated',
    sort_order: order === 'ascending' ? 'asc' : 'desc',
  });
};
</script>

<style scoped>
.table-card :deep(.el-card__body) {
  padding: 10px;
}

.title-cell {
  font-weight: 600;
  color: #253253;
  line-height: 1.4;
}

.desc-cell {
  margin-top: 4px;
  color: #7483a8;
  font-size: 12px;
  line-height: 1.4;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
