<template>
  <div class="page search-page">
    <el-alert v-if="apiError" :title="apiError" type="error" show-icon style="margin-bottom:12px" />
    <div class="search-header">
      <div>
        <h1>漏洞情报检索中心</h1>
        <p>默认按更新时间倒序，快速定位最新漏洞动态</p>
      </div>
      <el-button type="primary" @click="router.push('/chat')">
        💬 智能问答
      </el-button>
    </div>

    <el-row :gutter="14">
      <el-col :span="24"><OverviewCards :stats="stats" /></el-col>
      <el-col :span="24" style="margin-top: 12px"><SearchBar :q="params.q || ''" @search="onSearch" /></el-col>
      <el-col :span="24" style="margin-top: 12px">
        <FilterPanel
          :source="params.source"
          :severity="params.severity"
          :date-from="params.date_from"
          :date-to="params.date_to"
          @change="onFilterChange"
        />
      </el-col>
      <el-col :span="24" style="margin-top: 12px"><VulnTable :items="items" @detail="goDetail" @sort="onSortChange" /></el-col>
      <el-col :span="24">
        <PaginationBar :total="total" :page="params.page" :page-size="params.page_size" @change="onPageChange" />
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import OverviewCards from '../components/search/OverviewCards.vue';
import SearchBar from '../components/search/SearchBar.vue';
import FilterPanel from '../components/search/FilterPanel.vue';
import VulnTable from '../components/list/VulnTable.vue';
import PaginationBar from '../components/list/PaginationBar.vue';
import { getOverviewStats, searchVulns } from '../api/vulns';
import type { SearchParams, VulnItem } from '../types/vuln';

const router = useRouter();
const items = ref<VulnItem[]>([]);
const total = ref(0);
const stats = ref({ total: 0, updated_today: 0, high_risk_total: 0, by_source: {} as Record<string, number> });
const apiError = ref('');
const params = reactive<SearchParams>({
  page: 1,
  page_size: 20,
  sort_by: 'last_updated',
  sort_order: 'desc',
});

const load = async () => {
  try {
    const res = await searchVulns(params);
    items.value = res.data.items;
    total.value = res.data.pagination.total;
    apiError.value = '';
  } catch (e: any) {
    apiError.value = `漏洞数据加载失败：${e?.response?.data?.detail || e?.message || e}`;
  }
};

const loadStats = async () => {
  try {
    const res = await getOverviewStats();
    stats.value = res.data;
  } catch (e: any) {
    apiError.value = `统计数据加载失败：${e?.response?.data?.detail || e?.message || e}`;
  }
};

const onSearch = (q: string) => {
  params.q = q || undefined;
  params.page = 1;
  load();
};

const onFilterChange = (payload: { source?: string; severity?: string; date_from?: string; date_to?: string }) => {
  params.source = payload.source;
  params.severity = payload.severity;
  params.date_from = payload.date_from;
  params.date_to = payload.date_to;
  params.page = 1;
  load();
};

const onSortChange = (payload: { sort_by: 'published_date' | 'last_updated'; sort_order: 'asc' | 'desc' }) => {
  params.sort_by = payload.sort_by;
  params.sort_order = payload.sort_order;
  params.page = 1;
  load();
};

const onPageChange = (page: number) => {
  params.page = page;
  load();
};

const goDetail = (item: VulnItem) => {
  router.push(`/detail/${item.source}/${encodeURIComponent(item.vuln_id)}`);
};

onMounted(async () => {
  await Promise.all([load(), loadStats()]);
});
</script>

<style scoped>
.search-page {
  max-width: 1280px;
  margin: 0 auto;
}

.search-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  padding: 16px 18px;
  border-radius: 12px;
  background: linear-gradient(120deg, #f8fbff, #eef5ff);
  border: 1px solid #e2ebff;
}

.search-header h1 {
  margin: 0;
  font-size: 22px;
  color: #1f2a44;
}

.search-header p {
  margin: 8px 0 0;
  color: #5f6f96;
}
</style>
