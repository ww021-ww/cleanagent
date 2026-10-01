<template>
  <el-card>
    <el-form inline>
      <el-form-item label="来源">
        <el-select v-model="localSource" placeholder="全部来源" clearable style="width: 160px" @change="emitChange">
          <el-option v-for="s in sources" :key="s" :label="s.toUpperCase()" :value="s" />
        </el-select>
      </el-form-item>
      <el-form-item label="级别">
        <el-select v-model="localSeverity" placeholder="全部级别" clearable style="width: 150px" @change="emitChange">
          <el-option label="Low" value="Low" />
          <el-option label="Medium" value="Medium" />
          <el-option label="High" value="High" />
          <el-option label="Critical" value="Critical" />
        </el-select>
      </el-form-item>
      <el-form-item label="时间范围">
        <el-date-picker
          v-model="dateRange"
          type="daterange"
          value-format="YYYY-MM-DD"
          range-separator="至"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
          @change="emitChange"
        />
      </el-form-item>
      <el-form-item>
        <el-button text @click="resetFilters">重置筛选</el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';

const props = defineProps<{ source?: string; severity?: string; dateFrom?: string; dateTo?: string }>();
const emit = defineEmits<{
  (e: 'change', payload: { source?: string; severity?: string; date_from?: string; date_to?: string }): void;
}>();

const sources = ['cve', 'nvd', 'cnvd', 'cisa', 'cert', 'jvn'];
const localSource = ref(props.source || '');
const localSeverity = ref(props.severity || '');
const dateRange = ref<string[]>(props.dateFrom && props.dateTo ? [props.dateFrom, props.dateTo] : []);

watch(() => props.source, (v) => (localSource.value = v || ''));
watch(() => props.severity, (v) => (localSeverity.value = v || ''));
watch(
  () => [props.dateFrom, props.dateTo],
  ([df, dt]) => (dateRange.value = df && dt ? [df, dt] : []),
);

const emitChange = () =>
  emit('change', {
    source: localSource.value || undefined,
    severity: localSeverity.value || undefined,
    date_from: dateRange.value?.[0] || undefined,
    date_to: dateRange.value?.[1] || undefined,
  });

const resetFilters = () => {
  localSource.value = '';
  localSeverity.value = '';
  dateRange.value = [];
  emitChange();
};
</script>
