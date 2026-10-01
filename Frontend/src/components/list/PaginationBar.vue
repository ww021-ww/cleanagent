<template>
  <div class="bar">
    <el-pagination
      background
      layout="prev, pager, next, total"
      :total="total"
      :page-size="pageSize"
      :current-page="page"
      @current-change="onChange"
    />
  </div>
</template>

<script setup lang="ts">
defineProps<{ total: number; page: number; pageSize: number }>();
const emit = defineEmits<{ (e: 'change', page: number): void }>();
const onChange = (p: number) => emit('change', p);
</script>

<style scoped>
.bar {
  margin-top: 12px;
  display: flex;
  justify-content: flex-end;
}
</style>
