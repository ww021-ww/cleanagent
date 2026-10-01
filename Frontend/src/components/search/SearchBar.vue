<template>
  <el-card class="search-card">
    <el-form inline>
      <el-form-item label="漏洞名称 / ID">
        <el-input
          v-model="localQ"
          placeholder="输入漏洞名称关键词，如 OpenSSH、Apache、CVE-2026-xxxx"
          clearable
          style="width: 460px"
          @keyup.enter="emitSearch"
          @clear="emitSearch"
        />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="emitSearch">搜索漏洞</el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';

const props = defineProps<{ q: string }>();
const emit = defineEmits<{ (e: 'search', value: string): void }>();

const localQ = ref(props.q);
watch(
  () => props.q,
  (v) => (localQ.value = v),
);

const emitSearch = () => emit('search', localQ.value);
</script>

<style scoped>
.search-card :deep(.el-card__body) {
  padding: 14px 16px;
}
</style>
