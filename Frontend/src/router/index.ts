import { createRouter, createWebHistory } from 'vue-router';

import VulnSearchView from '../views/VulnSearchView.vue';
import VulnDetailView from '../views/VulnDetailView.vue';
import ChatView from '../views/ChatView.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'search', component: VulnSearchView },
    { path: '/detail/:source/:vulnId', name: 'detail', component: VulnDetailView },
    { path: '/chat', name: 'chat', component: ChatView },
  ],
});

export default router;
