import client from './client';
import type { SearchParams, VulnDetailResponse, VulnSearchResponse, StatsResponse } from '../types/vuln';

export async function searchVulns(params: SearchParams): Promise<VulnSearchResponse> {
  const { data } = await client.get('/api/v1/vulns', { params });
  return data;
}

export async function getVulnDetail(source: string, vulnId: string): Promise<VulnDetailResponse> {
  const { data } = await client.get(`/api/v1/vulns/${source}/${encodeURIComponent(vulnId)}`);
  return data;
}

export async function getOverviewStats(): Promise<StatsResponse> {
  const { data } = await client.get('/api/v1/stats/overview');
  return data;
}
