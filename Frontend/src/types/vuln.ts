export interface VulnItem {
  source: string;
  vuln_id: string;
  title?: string | null;
  description?: string | null;
  severity?: string | null;
  published_date?: string | null;
  last_updated?: string | null;
  cve_id?: string | null;
  vendor?: string | null;
}

export interface Pagination {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface SearchParams {
  q?: string;
  source?: string;
  severity?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  page_size?: number;
  sort_by?: 'published_date' | 'last_updated';
  sort_order?: 'asc' | 'desc';
}

export interface VulnSearchResponse {
  code: number;
  message: string;
  data: {
    items: VulnItem[];
    pagination: Pagination;
  };
}

export interface VulnDetailResponse {
  code: number;
  message: string;
  data: {
    source: string;
    vuln_id: string;
    raw: Record<string, unknown>;
  };
}

export interface StatsResponse {
  code: number;
  message: string;
  data: {
    total: number;
    by_source: Record<string, number>;
    updated_today: number;
    high_risk_total: number;
  };
}
