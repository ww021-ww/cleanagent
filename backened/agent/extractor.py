"""
Extractor Agent - 提取智能体
负责识别来源并提取数据
"""
import logging
import re
import json
from pathlib import Path
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from config import SOURCE_PATTERNS

logger = logging.getLogger(__name__)


class SourceExtractor:
    """单个来源的提取器"""
    
    def __init__(self, source: str, field_config: Dict, llm=None):
        self.source = source
        self.field_config = field_config
    
    def extract(self, content: str, file_path: str = '') -> List[Dict[str, Any]]:
        """
        提取数据（规则提取 + LLM补充）
        
        Args:
            content: HTML/JSON内容
            file_path: 文件路径（CERT来源需要用于定位配对的JSON文件）
        
        Returns:
            提取的数据字典列表（支持多个漏洞）
        """
        # 检查是否为JSON格式
        is_json = content.strip().startswith('{')
        
        # CERT来源：专用双文件提取逻辑
        if self.source.upper() == 'CERT':
            if is_json:
                # CERT JSON 文件
                result = self.extract_cert_json_file(content, file_path)
                return [result] if result else []
            else:
                # CERT HTML 文件
                result = self.extract_cert(content, file_path)
                return [result] if result else []
        
        # 其他来源：检查是否为JSON格式
        if is_json:
            return self.extract_from_json(content)
        else:
            # HTML格式，返回单个结果的列表
            result = self.extract_from_html(content)
            return [result] if result else []
    
    def extract_from_json(self, content: str) -> List[Dict[str, Any]]:
        """从JSON内容提取多个漏洞数据"""
        try:
            data = json.loads(content)
            
            # 检查是否为CISA格式（包含vulnerabilities数组）
            if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list):
                results = []
                for vuln in data['vulnerabilities']:
                    # 直接使用JSON中的字段，映射到配置的字段名
                    extracted = self.map_json_fields(vuln)
                    if extracted:
                        results.append(extracted)
                return results
            
            # 检查是否为CVE/NVD格式（使用JSON提取器）
            elif 'cveMetadata' in data or 'id' in data:
                from agent.json_extractor import JSONExtractor
                
                # 传入field_config，用于字段过滤
                json_extractor = JSONExtractor(self.source, self.field_config)
                extracted = json_extractor.extract(data)
                return [extracted] if extracted else []
            
            else:
                # 其他单个漏洞的JSON
                extracted = self.map_json_fields(data)
                return [extracted] if extracted else []
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {e}")
            return []
        except Exception as e:
            logger.error(f"JSON extraction failed: {e}")
            return []
    
    def map_json_fields(self, json_data: Dict) -> Dict[str, Any]:
        """将JSON字段映射到配置的字段名"""
        result = {}
        
        # 直接映射JSON字段到数据库字段（使用配置中的字段名）
        field_mapping = {
            'cveID': 'cveID',
            'vendorProject': 'vendorProject', 
            'product': 'product',
            'vulnerabilityName': 'vulnerabilityName',
            'dateAdded': 'dateAdded',
            'shortDescription': 'shortDescription',
            'requiredAction': 'requiredAction',
            'dueDate': 'dueDate',
            'knownRansomwareCampaignUse': 'knownRansomwareCampaignUse',
            'notes': 'notes',
            'cwes': 'cwes'
        }
        
        for json_field, db_field in field_mapping.items():
            if json_field in json_data:
                value = json_data[json_field]
                
                # 处理特殊字段类型转换
                if json_field == 'cwes' and isinstance(value, list):
                    result[db_field] = ', '.join(str(v) for v in value)
                else:
                    result[db_field] = value
        
        return result
    
    def extract_from_html(self, content: str) -> Dict[str, Any]:
        """从HTML内容提取数据（原有逻辑）"""
        # CNVD 来源：使用专用提取方法（BeautifulSoup不支持:contains()伪类）
        if self.source.upper() == 'CNVD':
            return self._extract_cnvd_from_html(content)
        
        # JVN 来源：使用专用提取方法（日文HTML结构）
        if self.source.upper() == 'JVN':
            return self._extract_jvn_from_html(content)
        
        return self.extract_by_rules(content)

    def _extract_jvn_from_html(self, content: str) -> Dict[str, Any]:
        """JVN专用HTML提取器 - 处理所有JVN页面格式
        
        支持的格式：
          JVN#XXXXXXXX  (JVN-00015036, JVN-00000601)
          JVNVU#XXXXXXXX (JVNVU-#99979220, JVNVU-#92198165, JVNVU-#92207212)
          JVNTA04-XXXXX  (JVNTA-04-315A, JVNTA-04-316A, JVNTA-04-356A)
          CPNI-XXXXXX   (CPNI-072928, CPNI-957037)
          NISCC-XXXXXX  (NISCC-870760, NISCC-891011)
        """
        soup = BeautifulSoup(content, 'html.parser')
        result = {}

        # ── jvn_number ──────────────────────────────────────────────────────────
        # 从 <h1 class="h1ver2"> 第一行提取，原样保留（JVNVU#99979220、CPNI-072928 等）
        h1 = soup.find('h1', class_='h1ver2')
        if h1:
            lines = [line.strip() for line in h1.get_text(separator='\n').splitlines() if line.strip()]
            if lines:
                result['jvn_number'] = lines[0]
            if len(lines) >= 2:
                result['title'] = lines[1]

        # ── published_date / last_updated ────────────────────────────────────────
        date_span = soup.find('span', class_='margin-lb')
        if date_span:
            date_text = date_span.get_text(strip=True)
            m_pub = re.search(r'公開日[：:](\d{4}/\d{2}/\d{2})', date_text)
            if m_pub:
                result['published_date'] = m_pub.group(1).replace('/', '-')
            m_upd = re.search(r'最終更新日[：:](\d{4}/\d{2}/\d{2})', date_text)
            if m_upd:
                result['last_updated'] = m_upd.group(1).replace('/', '-')

        # ── セクション取得ヘルパー ────────────────────────────────────────────────
        def get_section_text(alt_keyword: str) -> str:
            """img alt 属性でtextboxを特定し、h2以降の<p>テキストを返す"""
            for img in soup.find_all('img'):
                if alt_keyword in img.get('alt', ''):
                    textbox = img.find_parent('div', class_='textbox')
                    if textbox:
                        texts = []
                        found_h2 = False
                        for child in textbox.children:
                            if hasattr(child, 'name'):
                                if child.name == 'h2':
                                    found_h2 = True
                                    continue
                                if found_h2 and child.name == 'p':
                                    t = child.get_text(separator=' ', strip=True)
                                    if t:
                                        texts.append(t)
                        return '\n'.join(texts).strip()
            return ''

        # ── overview ─────────────────────────────────────────────────────────────
        overview_text = get_section_text('概要')
        if overview_text:
            result['overview'] = overview_text

        # ── Affected Systems/Products ─────────────────────────────────────────────
        affected_text = get_section_text('影響を受けるシステム')
        if affected_text:
            result['Affected Systems/Products'] = affected_text

        # ── description（詳細情報） ───────────────────────────────────────────────
        # テキストのみ取得（CVSS表は JPCERT/CCによる脆弱性分析結果 セクションで処理）
        description_text = get_section_text('詳細情報')
        if description_text:
            result['description'] = description_text

            # 从詳細情報(description)提取关联CVE（多个用 | 分隔）
            cve_matches = re.findall(r'CVE-\d{4}-\d+', description_text, re.IGNORECASE)
            if cve_matches:
                deduped = []
                seen = set()
                for cve in cve_matches:
                    normalized = cve.upper()
                    if normalized not in seen:
                        seen.add(normalized)
                        deduped.append(normalized)
                result['related_cve_ids'] = ' | '.join(deduped)

        # ── impact ───────────────────────────────────────────────────────────────
        impact_text = get_section_text('想定される影響')
        if impact_text:
            result['impact'] = impact_text

        # ── solutions ────────────────────────────────────────────────────────────
        solutions_text = get_section_text('対策方法')
        if solutions_text:
            result['solutions'] = solutions_text

        # ── vendor_name / vendor_status / vendor_lastupdateddate / vendor_url ────
        # 形式1: tbl-vinfo（ベンダ名・ステータス・日付・告知ページURLの4列表）
        vendor_table = soup.find('div', class_='tbl-vinfo')
        if vendor_table:
            rows = vendor_table.find_all('tr')
            vendor_names, vendor_statuses, vendor_dates, vendor_urls = [], [], [], []
            for row in rows[1:]:
                cols = row.find_all('td')
                if len(cols) >= 3:
                    name = cols[0].get_text(strip=True)
                    status_text = cols[1].get_text(strip=True)
                    date_text_td = cols[2].get_text(strip=True)
                    url = ''
                    if len(cols) >= 4:
                        a_tag = cols[3].find('a')
                        if a_tag:
                            url = a_tag.get('href', '').strip()
                    if name:
                        vendor_names.append(name)
                    if status_text:
                        vendor_statuses.append(status_text)
                    if date_text_td:
                        vendor_dates.append(date_text_td)
                    if url:
                        vendor_urls.append(url)
            if vendor_names:
                result['vendor_name'] = ' | '.join(vendor_names)
            if vendor_statuses:
                result['vendor_status'] = ' | '.join(vendor_statuses)
            if vendor_dates:
                # 拼接所有厂商的最后更新日期，空值保留占位符以对应厂商顺序
                # 示例："2005-09-05 | 2005-07-12 |  | 2005-07-12"
                result['vendor_lastupdateddate'] = ' | '.join(
                    d.replace('/', '-') if d else '' for d in vendor_dates
                )
            if vendor_urls:
                result['vendor_url'] = vendor_urls[0][:512]

        # 形式2: ベンダ情報 textbox 内の style_table（ベンダ名・リンクの2列表）
        for img in soup.find_all('img'):
            if 'ベンダ情報' in img.get('alt', ''):
                textbox = img.find_parent('div', class_='textbox')
                if textbox:
                    style_table = textbox.find('table', class_='style_table')
                    if style_table:
                        vendor_names_st, vendor_urls_st = [], []
                        for row in style_table.find_all('tr')[1:]:
                            cols = row.find_all('td')
                            if len(cols) >= 2:
                                vname = cols[0].get_text(strip=True)
                                a_tag = cols[1].find('a')
                                if a_tag:
                                    href = a_tag.get('href', '').strip()
                                    if href:
                                        vendor_urls_st.append(href)
                                if vname:
                                    vendor_names_st.append(vname)
                        if not result.get('vendor_name') and vendor_names_st:
                            result['vendor_name'] = ' | '.join(
                                n for n in vendor_names_st if n)
                        if not result.get('vendor_url') and vendor_urls_st:
                            result['vendor_url'] = vendor_urls_st[0][:512]
                break

        # ── supplement_information（JPCERT/CCからの補足情報） ──────────────────────
        # 修改：使用 supplement_information 替代 comment
        supplement_text = get_section_text('JPCERT/CCからの補足情報')
        if supplement_text:
            result['supplement_information'] = supplement_text

        # ── CVSS v2/v3（JPCERT/CCによる脆弱性分析結果セクション） ────────────────────
        cvss_section = None
        for img in soup.find_all('img'):
            if 'JPCERT/CCによる脆弱性分析結果' in img.get('alt', ''):
                cvss_section = img.find_parent('div', class_='textbox')
                break

        if cvss_section:
            # 新版本：支持 <div class="cvss-wrapper"> 结构（CVSS v3 + v2）
            cvss_v3_wrapper = cvss_section.find('div', id='cvss-v3-line')
            if cvss_v3_wrapper:
                # 提取 CVSS v3 基础评分
                v3_score_span = cvss_section.find('span', id='cvss-v3-base-score')
                if v3_score_span:
                    try:
                        result['cvss_v3_base_score'] = float(v3_score_span.get_text(strip=True))
                    except ValueError:
                        pass
                
                # 提取 CVSS v3 向量字符串
                v3_vector_span = cvss_section.find('span', id='cvss-v3-vector-string')
                if v3_vector_span:
                    vector_str = v3_vector_span.get_text(strip=True)
                    if vector_str.startswith('CVSS:3'):
                        self._parse_cvss_v3_vector(vector_str, result)
            
            # 新版本：CVSS v2 在第二个 cvss-wrapper 中
            cvss_v2_wrapper = cvss_section.find('div', id='cvss-v2-line')
            if cvss_v2_wrapper:
                # 提取 CVSS v2 基础评分
                v2_score_span = cvss_section.find('span', id='cvss-v2-base-score')
                if v2_score_span:
                    try:
                        result['cvss_v2_base_score'] = float(v2_score_span.get_text(strip=True))
                    except ValueError:
                        pass
                
                # 提取 CVSS v2 向量字符串
                v2_vector_span = cvss_section.find('span', id='cvss-v2-vector-string')
                if v2_vector_span:
                    vector_str = v2_vector_span.get_text(strip=True)
                    if not vector_str.startswith('CVSS:'):  # v2 向量不以 CVSS: 开头
                        self._parse_cvss_v2_vector(vector_str, result)
            
            # 旧版本：支持 <table class="tbl-result"> 结构（仅 CVSS v2）
            if not cvss_v2_wrapper:
                score_p = cvss_section.find('p', style=lambda s: s and 'font-weight' in s)
                if score_p:
                    m = re.search(r'Base Score[:\s]*(\d+\.\d+)', score_p.get_text())
                    if m:
                        try:
                            result['cvss_v2_base_score'] = float(m.group(1))
                        except ValueError:
                            pass

                # tbl-result class 可能在外层 div 上，也可能直接在 table 上
                tbl_result_div = cvss_section.find('div', class_='tbl-result')
                cvss_table = tbl_result_div.find('table') if tbl_result_div else cvss_section.find('table', class_='tbl-result')
                if cvss_table and cvss_table.find('td', class_='cvss_v2_selected'):
                    # 格式B（中间版）：有 cvss_v2_selected 高亮 → 提取 cvss_v2_* 字段
                    # CVSS v2 缩写 → 完整英文名称映射
                    cv2_expand = {
                        'AV': {'L': 'Local', 'A': 'Adjacent', 'N': 'Network'},
                        'AC': {'H': 'High', 'M': 'Medium', 'L': 'Low'},
                        'Au': {'M': 'Multiple', 'S': 'Single', 'N': 'None'},
                        'C':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
                        'I':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
                        'A':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
                    }
                    for tr in cvss_table.find_all('tr'):
                        th = tr.find('th')
                        selected_td = tr.find('td', class_='cvss_v2_selected')
                        if th and selected_td:
                            label = th.get_text(strip=True)
                            raw_val = selected_td.get_text(strip=True)
                            m_abbr = re.search(r'\(([^)]+)\)', raw_val)
                            abbr = m_abbr.group(1) if m_abbr else raw_val
                            if '攻撃元区分' in label or '攻撃経路' in label:
                                result['cvss_v2_accessvector'] = cv2_expand['AV'].get(abbr, abbr)
                            elif '攻撃条件の複雑さ' in label or '攻撃の難易度' in label:
                                result['cvss_v2_accesscomplexity'] = cv2_expand['AC'].get(abbr, abbr)
                            elif '認証' in label:
                                result['cvss_v2_authentication'] = cv2_expand['Au'].get(abbr, abbr)
                            elif '機密性' in label:
                                result['cvss_v2_confidentialityimpact'] = cv2_expand['C'].get(abbr, abbr)
                            elif '完全性' in label:
                                result['cvss_v2_integrityimpact'] = cv2_expand['I'].get(abbr, abbr)
                            elif '可用性' in label:
                                result['cvss_v2_availabilityimpact'] = cv2_expand['A'].get(abbr, abbr)

                # 格式C：最旧版，无 cvss_v2_selected，有 hazard ul
                # 表格结构为「評価尺度 | 攻撃成立条件 | 評価値」三列
                # → 提取到 cvss_v_* 四个字段
                if not cvss_table or not cvss_table.find('td', class_='cvss_v2_selected'):
                    # 查找含有 hazard 列表的表格
                    hazard_table = cvss_section.find('table', lambda tag: True)
                    if not hazard_table:
                        # 尝试找任意表格
                        hazard_table = cvss_section.find('table')
                    if hazard_table and hazard_table.find('ul', class_='hazard'):
                        # 字段映射：日文 th 文本 → cvss_v_* 字段名
                        legacy_field_map = {
                            '攻撃経路':               'cvss_v_accessvector',
                            '認証レベル':              'cvss_v_privilegesrequired',
                            '攻撃成立に必要なユーザーの関与': 'cvss_v_userinteraction',
                            '攻撃の難易度':            'cvss_v_attackcomplexity',
                        }
                        for tr in hazard_table.find_all('tr'):
                            th = tr.find('th')
                            tds = tr.find_all('td')
                            if th and len(tds) >= 2:
                                label = th.get_text(strip=True)
                                # 第三列（index=1）是 hazard 评级，取 <span> 文本
                                hazard_ul = tds[1].find('ul', class_='hazard')
                                if hazard_ul:
                                    span = hazard_ul.find('span')
                                    hazard_val = span.get_text(strip=True) if span else ''
                                else:
                                    hazard_val = tds[1].get_text(strip=True)
                                for key, field in legacy_field_map.items():
                                    if key in label:
                                        result[field] = hazard_val
                                        break

        # ── revision_history（更新履歴） ────────────────────────────────────────────
        # 新增：提取修订历史
        revision_history = self._extract_revision_history(soup)
        if revision_history:
            result['revision_history'] = revision_history

        # ── 参考情報（reference_name 和 reference_url） ──────────────────────────────
        # 修改：收集所有参考链接，而不仅仅是第一个
        for img in soup.find_all('img'):
            if '参考情報' in img.get('alt', ''):
                textbox = img.find_parent('div', class_='textbox')
                if textbox:
                    # 收集所有 <a> 标签
                    all_links = textbox.find_all('a')
                    if all_links:
                        ref_names = []
                        ref_urls = []
                        for a_tag in all_links:
                            href = a_tag.get('href', '').strip()
                            text = a_tag.get_text(strip=True)
                            if href and text:
                                ref_names.append(text)
                                ref_urls.append(href)
                        
                        if ref_names:
                            result['reference_name'] = ' | '.join(ref_names)
                        if ref_urls:
                            result['reference_url'] = ' | '.join(ref_urls)[:512]
                break

        logger.debug(f"JVN HTML提取结果: {list(result.keys())}")
        return result

    def _extract_revision_history(self, soup: BeautifulSoup) -> str:
        """从 HTML 提取修订历史（alt="更新履歴"）
        
        格式：日期: 内容
        多条记录用 \n 分隔
        """
        for img in soup.find_all('img'):
            if '更新履歴' in img.get('alt', ''):
                textbox = img.find_parent('div', class_='textbox')
                if textbox:
                    dl = textbox.find('dl')
                    if dl:
                        history_items = []
                        dts = dl.find_all('dt')
                        dds = dl.find_all('dd')
                        
                        # 配对 <dt> 和 <dd>
                        for dt, dd in zip(dts, dds):
                            date_text = dt.get_text(strip=True)
                            content_text = dd.get_text(strip=True)
                            # 转换日期格式：2009/02/23 → 2009-02-23
                            date_text = date_text.replace('/', '-')
                            history_items.append(f'{date_text}: {content_text}')
                        
                        if history_items:
                            return '\n'.join(history_items)
                break
        return ''

    def _parse_cvss_v3_vector(self, vector_str: str, result: Dict[str, Any]) -> None:
        """从 CVSS v3 向量字符串解析各分量并写入 result
        
        示例：CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
        """
        field_mapping = {
            'AV': 'cvss_v3_attackvector',
            'AC': 'cvss_v3_attackcomplexity',
            'PR': 'cvss_v3_privilegesrequired',
            'UI': 'cvss_v3_userinteraction',
            'S':  'cvss_v3_scope',
            'C':  'cvss_v3_confidentialityimpact',
            'I':  'cvss_v3_integrityimpact',
            'A':  'cvss_v3_availabilityimpact',
        }
        # 缩写 -> 完整英文名称映射
        value_expand = {
            # Attack Vector (AV)
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
            # Attack Complexity (AC)
            'AC': {'L': 'Low', 'H': 'High'},
            # Privileges Required (PR)
            'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
            # User Interaction (UI)
            'UI': {'N': 'None', 'R': 'Required'},
            # Scope (S)
            'S':  {'U': 'Unchanged', 'C': 'Changed'},
            # Confidentiality / Integrity / Availability Impact (C/I/A)
            'C':  {'N': 'None', 'L': 'Low', 'H': 'High'},
            'I':  {'N': 'None', 'L': 'Low', 'H': 'High'},
            'A':  {'N': 'None', 'L': 'Low', 'H': 'High'},
        }
        for part in vector_str.split('/'):
            if ':' in part:
                key, val = part.split(':', 1)
                if key in field_mapping:
                    expanded = value_expand.get(key, {}).get(val, val)
                    result[field_mapping[key]] = expanded

    def _parse_cvss_v2_vector(self, vector_str: str, result: Dict[str, Any]) -> None:
        """从 CVSS v2 向量字符串解析各分量并写入 result
        
        示例：AV:N/AC:H/Au:N/C:P/I:P/A:N
        """
        field_mapping = {
            'AV': 'cvss_v2_accessvector',
            'AC': 'cvss_v2_accesscomplexity',
            'Au': 'cvss_v2_authentication',
            'C':  'cvss_v2_confidentialityimpact',
            'I':  'cvss_v2_integrityimpact',
            'A':  'cvss_v2_availabilityimpact',
        }
        # 缩写 -> 完整英文名称映射
        value_expand = {
            # Access Vector (AV)
            'AV': {'L': 'Local', 'A': 'Adjacent', 'N': 'Network'},
            # Access Complexity (AC)
            'AC': {'H': 'High', 'M': 'Medium', 'L': 'Low'},
            # Authentication (Au)
            'Au': {'M': 'Multiple', 'S': 'Single', 'N': 'None'},
            # Confidentiality / Integrity / Availability Impact (C/I/A)
            'C':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'I':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'A':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
        }
        for part in vector_str.split('/'):
            if ':' in part:
                key, val = part.split(':', 1)
                if key in field_mapping:
                    expanded = value_expand.get(key, {}).get(val, val)
                    result[field_mapping[key]] = expanded

    def _extract_cnvd_from_html(self, content: str) -> Dict[str, Any]:
        """CNVD专用HTML提取器 - 按中文标签文本查找相邻td"""
        soup = BeautifulSoup(content, 'html.parser')
        result = {}

        def get_td_by_label(label: str) -> str:
            """查找包含指定标签文字的td，取其下一个兄弟td的文本"""
            for td in soup.find_all('td'):
                if td.get_text(strip=True) == label:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        return next_td.get_text(strip=True)
            return ''

        # CNVD-ID
        cnvd_id = get_td_by_label('CNVD-ID')
        if cnvd_id:
            result['cnvd_id'] = cnvd_id
        else:
            # 从正文中用正则提取
            m = re.search(r'CNVD-\d{4}-\d+', soup.get_text())
            if m:
                result['cnvd_id'] = m.group(0)

        # 公开日期
        val = get_td_by_label('公开日期')
        if val:
            result['Publicdate'] = val

        # 危害级别：只取中文等级文字（高/中/低）
        for td in soup.find_all('td'):
            if td.get_text(strip=True) == '危害级别':
                next_td = td.find_next_sibling('td')
                if next_td:
                    text = next_td.get_text(separator=' ', strip=True)
                    # 提取等级文字（高/中/低）
                    m_level = re.search(r'(高|中|低)', text)
                    level = m_level.group(1) if m_level else ''
                    # 提取向量字符串（如 AV:N/AC:M/Au:N/C:N/I:N/A:P）
                    a_tag = next_td.find('a', class_='showInfo')
                    vector = a_tag.get_text(strip=True) if a_tag else ''
                    # 拼合为 "中(AV:N/AC:M/Au:N/C:N/I:N/A:P)" 格式
                    if level and vector:
                        result['severity'] = f'{level}({vector})'
                    elif level:
                        result['severity'] = level
                    else:
                        result['severity'] = text
                break

        # 影响产品
        val = get_td_by_label('影响产品')
        if val:
            result['products'] = val

        # CVE ID（从全文提取）
        m = re.search(r'CVE-\d{4}-\d+', soup.get_text())
        if m:
            result['cveid'] = m.group(0)

        # 漏洞描述
        val = get_td_by_label('漏洞描述')
        if val:
            result['description'] = val

        # 漏洞类型
        val = get_td_by_label('漏洞类型')
        if val:
            result['vulnerabilitiestype'] = val

        # 参考链接：取所有有效URL，用 | 拼接
        for td in soup.find_all('td'):
            if td.get_text(strip=True) == '参考链接':
                next_td = td.find_next_sibling('td')
                if next_td:
                    urls = []
                    for a in next_td.find_all('a'):
                        href = a.get('href', '').strip()
                        if href and href.startswith('http'):
                            urls.append(href)
                    if urls:
                        combined = ' | '.join(urls)
                        result['referenceLink'] = combined[:512]
                break

        # 漏洞解决方案
        val = get_td_by_label('漏洞解决方案')
        if val:
            result['solutions'] = val

        # 厂商补丁
        val = get_td_by_label('厂商补丁')
        if val:
            result['Vendor Patch'] = val

        # 验证信息
        val = get_td_by_label('验证信息')
        if val:
            result['Verification Information'] = val

        # 报送时间
        val = get_td_by_label('报送时间')
        if val:
            result['submitTime'] = val

        # 收录时间
        val = get_td_by_label('收录时间')
        if val:
            result['collectionTime'] = val

        # 更新时间
        val = get_td_by_label('更新时间')
        if val:
            result['updateTime'] = val

        # 漏洞附件
        val = get_td_by_label('漏洞附件')
        if val:
            result['Vulnerability Attachment'] = val

        logger.debug(f"CNVD HTML提取结果: {list(result.keys())}")
        return result
    
    def extract_by_rules(self, content: str) -> Dict[str, Any]:
        """基于规则提取"""
        soup = BeautifulSoup(content, 'html.parser')
        result = {}
        
        for field in self.field_config.get('fields', []):
            field_name = field['name']
            extraction_rules = field.get('extraction_rules', [])
            
            # 尝试每个提取规则
            for rule in extraction_rules:
                value = self._apply_rule(soup, rule)
                if value:
                    result[field_name] = value
                    break
        
        return result
    
    def _apply_rule(self, soup: BeautifulSoup, rule: Dict) -> Any:
        """应用单个提取规则"""
        try:
            if 'selector' in rule:
                elem = soup.select_one(rule['selector'])
                if elem:
                    if 'attribute' in rule:
                        return elem.get(rule['attribute'])
                    else:
                        return elem.get_text(strip=True)
            
            elif 'regex' in rule:
                text = soup.get_text()
                match = re.search(rule['regex'], text)
                if match:
                    return match.group(0)
        except Exception as e:
            logger.debug(f"Rule application failed: {e}")
        
        return None
    
    def calculate_confidence(self, data: Dict) -> float:
        """计算提取置信度"""
        required_fields = [f for f in self.field_config.get('fields', []) 
                          if f.get('required')]
        filled_required = sum(1 for f in required_fields 
                             if data.get(f['name']))
        
        optional_fields = [f for f in self.field_config.get('fields', []) 
                          if not f.get('required')]
        filled_optional = sum(1 for f in optional_fields 
                             if data.get(f['name']))
        
        # 必填字段权重0.7，可选字段权重0.3
        required_score = filled_required / len(required_fields) if required_fields else 1.0
        optional_score = filled_optional / len(optional_fields) if optional_fields else 1.0
        
        return required_score * 0.7 + optional_score * 0.3

    def extract_cert_json_file(self, json_content: str, file_path: str) -> Dict[str, Any]:
        """
        处理 CERT JSON 文件（直接从 JSON 提取）
        
        Args:
            json_content: JSON 文件内容
            file_path: 文件路径
        
        Returns:
            提取的数据字典
        """
        try:
            json_data = json.loads(json_content)
            result = self.extract_cert_json(json_data)
            logger.info(f"CERT JSON: 成功提取 {file_path}")
            return result
        except json.JSONDecodeError as e:
            logger.error(f"CERT JSON: 解析失败 {file_path} - {e}")
            return {}
        except Exception as e:
            logger.error(f"CERT JSON: 提取失败 {file_path} - {e}")
            return {}

    def extract_cert(self, html_content: str, html_path: str) -> Dict[str, Any]:
        """
        CERT 专用提取方法：JSON 优先，HTML 补充。
        
        策略：
          1. 检测是否存在对应 JSON 文件
          2. 若存在：提取 JSON 字段 + 提取 HTML 各区块，按优先级合并
          3. 若不存在：仅提取 HTML
        """
        json_result = {}
        html_result = {}

        # --- 步骤1：尝试加载对应 JSON 文件 ---
        try:
            html_p = Path(html_path)
            parts = list(html_p.parts)
            html_idx = None
            for i, part in enumerate(parts):
                if part.lower() == 'html':
                    html_idx = i
                    break
            if html_idx is not None:
                parts[html_idx] = 'json'
                json_path = Path(*parts).with_suffix('.json')
                if json_path.exists():
                    with open(json_path, 'r', encoding='utf-8') as f:
                        json_data = json.load(f)
                    json_result = self.extract_cert_json(json_data)
                    logger.info(f"CERT: 找到JSON文件 {json_path.name}")
                else:
                    logger.info(f"CERT: 未找到JSON文件 {json_path.name}，仅用HTML")
        except Exception as e:
            logger.warning(f"CERT: JSON路径计算失败: {e}")

        # --- 步骤2：从 HTML 提取各区块 ---
        html_result = self._extract_cert_from_html(html_content)

        # --- 步骤3：合并，按字段优先级决定来源 ---
        final = {}

        # JSON 优先的字段（元数据，JSON更精确）
        json_priority_fields = [
            'vuid', 'idnumber', 'name', 'keywords', 'cveids',
            'datecreated', 'publicdate', 'datefirstpublished', 'dateupdated',
            'revision', 'vulnote',
            'cam_widelyknown', 'cam_exploitation', 'cam_internetinfrastructure',
            'cam_scorecurrent', 'ipprotocol',
            'cvss_accessvector', 'cvss_accesscomplexity', 'cvss_authentication',
            'cvss_confidentialityimpact', 'cvss_integrityimpact', 'cvss_availabilityimpact',
            'cvss_exploitablity', 'cvss_basescore', 'cvss_basevector',
        ]

        # HTML 优先的字段（正文内容，HTML有独立分节，更精确）
        html_priority_fields = [
            'overview', 'clean_desc', 'impact', 'resolution',
            'workarounds', 'sysaffected',
        ]

        # 先填 JSON 优先字段
        for field in json_priority_fields:
            json_val = json_result.get(field)
            html_val = html_result.get(field)
            # 保留原始值，只过滤None
            if json_val is not None:
                final[field] = json_val
            elif html_val is not None:
                final[field] = html_val

        # 再填 HTML 优先字段
        for field in html_priority_fields:
            html_val = html_result.get(field)
            json_val = json_result.get(field)
            # 保留原始值，只过滤None
            if html_val is not None:
                final[field] = html_val
            elif json_val is not None:
                final[field] = json_val

        return final

    def extract_cert_json(self, json_data: Dict) -> Dict[str, Any]:
        """从 CERT JSON 数据直接提取字段，并从 overview 中拆分各子字段"""
        result = {}

        # 直接映射的字段
        direct_fields = [
            'vuid', 'idnumber', 'name', 'keywords',
            'datecreated', 'publicdate', 'datefirstpublished', 'dateupdated',
            'cam_widelyknown', 'cam_exploitation', 'cam_internetinfrastructure',
            'cam_scorecurrent', 'ipprotocol',
            'cvss_accessvector', 'cvss_accesscomplexity', 'cvss_authentication',
            'cvss_confidentialityimpact', 'cvss_integrityimpact', 'cvss_availabilityimpact',
            'cvss_exploitablity', 'cvss_basescore', 'cvss_basevector',
        ]
        for field in direct_fields:
            val = json_data.get(field)
            # 保留原始值，只过滤None
            if val is not None:
                result[field] = val

        # cveids: 数组转逗号分隔字符串
        cveids = json_data.get('cveids')
        if cveids and isinstance(cveids, list):
            result['cveids'] = ', '.join(cveids)
        elif cveids:
            result['cveids'] = str(cveids)

        # revision: 数字转字符串
        revision = json_data.get('revision')
        if revision is not None:
            result['revision'] = str(revision)

        # vulnote: 数字转字符串（内部ID）
        vulnote = json_data.get('vulnote')
        if vulnote is not None:
            result['vulnote'] = str(vulnote)

        # 从 overview 的 Markdown 文本中拆分各子字段
        overview_text = json_data.get('overview', '')
        if overview_text:
            sections = self._parse_cert_overview_sections(overview_text)
            # 只更新不存在的字段，保留已有的字段
            for key, value in sections.items():
                if key not in result:
                    result[key] = value

        # 确保必填字段存在（vuid 是 id_field）
        if 'vuid' not in result:
            logger.warning("CERT JSON: Missing required field 'vuid'")
            return {}

        return result

    def _parse_cert_overview_sections(self, overview_text: str) -> Dict[str, str]:
        """
        将 CERT JSON 的 overview 字段按 Markdown 标题拆分为各 MySQL 字段。
        支持 ## 和 ### 两种标题级别，忽略 #### 及更深层子标题。
        """
        if not overview_text:
            return {}

        # 只匹配 ## 或 ### 开头的标题（不匹配 ####）
        section_pattern = re.compile(r'^#{2,3}\s+(.+)$', re.MULTILINE)
        matches = list(section_pattern.finditer(overview_text))

        if not matches:
            # 没有标题结构，整体存入 overview
            return {'overview': overview_text.strip()}

        sections = {}
        for i, match in enumerate(matches):
            title = match.group(1).strip()
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(overview_text)
            content = overview_text[start:end].strip()
            
            # 清理内容中的多余空白和换行
            content = re.sub(r'\s+', ' ', content).strip()
            
            if content:  # 只保存有内容的部分
                sections[title.lower()] = content

        # Markdown 标题 → MySQL 字段名映射
        field_map = {
            'overview':       'overview',
            'description':    'clean_desc',
            'impact':         'impact',
            'solution':       'resolution',
            'solutions':      'resolution',
            'workaround':     'workarounds',
            'workarounds':    'workarounds',
        }

        result = {}
        for section_title, content in sections.items():
            db_field = field_map.get(section_title)
            # 保留原始值，只过滤None
            if db_field and content is not None:
                result[db_field] = content
        
        # 如果没有拆分出任何字段，返回整个 overview
        if not result:
            result['overview'] = overview_text.strip()

        return result

    def _extract_cert_from_html(self, content: str) -> Dict[str, Any]:
        """从 CERT HTML 精确提取各字段区块"""
        soup = BeautifulSoup(content, 'html.parser')
        result = {}

        # vuid：从 div#vuid 或 breadcrumb
        vuid_div = soup.find('div', id='vuid')
        if vuid_div:
            num = vuid_div.get_text(strip=True)
            result['vuid'] = f'VU#{num}'
            result['idnumber'] = num

        # name：h2.subtitle
        h2 = soup.find('h2', class_='subtitle')
        if h2:
            result['name'] = h2.get_text(strip=True)

        # overview：h3#overview 后的第一个 <p>
        overview_h3 = soup.find('h3', id='overview')
        if overview_h3:
            p = overview_h3.find_next_sibling('p')
            if p:
                text = p.get_text(strip=True)
                # 保留原始值，包括空字符串
                result['overview'] = text

        # clean_desc（description）：h3#description 后的所有 <p>，合并
        desc_h3 = soup.find('h3', id='description')
        if desc_h3:
            texts = []
            for sib in desc_h3.next_siblings:
                if hasattr(sib, 'name'):
                    if sib.name and sib.name.startswith('h') and sib.name[1:].isdigit() and int(sib.name[1:]) <= 3:
                        break
                    if sib.name == 'p':
                        texts.append(sib.get_text(strip=True))
            # 保留原始值，包括空列表
            if texts:
                result['clean_desc'] = '\n\n'.join(texts)

        # impact：h3#impact 后的所有 <p>
        impact_h3 = soup.find('h3', id='impact')
        if impact_h3:
            texts = []
            for sib in impact_h3.next_siblings:
                if hasattr(sib, 'name'):
                    if sib.name and sib.name.startswith('h') and sib.name[1:].isdigit() and int(sib.name[1:]) <= 3:
                        break
                    if sib.name in ('p', 'blockquote'):
                        texts.append(sib.get_text(strip=True))
            # 保留原始值，包括空列表
            if texts:
                result['impact'] = '\n\n'.join(texts)

        # resolution：h3#solution 后的所有 <h4>+<p>
        solution_h3 = soup.find('h3', id='solution')
        if solution_h3:
            texts = []
            for sib in solution_h3.next_siblings:
                if hasattr(sib, 'name'):
                    if sib.name and sib.name == 'h3':
                        break
                    if sib.name in ('p', 'h4'):
                        texts.append(sib.get_text(strip=True))
            # 保留原始值，包括空列表
            if texts:
                result['resolution'] = '\n\n'.join(texts)

        # cveids：Other Information 表格中 CVE IDs 行
        cve_links = []
        for b_tag in soup.find_all('b'):
            if 'CVE IDs' in b_tag.get_text():
                td = b_tag.find_parent('td')
                if td:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        for a in next_td.find_all('a'):
                            cve_text = a.get_text(strip=True)
                            if re.match(r'CVE-\d{4}-\d+', cve_text):
                                cve_links.append(cve_text)
        # 保留原始值，包括空列表
        if cve_links:
            result['cveids'] = ', '.join(cve_links)

        # publicdate：Date Public 行
        for b_tag in soup.find_all('b'):
            if b_tag.get_text(strip=True) == 'Date Public:':
                td = b_tag.find_parent('td')
                if td:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        result['publicdate'] = next_td.get_text(strip=True)
                break

        # datefirstpublished：id="datefirstpublished"
        dfp = soup.find(id='datefirstpublished')
        if dfp:
            result['datefirstpublished'] = dfp.get_text(strip=True)

        # dateupdated：Date Last Updated 行
        for b_tag in soup.find_all('b'):
            if 'Date Last Updated' in b_tag.get_text():
                td = b_tag.find_parent('td')
                if td:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        result['dateupdated'] = next_td.get_text(strip=True)
                break

        # revision：Document Revision 行
        for b_tag in soup.find_all('b'):
            if 'Document Revision' in b_tag.get_text():
                td = b_tag.find_parent('td')
                if td:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        result['revision'] = next_td.get_text(strip=True)
                break

        # cam_scorecurrent：Severity Metric 行
        for b_tag in soup.find_all('b'):
            if 'Severity Metric' in b_tag.get_text():
                td = b_tag.find_parent('td')
                if td:
                    next_td = td.find_next_sibling('td')
                    if next_td:
                        val = next_td.get_text(strip=True)
                        if val:
                            try:
                                result['cam_scorecurrent'] = float(val)
                            except ValueError:
                                pass
                break

        # sysaffected：vendor accordion 中的受影响厂商列表
        vendor_div = soup.find('div', id='vendorinfo')
        if vendor_div:
            vendors = vendor_div.find_all('div', attrs={'data-type': 'accordion-section'})
            vendor_list = []
            for v in vendors:
                name = v.get('name', '').strip()
                status_span = v.find('span', class_='label')
                status = status_span.get_text(strip=True) if status_span else 'Unknown'
                if name:
                    vendor_list.append(f'{name}: {status}')
            # 保留原始值，包括空列表
            if vendor_list:
                result['sysaffected'] = '\n'.join(vendor_list)

        # publicdate 备用：meta[name='sei_date_published']
        if not result.get('publicdate'):
            meta_pub = soup.find('meta', {'name': 'sei_date_published'})
            if meta_pub:
                result['publicdate'] = meta_pub.get('content')

        return result


class ExtractorAgent:
    """提取智能体 - 识别来源并提取数据"""
    
    def __init__(self, config: Dict, message_bus):
        """
        初始化提取智能体
        
        Args:
            config: 配置字典
            message_bus: 消息总线实例
        """
        self.config = config
        self.message_bus = message_bus
        
        # 加载字段配置
        from config.field_config_loader import FieldConfigLoader
        import os
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'field_mappings.yaml')
        self.config_loader = FieldConfigLoader(config_path)
        
        # 为每个源创建提取器
        self.extractors = {}
        for source in self.config_loader.get_all_sources():
            source_config = self.config_loader.get_source_config(source)
            # Store with lowercase key for consistent lookup
            self.extractors[source.lower()] = SourceExtractor(
                source=source,
                field_config=source_config,
            )
        
        logger.info(f"Extractor agent initialized with sources: {list(self.extractors.keys())}")

    def identify_source(self, file_path: str, content: str) -> str:
        """
        识别漏洞来源
        
        Args:
            file_path: 文件路径
            content: 文件内容
        
        Returns:
            来源名称（大写）
        """
        # 转换为小写便于匹配
        file_path_lower = file_path.lower()
        filename = Path(file_path).name.lower()
        
        # 1. 优先基于文件路径识别（检查目录名）- 精确匹配目录分隔符
        if '/cert/' in file_path_lower or '\\cert\\' in file_path_lower:
            return 'CERT'
        elif '/jvn/' in file_path_lower or '\\jvn\\' in file_path_lower:
            return 'JVN'
        elif '/cnvd/' in file_path_lower or '\\cnvd\\' in file_path_lower:
            return 'CNVD'
        elif '/cisa/' in file_path_lower or '\\cisa\\' in file_path_lower:
            return 'CISA'
        elif '/nvd/' in file_path_lower or '\\nvd\\' in file_path_lower:
            return 'NVD'
        elif '/cve/' in file_path_lower or '\\cve\\' in file_path_lower:
            return 'CVE'
        
        # 1.5. 检查路径中包含的关键词（用于像 nvd_cve_jsons_free 这样的目录名）
        path_parts = file_path_lower.replace('\\', '/').split('/')
        for part in path_parts:
            if 'nvd' in part and 'cve' in part:  # nvd_cve_jsons_free 这样的目录
                return 'NVD'
            elif part == 'cert' or 'cert' in part:
                return 'CERT'
            elif part == 'jvn' or 'jvn' in part:
                return 'JVN'
            elif part == 'cnvd' or 'cnvd' in part:
                return 'CNVD'
            elif part == 'cisa' or 'cisa' in part:
                return 'CISA'
            elif part == 'nvd' or part.startswith('nvd'):
                return 'NVD'
            elif part == 'cve' or part.startswith('cve'):
                return 'CVE'
        
        # 2. 基于文件名模式识别
        for source, pattern in SOURCE_PATTERNS.items():
            if re.search(pattern, filename):
                return source.upper()
        
        # 3. 基于文件名中的特征识别
        if filename.startswith('vu-') or filename.startswith('vu#'):
            return 'CERT'
        elif filename.startswith('jvn'):
            return 'JVN'
        elif filename.startswith('cnvd'):
            return 'CNVD'
        elif filename.startswith('cve-'):
            return 'CVE'
        
        # 4. 最后基于内容识别
        content_lower = content.lower()
        if 'cnvd' in content_lower:
            return 'CNVD'
        elif 'jvn' in content_lower:
            return 'JVN'
        elif 'cert' in content_lower or 'vulnerability note' in content_lower:
            return 'CERT'
        elif 'cisa' in content_lower:
            return 'CISA'
        elif 'cve' in content_lower:
            return 'CVE'
        
        return 'UNKNOWN'
