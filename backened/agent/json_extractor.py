"""
JSON Extractor - JSON数据提取器
专门用于提取嵌套JSON结构的数据，字段名使用下划线连接
"""
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class JSONExtractor:
    """JSON数据提取器 - 将嵌套JSON扁平化为下划线连接的字段"""
    
    def __init__(self, source: str, field_config: Dict):
        """
        初始化JSON提取器
        
        Args:
            source: 数据源名称（cve, nvd等）
            field_config: 字段配置（从field_mappings.yaml加载）
        """
        self.source = source.lower()
        self.field_config = field_config
        
        # 构建主表字段白名单
        self.valid_fields = set(f['name'] for f in field_config.get('fields', []))
        
        # 构建子表字段白名单（如果有子表）
        self.valid_subtable_fields = set()
        if field_config.get('has_subtable'):
            subtable = field_config.get('subtable', {})
            self.valid_subtable_fields = set(f['name'] for f in subtable.get('fields', []))
        
        logger.info(f"JSON提取器初始化: source={source}, 主表字段数={len(self.valid_fields)}, 子表字段数={len(self.valid_subtable_fields)}")
    
    def flatten_json(self, data: Dict[str, Any], prefix: str = '', result: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        将嵌套JSON扁平化为下划线连接的字段
        
        Args:
            data: JSON数据
            prefix: 字段前缀
            result: 结果字典
        
        Returns:
            扁平化后的字典
        
        Example:
            Input: {"cveMetadata": {"cveId": "CVE-2024-1234", "state": "PUBLISHED"}}
            Output: {"cveMetadata_cveId": "CVE-2024-1234", "cveMetadata_state": "PUBLISHED"}
        """
        if result is None:
            result = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}_{key}" if prefix else key
                
                if isinstance(value, dict):
                    # 递归处理嵌套字典
                    self.flatten_json(value, new_key, result)
                elif isinstance(value, list):
                    # 处理列表
                    self._handle_list(value, new_key, result)
                else:
                    # 基本类型直接存储
                    result[new_key] = value
        
        return result
    
    def _handle_list(self, data: List, prefix: str, result: Dict[str, Any]):
        """
        处理列表类型的数据
        
        对于不同类型的列表采用不同策略：
        1. 字符串列表：用逗号连接
        2. 字典列表：取第一个元素展开，或合并所有元素
        3. 其他：转为字符串
        """
        if not data:
            # 保留空列表的原始值，不转换为None
            result[prefix] = data
            return
        
        # 如果是字符串列表，用逗号连接
        if all(isinstance(item, str) for item in data):
            result[prefix] = ', '.join(data)
            return
        
        # 如果是字典列表
        if all(isinstance(item, dict) for item in data):
            # 对于某些特殊字段，取第一个元素
            if any(keyword in prefix.lower() for keyword in ['description', 'reference', 'affected', 'problemtype']):
                # 取第一个元素并展开
                if data:
                    self.flatten_json(data[0], prefix, result)
            else:
                # 对于其他情况，尝试合并所有元素
                for idx, item in enumerate(data):
                    if idx == 0:
                        # 第一个元素直接展开
                        self.flatten_json(item, prefix, result)
                    else:
                        # 后续元素添加索引
                        self.flatten_json(item, f"{prefix}_{idx}", result)
            return
        
        # 其他情况转为字符串
        result[prefix] = str(data)
    
    def filter_fields(self, data: Dict[str, Any], valid_fields: set, log_filtered: bool = False) -> Dict[str, Any]:
        """
        过滤字段，只保留field_mappings.yaml中定义的字段
        
        Args:
            data: 原始数据
            valid_fields: 有效字段集合（从field_mappings.yaml加载）
            log_filtered: 是否记录被过滤的字段
        
        Returns:
            过滤后的数据
        """
        filtered = {}
        filtered_out = []
        
        for key, value in data.items():
            if key in valid_fields:
                filtered[key] = value
            else:
                filtered_out.append(key)
        
        if log_filtered:
            if filtered_out:
                logger.debug(f"过滤掉的字段 ({len(filtered_out)}): {', '.join(filtered_out[:10])}{'...' if len(filtered_out) > 10 else ''}")
            
            # 显示保留的字段（用于调试）
            kept_fields = list(filtered.keys())
            logger.debug(f"保留的字段 ({len(kept_fields)}): {', '.join(kept_fields[:10])}{'...' if len(kept_fields) > 10 else ''}")
        
        logger.info(f"字段过滤: 原始={len(data)}, 保留={len(filtered)}, 过滤={len(filtered_out)} (基于field_mappings.yaml)")
        
        return filtered
    
    def extract_cve(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        提取CVE数据（只提取field_mappings.yaml中定义的字段）
        
        Args:
            data: CVE JSON数据
        
        Returns:
            扁平化的CVE数据
        """
        # 扁平化整个JSON
        flattened = self.flatten_json(data)
        
        # 特殊处理：提取第一个affected产品和厂商
        if 'containers' in data and 'cna' in data['containers']:
            cna = data['containers']['cna']
            
            # 提取affected信息
            if 'affected' in cna and cna['affected']:
                first_affected = cna['affected'][0]
                flattened['containers_cna_affected_product'] = first_affected.get('product', '')
                flattened['containers_cna_affected_vendor'] = first_affected.get('vendor', '')
                
                # 提取CPE列表
                if 'cpes' in first_affected:
                    flattened['containers_cna_affected_cpes'] = ', '.join(first_affected['cpes'])
            
            # 提取descriptions：合并所有条目的value（优先en排最前）
            if 'descriptions' in cna and cna['descriptions']:
                sorted_descs = sorted(cna['descriptions'], key=lambda d: (0 if d.get('lang', '').lower() == 'en' else 1))
                flattened['containers_cna_descriptions_lang'] = sorted_descs[0].get('lang', '')
                flattened['containers_cna_descriptions_value'] = ' | '.join(d.get('value', '') for d in sorted_descs if d.get('value', ''))
            
            # 提取references：合并所有条目（用 | 分隔，VARCHAR截断）
            if 'references' in cna and cna['references']:
                all_urls = [r.get('url', '') for r in cna['references'] if r.get('url', '')]
                combined_url = ' | '.join(all_urls)
                flattened['containers_cna_references_url'] = combined_url[:512] if len(combined_url) > 512 else combined_url
                # tags：合并所有条目的 tags（每条 tags 列表内部用逗号，条目间用 |）
                all_tags = [', '.join(r['tags']) for r in cna['references'] if r.get('tags')]
                combined_tags = ' | '.join(all_tags)
                if combined_tags:
                    flattened['containers_cna_references_tags'] = combined_tags[:255]
                # name：合并所有条目的 name（用 | 分隔，过滤空值）
                all_names = [r['name'] for r in cna['references'] if r.get('name')]
                combined_names = ' | '.join(all_names)
                if combined_names:
                    flattened['containers_cna_references_name'] = combined_names[:255]
        
        # 使用field_mappings.yaml中定义的字段进行过滤
        result = self.filter_fields(flattened, self.valid_fields, log_filtered=True)
        
        return result
    
    def extract_cve_metrics(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        提取CVE的CVSS评分数据（子表）
        
        Args:
            data: CVE JSON数据
        
        Returns:
            过滤后的CVSS评分记录列表
        """
        metrics_records = []
        cve_id = data.get('cveMetadata', {}).get('cveId', '')
        
        if 'containers' in data and 'cna' in data['containers']:
            cna = data['containers']['cna']
            
            if 'metrics' in cna:
                for metric in cna['metrics']:
                    # 检测CVSS版本
                    for version_key in ['cvssV2_0', 'cvssV3_0', 'cvssV3_1', 'cvssV4_0']:
                        if version_key in metric:
                            record = {'cve_id': cve_id}
                            
                            # 扁平化该版本的CVSS数据（字段名含版本信息，如 containers_cna_metrics_cvssV2_0_baseScore）
                            cvss_data = metric[version_key]
                            flattened_cvss = self.flatten_json(cvss_data, f'containers_cna_metrics_{version_key}')
                            record.update(flattened_cvss)
                            
                            # 过滤字段（只保留子表中存在的字段）
                            filtered_record = self.filter_fields(record, self.valid_subtable_fields, log_filtered=False)
                            
                            if filtered_record:
                                metrics_records.append(filtered_record)
        
        return metrics_records
    
    def extract_nvd(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        提取NVD数据

        NVD格式：根级别有 id, descriptions, metrics, references 等字段

        Args:
            data: NVD JSON数据

        Returns:
            过滤后的NVD数据（只包含field_mappings.yaml中定义的字段）
        """
        result = {}

        # CVE ID字段映射：NVD JSON中的'id'字段映射到数据库的'cve_id'字段
        if 'id' in data:
            result['cve_id'] = data['id']

        # 提取descriptions：仅保留英文描述（lang=en），若无英文则回退第一条
        if 'descriptions' in data and data['descriptions']:
            en_desc = next((d for d in data['descriptions'] if d.get('lang', '').lower() == 'en' and d.get('value')), None)
            selected = en_desc if en_desc else data['descriptions'][0]
            result['descriptions_lang'] = selected.get('lang', '')
            result['descriptions_value'] = selected.get('value', '')

        # 提取references：合并所有URL（VARCHAR(512)截断）
        if 'references' in data and data['references']:
            all_urls = [r.get('url', '') for r in data['references'] if r.get('url', '')]
            combined = ' | '.join(all_urls)
            result['references_url'] = combined[:512] if len(combined) > 512 else combined

        # 直接映射的字段
        for field in ['published', 'lastModified']:
            if field in data:
                result[field] = data[field]

        # 提取vendorComments（如果存在）
        if 'vendorComments' in data and data['vendorComments']:
            vendor_comment = data['vendorComments'][0]
            result['vendorComments_comment'] = vendor_comment.get('comment', '')
            result['vendorComments_lastModified'] = vendor_comment.get('lastModified', '')
            result['vendorComments_organization'] = vendor_comment.get('organization', '')

        # 提取evaluatorComment（如果存在）
        if 'evaluatorComment' in data:
            result['evaluatorComment'] = data['evaluatorComment']

        # 使用field_mappings.yaml中定义的字段进行过滤
        filtered = self.filter_fields(result, self.valid_fields, log_filtered=True)

        logger.info(f"NVD字段提取: 原始={len(result)}, 保留={len(filtered)}, JSON的id映射到cve_id")

        return filtered

    
    def extract_nvd_metrics(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        提取NVD的CVSS评分数据（子表）
        
        支持两种NVD JSON格式：
        1. 旧格式（如CVE-2005-xxxx）：metrics.cvssMetricV2[]/cvssMetricV31[] 列表，每项有 type: Primary/Secondary
        2. 新格式（CVE Record 5.x，如CVE-2025-xxxx）：containers.cna.metrics[{cvssV4_0:{...}}, ...]
        
        Args:
            data: NVD JSON数据
        
        Returns:
            过滤后的CVSS评分记录列表（每个版本一条记录，合并到同一行）
        """
        metrics_records = []
        cve_id = data.get('id', '')  # 旧格式
        
        # --- 格式1：旧格式 metrics.cvssMetricV2/V30/V31/V40 ---
        if 'metrics' in data and isinstance(data['metrics'], dict):
            metrics = data['metrics']
            # 每个版本只取 type=Primary 的第一条，合并成一条记录
            record = {'cve_id': cve_id}
            has_data = False
            
            for version_key in ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31', 'cvssMetricV40']:
                if version_key not in metrics:
                    continue
                metric_list = metrics[version_key]
                if not isinstance(metric_list, list):
                    continue
                
                # 只取 type=Primary 的第一条
                primary_metric = next(
                    (m for m in metric_list if m.get('type', '').lower() == 'primary'),
                    None
                )
                if primary_metric is None and metric_list:
                    # 若没有 Primary 标记，取第一条
                    primary_metric = metric_list[0]
                
                if primary_metric:
                    # 扁平化该版本的CVSS数据，字段名带版本前缀如 metrics_cvssMetricV2_xxx
                    flattened_metric = self.flatten_json(primary_metric, f'metrics_{version_key}')
                    record.update(flattened_metric)
                    has_data = True
                            
            if has_data:
                filtered_record = self.filter_fields(record, self.valid_subtable_fields, log_filtered=False)
                if filtered_record:
                    metrics_records.append(filtered_record)
            return metrics_records
        
        # --- 格式2：新CVE Record格式 containers.cna.metrics [{cvssV3_1:{...}}, ...] ---
        # 将新格式字段名映射到旧格式字段名，复用已有的 t_nvd_metrics 列
        if 'containers' in data and isinstance(data.get('containers'), dict):
            cve_id = data.get('cveMetadata', {}).get('cveId', '') or cve_id
            cna = data['containers'].get('cna', {})
            metrics_list = cna.get('metrics', [])

            # 新格式版本键 -> 旧格式字段前缀映射
            new_to_old_prefix = {
                'cvssV2_0': 'metrics_cvssMetricV2',
                'cvssV3_0': 'metrics_cvssMetricV30',
                'cvssV3_1': 'metrics_cvssMetricV31',
                'cvssV4_0': 'metrics_cvssMetricV40',
            }
            # V2 顶层字段（不放在 cvssData 下）
            v2_top_fields = {'baseSeverity', 'exploitabilityScore', 'impactScore', 'source', 'type'}
            # V3/V4 顶层字段（baseSeverity 除外，它在 cvssData 下）
            v3v4_top_fields = {'exploitabilityScore', 'impactScore', 'source', 'type'}

            record = {'cve_id': cve_id}
            has_data = False

            for metric_item in metrics_list:
                for version_key, old_prefix in new_to_old_prefix.items():
                    if version_key not in metric_item:
                        continue
                    cvss_obj = metric_item[version_key]
                    if not isinstance(cvss_obj, dict):
                        continue

                    is_v2 = (version_key == 'cvssV2_0')
                    for field, value in cvss_obj.items():
                        if is_v2:
                            # V2: baseSeverity/exploitabilityScore/impactScore 是顶层字段
                            if field in v2_top_fields:
                                record[f'{old_prefix}_{field}'] = value
                            else:
                                record[f'{old_prefix}_cvssData_{field}'] = value
                        else:
                            # V3/V4: baseSeverity 在 cvssData 下，其他特定字段在顶层
                            if field in v3v4_top_fields:
                                record[f'{old_prefix}_{field}'] = value
                            else:
                                record[f'{old_prefix}_cvssData_{field}'] = value
                    has_data = True

            if has_data:
                filtered_record = self.filter_fields(record, self.valid_subtable_fields, log_filtered=False)
                if filtered_record:
                    metrics_records.append(filtered_record)
        
        return metrics_records
    
    def extract(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据数据源类型提取数据
        
        Args:
            data: JSON数据
        
        Returns:
            提取的数据
        """
        if self.source == 'cve':
            return self.extract_cve(data)
        elif self.source == 'nvd':
            return self.extract_nvd(data)
        else:
            # 其他数据源直接扁平化
            return self.flatten_json(data)
    
    def extract_with_subtable(self, data: Dict[str, Any]) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        提取主表和子表数据
        
        Args:
            data: JSON数据
        
        Returns:
            (主表数据, 子表数据列表)
        """
        main_data = self.extract(data)
        
        if self.source == 'cve':
            sub_data = self.extract_cve_metrics(data)
        elif self.source == 'nvd':
            sub_data = self.extract_nvd_metrics(data)
        else:
            sub_data = []
        
        return main_data, sub_data


if __name__ == '__main__':
    # 测试代码
    import json
    from config.field_config_loader import FieldConfigLoader
    import os
    
    # 加载字段配置
    config_path = os.path.join('config', 'field_mappings.yaml')
    config_loader = FieldConfigLoader(config_path)
    cve_config = config_loader.get_source_config('cve')
    
    # 测试CVE提取
    test_cve = {
        "cveMetadata": {
            "cveId": "CVE-2024-1234",
            "state": "PUBLISHED",
            "datePublished": "2024-01-01T00:00:00"
        },
        "containers": {
            "cna": {
                "descriptions": [
                    {"lang": "en", "value": "Test vulnerability description"}
                ],
                "affected": [
                    {
                        "vendor": "TestVendor",
                        "product": "TestProduct",
                        "versions": [{"version": "1.0", "status": "affected"}]
                    }
                ]
            }
        }
    }
    
    extractor = JSONExtractor('cve', cve_config)
    result = extractor.extract(test_cve)
    
    print("提取结果:")
    for key, value in sorted(result.items()):
        print(f"  {key}: {value}")
