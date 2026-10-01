"""
Cleaner-Validator Agent - 清洗验证智能体
负责数据清洗和质量验证
"""
import logging
import re
from datetime import datetime
from typing import Dict, Any
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


class DataCleaner:
    """数据清洗器"""

    _DATE_FIELD_NAMES: frozenset = frozenset({
        'published', 'lastmodified', 'datepublished',
        'dateupdated', 'datereserved', 'daterejected',
    })

    def __init__(self, llm: ChatOpenAI = None):
        self.llm = llm
    
    def clean(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清洗数据
        
        Args:
            data: 原始数据
        
        Returns:
            清洗后的数据
        """
        # Handle None or empty data
        if not data:
            return {}
        
        cleaned = {}
        
        for key, value in data.items():
            if value is None:
                cleaned[key] = None
                continue
            
            # 日期清洗（优先检查，因为日期也是字符串）
            # 包含 date/time 关键词，或者已知的日期字段名
            if 'date' in key.lower() or 'time' in key.lower() or key.lower() in self._DATE_FIELD_NAMES:
                cleaned[key] = self.clean_date(value)
            # 字符串清洗
            elif isinstance(value, str):
                cleaned[key] = self.clean_string(value)
            else:
                cleaned[key] = value
        
        return cleaned
    
    def clean_string(self, text: str) -> str:
        """清洗字符串"""
        if not text:
            # 保留原始值，不转换为空字符串
            return text
        
        # 去除HTML标签
        soup = BeautifulSoup(text, 'html.parser')
        text = soup.get_text()
        
        # 去除多余空白
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        
        # 去除特殊字符
        text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', text)
        
        return text
    
    def clean_date(self, date_value: Any) -> Any:
        """清洗日期"""
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d %H:%M:%S')
        
        if isinstance(date_value, str):
            date_value = date_value.strip()
            
            # 处理 CERT HTML 格式: '2004-03-23 22:07 UTC' 或 '2004-03-23 22:07'
            if 'UTC' in date_value:
                try:
                    # 移除 UTC 时区标识
                    date_str = date_value.replace(' UTC', '').strip()
                    # 验证格式
                    datetime.strptime(date_str, '%Y-%m-%d %H:%M')
                    return date_str
                except ValueError:
                    pass
            
            # 处理ISO 8601格式 (2024-08-01T16:03:04.917Z)
            if 'T' in date_value:
                try:
                    # 移除毫秒和时区标识
                    date_str = date_value.replace('Z', '').split('.')[0]
                    # 替换T为空格
                    date_str = date_str.replace('T', ' ')
                    # 验证格式
                    datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                    return date_str
                except ValueError:
                    pass
            
            # 尝试解析常见日期格式
            date_patterns = [
                (r'(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})', '%Y-%m-%d %H:%M:%S'),
                (r'(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})', '%Y-%m-%d %H:%M'),
                (r'(\d{4})-(\d{2})-(\d{2})', '%Y-%m-%d'),
                (r'(\d{4})/(\d{2})/(\d{2})', '%Y/%m/%d'),
                (r'(\d{2})/(\d{2})/(\d{4})', '%m/%d/%Y'),
            ]
            
            for pattern, fmt in date_patterns:
                match = re.search(pattern, date_value)
                if match:
                    try:
                        parsed = datetime.strptime(match.group(0), fmt)
                        return parsed.strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        continue
        
        # 保留原始值，不转换为None
        return date_value


class CleanerValidatorAgent:
    """清洗验证智能体 - 清洗数据并验证质量"""
    
    def __init__(self, config: Dict, message_bus):
        """
        初始化清洗验证智能体
        
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
        
        # 初始化LLM（可选）
        from config import get_llm_config
        llm_config = get_llm_config()
        self.llm = ChatOpenAI(**llm_config)
        
        # 初始化清洗器
        self.cleaner = DataCleaner(self.llm)
        
        # 配置参数
        agent_config = config.get('agents', {}).get('cleaner_validator', {})
        self.quality_threshold = agent_config.get('quality_threshold', 0.7)
        self.enable_llm_validation = agent_config.get('enable_llm_validation', False)
        
        logger.info(f"Cleaner-Validator agent initialized (threshold={self.quality_threshold})")

    def validate(self, data: Dict, source: str) -> Dict:
        """
        验证数据
        
        Args:
            data: 清洗后的数据
            source: 漏洞库名称
        
        Returns:
            验证结果
        """
        config = self.config_loader.get_source_config(source)
        errors = []
        warnings = []
        field_issues = []
        evidence_gaps = []
        
        # 1. 必填字段检查
        required_fields = self.config_loader.get_required_fields(source)
        for field_name in required_fields:
            if not data.get(field_name):
                message = f"Missing required field: {field_name}"
                errors.append(message)
                field_issues.append({
                    'field': field_name,
                    'code': 'missing_required',
                    'severity': 'error',
                    'message': message,
                    'evidence_required': True,
                })
                evidence_gaps.append({
                    'field': field_name,
                    'reason': 'required_field_missing',
                })

        quality_cfg = getattr(self, 'config', {}).get('agentic', {}).get(
            'quality_gate', {}
        )
        quality_profile = quality_cfg.get('profiles', {}).get(source.lower(), {})
        if quality_cfg.get('enabled', False) and quality_profile:
            required_any = quality_profile.get('required_any', {})
            important_any = quality_profile.get('important_any', {})

            for fields in required_any.values():
                if not any(data.get(field) for field in fields):
                    target = fields[0]
                    message = f"Missing required field: {target}"
                    errors.append(message)
                    field_issues.append({
                        'field': target,
                        'code': 'missing_required',
                        'severity': 'error',
                        'message': message,
                        'evidence_required': True,
                    })
                    evidence_gaps.append({
                        'field': target,
                        'reason': 'quality_field_missing',
                    })

            for label, fields in important_any.items():
                if not any(data.get(field) for field in fields):
                    message = f"Missing important quality field: {label}"
                    warnings.append(message)
                    field_issues.append({
                        'field': fields[0],
                        'code': 'missing_important',
                        'severity': 'warning',
                        'message': message,
                        'evidence_required': False,
                    })

            quality_groups = [[field] for field in required_fields]
            quality_groups += list(required_any.values()) + list(important_any.values())
            quality_filled = sum(
                any(data.get(field) for field in fields)
                for fields in quality_groups
            )
        
        # 2. 字段类型检查
        for field in config.get('fields', []):
            field_name = field['name']
            if data.get(field_name):
                expected_type = field.get('type', 'string')
                if not self.check_type(data[field_name], expected_type):
                    message = f"Type mismatch for {field_name}: expected {expected_type}"
                    warnings.append(message)
                    field_issues.append({
                        'field': field_name,
                        'code': 'type_mismatch',
                        'severity': 'warning',
                        'message': message,
                        'evidence_required': False,
                    })
        
        # 3. 字段长度检查
        for field in config.get('fields', []):
            field_name = field['name']
            max_length = field.get('max_length')
            if max_length and data.get(field_name):
                if isinstance(data[field_name], str) and len(data[field_name]) > max_length:
                    message = f"Field {field_name} exceeds max length {max_length}"
                    warnings.append(message)
                    field_issues.append({
                        'field': field_name,
                        'code': 'max_length_exceeded',
                        'severity': 'warning',
                        'message': message,
                        'evidence_required': False,
                    })
        
        result = {
            'errors': errors,
            'warnings': warnings,
            'is_valid': len(errors) == 0,
            'field_issues': field_issues,
            'evidence_gaps': evidence_gaps,
        }
        if quality_cfg.get('enabled', False) and quality_profile:
            result['quality_filled'] = quality_filled
            result['quality_total'] = len(quality_groups)
        return result
    
    def check_type(self, value: Any, expected_type: str) -> bool:
        """检查值的类型是否匹配"""
        if value is None:
            return True
        
        type_checks = {
            'string': lambda v: isinstance(v, str),
            'text': lambda v: isinstance(v, str),
            'integer': lambda v: isinstance(v, int),
            'float': lambda v: isinstance(v, (int, float)),
            'boolean': lambda v: isinstance(v, bool),
            'datetime': lambda v: isinstance(v, (str, datetime)),
            'date': lambda v: isinstance(v, (str, datetime)),
        }
        
        check_func = type_checks.get(expected_type, lambda v: True)
        return check_func(value)
    
    def calculate_quality_score(self, data: Dict, validation: Dict, 
                                confidence: float) -> float:
        """
        计算质量分
        
        Args:
            data: 清洗后的数据
            validation: 验证结果
            confidence: 提取置信度
        
        Returns:
            质量分（0-1之间）
        """
        # 基础分：提取置信度（权重50%）
        score = confidence * 0.5
        
        # 验证分：无错误+30%，有警告-5%每个
        if validation['is_valid']:
            score += 0.3
        else:
            score -= len(validation['errors']) * 0.1
        
        score -= len(validation['warnings']) * 0.05
        
        # 完整性分：字段填充率（权重20%）
        filled_count = validation.get(
            'quality_filled', sum(1 for v in data.values() if v)
        )
        total_count = validation.get('quality_total', len(data))
        completeness = filled_count / total_count if total_count > 0 else 0
        score += completeness * 0.2
        
        # 确保分数在0-1之间
        return min(max(score, 0.0), 1.0)
