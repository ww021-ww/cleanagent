"""
Field Configuration Loader - 字段配置加载器
从YAML配置文件加载字段映射配置
"""
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class FieldConfigLoader:
    """加载和解析字段映射配置"""
    
    def __init__(self, config_path: str):
        """
        初始化配置加载器
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = Path(config_path)
        self.config = self._load_yaml()
        logger.debug(f"Loaded field config from {config_path}")
    
    def _load_yaml(self) -> Dict:
        """加载YAML配置文件"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        return config or {}
    
    def get_source_config(self, source: str) -> Dict:
        """
        获取指定漏洞库的配置
        
        Args:
            source: 漏洞库名称（不区分大小写）
        
        Returns:
            配置字典
        """
        source_lower = source.lower()
        if source_lower not in self.config:
            logger.warning(f"No config found for source: {source}")
            return {}
        
        return self.config[source_lower]
    
    def get_all_sources(self) -> List[str]:
        """
        获取所有配置的漏洞库
        
        Returns:
            漏洞库名称列表
        """
        return list(self.config.keys())
    
    def get_table_name(self, source: str) -> str:
        """
        获取表名
        
        Args:
            source: 漏洞库名称
        
        Returns:
            表名
        """
        config = self.get_source_config(source)
        return config.get('table_name', '')
    
    def get_id_field(self, source: str) -> str:
        """
        获取ID字段名
        
        Args:
            source: 漏洞库名称
        
        Returns:
            ID字段名
        """
        config = self.get_source_config(source)
        return config.get('id_field', '')
    
    def get_fields(self, source: str) -> List[Dict]:
        """
        获取字段列表
        
        Args:
            source: 漏洞库名称
        
        Returns:
            字段配置列表
        """
        config = self.get_source_config(source)
        return config.get('fields', [])
    
    def get_required_fields(self, source: str) -> List[str]:
        """
        获取必填字段列表
        
        Args:
            source: 漏洞库名称
        
        Returns:
            必填字段名列表
        """
        fields = self.get_fields(source)
        return [f['name'] for f in fields if f.get('required', False)]
    
    def get_field_config(self, source: str, field_name: str) -> Optional[Dict]:
        """
        获取指定字段的配置
        
        Args:
            source: 漏洞库名称
            field_name: 字段名
        
        Returns:
            字段配置字典，如果不存在返回None
        """
        fields = self.get_fields(source)
        for field in fields:
            if field['name'] == field_name:
                return field
        return None
    
    def has_subtable(self, source: str) -> bool:
        """
        检查是否有子表
        
        Args:
            source: 漏洞库名称
        
        Returns:
            是否有子表
        """
        config = self.get_source_config(source)
        return config.get('has_subtable', False)
    
    def get_subtable_config(self, source: str) -> Optional[Dict]:
        """
        获取子表配置
        
        Args:
            source: 漏洞库名称
        
        Returns:
            子表配置字典，如果没有子表返回None
        """
        if not self.has_subtable(source):
            return None
        
        config = self.get_source_config(source)
        return config.get('subtable')
    
    def reload(self):
        """重新加载配置文件"""
        self.config = self._load_yaml()
        logger.info("Config reloaded")
