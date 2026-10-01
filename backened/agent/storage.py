"""
Storage Agent - 存储智能体
负责数据持久化到数据库
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class StorageAgent:
    """存储智能体 - 数据持久化"""
    
    def __init__(self, config: Dict, message_bus):
        """
        初始化存储智能体
        
        Args:
            config: 配置字典
            message_bus: 消息总线实例
        """
        self.config = config
        self.message_bus = message_bus
        
        # 初始化数据库管理器
        from database import DatabaseManager
        from config.field_config_loader import FieldConfigLoader
        import os
        
        db_uri = config.get('db_uri')
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'field_mappings.yaml')
        config_loader = FieldConfigLoader(config_path)
        self.db = DatabaseManager(db_uri, config_loader)
        logger.debug("Storage agent initialized")

    def smart_merge(self, new_data: Dict, source: str) -> Dict:
        """
        智能合并：在 upsert 前查询现有记录，保护已有的有效字段不被空值覆盖
        """
        src_config = self.db.config_loader.get_source_config(source)
        id_field = src_config.get('id_field')
        if not id_field or not new_data.get(id_field):
            return new_data

        model_class = self.db.models.get(source.lower())
        if not model_class:
            return new_data

        session = self.db.Session()
        try:
            existing = session.query(model_class).filter(
                getattr(model_class, id_field) == new_data[id_field]
            ).first()
            if not existing:
                return new_data
            merged = new_data.copy()
            for key, new_val in new_data.items():
                old_val = getattr(existing, key, None)
                if not new_val and old_val:
                    merged[key] = old_val
            return merged
        except Exception as e:
            logger.warning(f"smart_merge 查询失败，使用原始数据: {e}")
            return new_data
        finally:
            session.close()

