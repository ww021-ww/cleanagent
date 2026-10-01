"""
Database Manager for Multi-Agent System
支持动态模型和批量操作的数据库管理器
"""
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, BigInteger
try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .reliability import ReliabilityStore, ReviewTask, VectorIndexOutbox

logger = logging.getLogger(__name__)

ID_TYPE = BigInteger().with_variant(Integer, "sqlite")


# 类型映射
TYPE_MAPPING = {
    'string': String,
    'text': Text,
    'integer': Integer,
    'bigint': BigInteger,
    'float': Float,
    'boolean': Boolean,
    'datetime': DateTime,
    'date': DateTime,
}


class DatabaseManager:
    """数据库管理器 - 支持动态模型和批量操作"""
    
    def __init__(self, db_uri: str, config_loader):
        """
        初始化数据库管理器
        
        Args:
            db_uri: 数据库连接URI
            config_loader: 字段配置加载器实例
        """
        connect_args = {}
        if db_uri.startswith('mysql'):
            connect_args = {
                'connect_timeout': 5,
                'read_timeout': 10,
                'write_timeout': 10,
            }
        self.engine = create_engine(db_uri, echo=False, pool_pre_ping=True, connect_args=connect_args)
        self.Session = sessionmaker(bind=self.engine)
        self.config_loader = config_loader
        self.Base = declarative_base()
        
        # 动态生成所有表模型（主表和子表）
        self.models = {}
        self.subtable_models = {}
        for source in config_loader.get_all_sources():
            try:
                model = self._create_model(source)
                self.models[source.lower()] = model
                logger.debug(f"Created model for {source}")
                
                # 如果有子表，创建子表模型
                if config_loader.has_subtable(source):
                    subtable_model = self._create_subtable_model(source)
                    self.subtable_models[source.lower()] = subtable_model
                    logger.debug(f"Created subtable model for {source}")
            except Exception as e:
                logger.error(f"Failed to create model for {source}: {e}")
        
        # 创建所有表
        try:
            self.Base.metadata.create_all(self.engine)
            self.reliability = ReliabilityStore(self.Session)
            self.reliability.create_tables(self.engine)
            logger.debug("Database tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
    
    def _create_model(self, source: str):
        """
        动态创建SQLAlchemy模型
        
        Args:
            source: 漏洞库名称
        
        Returns:
            动态生成的模型类
        """
        config = self.config_loader.get_source_config(source)
        table_name = config.get('table_name')
        
        if not table_name:
            raise ValueError(f"No table_name defined for source: {source}")
        
        # 基础字段
        attrs = {
            '__tablename__': table_name,
            '__table_args__': {'extend_existing': True},
            'id': Column(ID_TYPE, primary_key=True, autoincrement=True),
            'status': Column(Integer, default=0, comment='状态'),
            'is_deleted': Column(Boolean, default=False, comment='是否删除'),
            'create_time': Column(DateTime, default=datetime.now, comment='创建时间'),
            'modify_time': Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新时间'),
        }
        
        # 添加配置的字段
        for field in config.get('fields', []):
            field_name = field['name']
            field_type = field.get('type', 'string')
            max_length = field.get('max_length', 255)
            required = field.get('required', False)
            description = field.get('description', '')
            
            # 获取SQLAlchemy类型
            if field_type == 'string':
                column_type = String(max_length)
            elif field_type == 'text':
                column_type = Text
            elif field_type in TYPE_MAPPING:
                column_type = TYPE_MAPPING[field_type]
            else:
                column_type = String(255)
            
            # 创建列
            attrs[field_name] = Column(
                column_type,
                nullable=not required,
                comment=description
            )
        
        # 动态创建类
        model_name = f"{source.upper()}Model"
        model_class = type(model_name, (self.Base,), attrs)
        
        return model_class
    
    def _create_subtable_model(self, source: str):
        """
        动态创建子表SQLAlchemy模型
        
        Args:
            source: 漏洞库名称
        
        Returns:
            动态生成的子表模型类
        """
        subtable_config = self.config_loader.get_subtable_config(source)
        
        if not subtable_config:
            raise ValueError(f"No subtable config found for source: {source}")
        
        table_name = subtable_config.get('name')
        if not table_name:
            raise ValueError(f"No table name defined for subtable of source: {source}")
        
        # 基础字段
        attrs = {
            '__tablename__': table_name,
            '__table_args__': {'extend_existing': True},
            'id': Column(ID_TYPE, primary_key=True, autoincrement=True),
            'create_time': Column(DateTime, default=datetime.now, comment='创建时间'),
        }
        
        # 只有当表不存在时才添加modify_time字段
        # 这样可以兼容已存在的表
        try:
            # 检查表是否已存在
            from sqlalchemy import inspect
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()
            
            if table_name not in existing_tables:
                # 表不存在，添加modify_time字段
                attrs['modify_time'] = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新时间')
        except Exception:
            # 如果检查失败，仍然添加字段
            attrs['modify_time'] = Column(DateTime, default=datetime.now, onupdate=datetime.now, comment='更新时间')
        
        # 添加配置的字段
        for field in subtable_config.get('fields', []):
            field_name = field['name']
            field_type = field.get('type', 'string')
            max_length = field.get('max_length', 255)
            required = field.get('required', False)
            description = field.get('description', '')
            
            # 获取SQLAlchemy类型
            if field_type == 'string':
                column_type = String(max_length)
            elif field_type == 'text':
                column_type = Text
            elif field_type in TYPE_MAPPING:
                column_type = TYPE_MAPPING[field_type]
            else:
                column_type = String(255)
            
            # 创建列
            attrs[field_name] = Column(
                column_type,
                nullable=not required,
                comment=description
            )
        
        # 动态创建类
        model_name = f"{source.upper()}SubtableModel"
        model_class = type(model_name, (self.Base,), attrs)
        
        return model_class
    
    def _apply_field_mapping(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """应用字段名映射（处理旧字段名到新字段名的转换）"""
        field_mapping = {
            'comment': 'supplement_information'  # JVN: comment → supplement_information
        }
        
        for old_field, new_field in field_mapping.items():
            if old_field in data:
                data[new_field] = data.pop(old_field)
        
        return data
    
    def upsert(self, data: Dict[str, Any], source: str) -> bool:
        """
        插入或更新单条数据
        
        Args:
            data: 数据字典
            source: 漏洞库名称
        
        Returns:
            是否成功
        """
        session = self.Session()
        try:
            # 应用字段映射
            data = self._apply_field_mapping(data)
            
            model_class = self.models.get(source.lower())
            if not model_class:
                raise ValueError(f"No model found for source: {source}")
            
            config = self.config_loader.get_source_config(source)
            id_field = config.get('id_field')
            
            if not id_field or id_field not in data:
                raise ValueError(f"ID field '{id_field}' not found in data")
            
            # 查找是否存在
            existing = session.query(model_class).filter(
                getattr(model_class, id_field) == data[id_field]
            ).first()
            
            if existing:
                # 更新
                for key, value in data.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.modify_time = datetime.now()
                logger.debug(f"Updated {source}: {data[id_field]}")
            else:
                # 插入
                new_record = model_class(**data)
                session.add(new_record)
                logger.debug(f"Inserted {source}: {data[id_field]}")
            
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Upsert failed for {source}: {e}")
            return False
        finally:
            session.close()

    def _upsert_in_session(self, session, data: Dict[str, Any], source: str) -> str:
        data = self._apply_field_mapping(dict(data))
        model_class = self.models.get(source.lower())
        if not model_class:
            raise ValueError(f"No model found for source: {source}")

        config = self.config_loader.get_source_config(source)
        id_field = config.get('id_field')
        if not id_field or id_field not in data:
            raise ValueError(f"ID field '{id_field}' not found in data")

        validated = self._validate_record_data(data, model_class)
        if validated is None:
            raise ValueError("Record validation failed")

        vuln_id = str(validated[id_field])
        existing = session.query(model_class).filter(
            getattr(model_class, id_field) == validated[id_field]
        ).first()
        if existing:
            for key, value in validated.items():
                setattr(existing, key, value)
            existing.modify_time = datetime.now()
        else:
            session.add(model_class(**validated))
        return vuln_id

    def _upsert_subtable_in_session(self, session, records, source: str) -> None:
        if not records:
            return
        model_class = self.subtable_models.get(source.lower())
        if not model_class:
            raise ValueError(f"No subtable model found for source: {source}")
        foreign_key = self.config_loader.get_subtable_config(source).get(
            'foreign_key', 'cve_id'
        )
        for data in records:
            if foreign_key not in data:
                raise ValueError(f"Missing foreign key '{foreign_key}' in subtable record")
            validated = self._validate_record_data(dict(data), model_class)
            if validated is None:
                raise ValueError("Subtable record validation failed")
            session.add(model_class(**validated))

    def _enqueue_outbox_in_session(self, session, source: str, vuln_id: str) -> None:
        row = session.query(VectorIndexOutbox).filter_by(
            source=source.lower(),
            vuln_id=vuln_id,
        ).first()
        if row is None:
            session.add(VectorIndexOutbox(source=source.lower(), vuln_id=vuln_id))
            return
        row.status = 'pending'
        row.attempt_count = 0
        row.next_retry_at = None
        row.locked_at = None
        row.last_error = None

    def upsert_with_outbox(
        self,
        data: Dict[str, Any],
        source: str,
        subtable_records: Optional[List[Dict[str, Any]]] = None,
        review_task_id: Optional[str] = None,
    ) -> bool:
        """Atomically store source data, subtable rows, vector job, and review result."""
        session = self.Session()
        try:
            vuln_id = self._upsert_in_session(session, data, source)
            self._upsert_subtable_in_session(session, subtable_records or [], source)
            self._enqueue_outbox_in_session(session, source, vuln_id)
            if review_task_id:
                review = session.query(ReviewTask).filter_by(
                    task_id=review_task_id,
                    status='processing',
                ).first()
                if review is None:
                    raise ValueError(f"Review task is not claimed: {review_task_id}")
                review.status = 'approved'
                review.reviewed_at = datetime.utcnow()
                review.locked_at = None
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Atomic upsert failed for {source}: {e}")
            return False
        finally:
            session.close()

    def get_record(self, source: str, vuln_id: str) -> Optional[Dict[str, Any]]:
        model_class = self.models.get(source.lower())
        if not model_class:
            return None
        id_field = self.config_loader.get_source_config(source).get('id_field')
        with self.Session() as session:
            row = session.query(model_class).filter(
                getattr(model_class, id_field) == vuln_id
            ).first()
            if row is None:
                return None
            return {
                column.name: getattr(row, column.name)
                for column in model_class.__table__.columns
            }
    
    def bulk_upsert(self, records: List[Dict[str, Any]], source: str, 
                    batch_size: int = 100) -> Dict[str, int]:
        """
        批量插入或更新数据
        
        Args:
            records: 数据字典列表
            source: 漏洞库名称
            batch_size: 批次大小
        
        Returns:
            统计信息 {'inserted': 数量, 'updated': 数量, 'failed': 数量}
        """
        if not records:
            return {'inserted': 0, 'updated': 0, 'failed': 0}
        
        stats = {'inserted': 0, 'updated': 0, 'failed': 0}
        
        model_class = self.models.get(source.lower())
        if not model_class:
            logger.error(f"No model found for source: {source}")
            stats['failed'] = len(records)
            return stats
        
        config = self.config_loader.get_source_config(source)
        id_field = config.get('id_field')
        
        # 分批处理
        for i in range(0, len(records), batch_size):
            batch = records[i:i+batch_size]
            batch_success = []
            
            # 先处理每个记录，收集成功的记录
            for data in batch:
                try:
                    # 应用字段映射
                    data = self._apply_field_mapping(data)
                    
                    if not id_field or id_field not in data:
                        logger.warning(f"Missing ID field '{id_field}' in record")
                        stats['failed'] += 1
                        continue
                    
                    # 验证数据类型（特别是布尔字段）
                    validated_data = self._validate_record_data(data, model_class)
                    if validated_data is None:
                        stats['failed'] += 1
                        continue
                    
                    batch_success.append(validated_data)
                    
                except Exception as e:
                    logger.error(f"Failed to validate record {data.get(id_field, 'unknown')}: {e}")
                    stats['failed'] += 1
            
            # 批量提交成功的记录
            if batch_success:
                session = self.Session()
                try:
                    for data in batch_success:
                        # 检查是否存在
                        existing = session.query(model_class).filter(
                            getattr(model_class, id_field) == data[id_field]
                        ).first()
                        
                        if existing:
                            # 更新
                            for key, value in data.items():
                                if hasattr(existing, key):
                                    setattr(existing, key, value)
                            existing.modify_time = datetime.now()
                            stats['updated'] += 1
                        else:
                            # 插入
                            new_record = model_class(**data)
                            session.add(new_record)
                            stats['inserted'] += 1
                    
                    # 提交批次
                    session.commit()
                    logger.info(f"Batch committed: {len(batch_success)} records, batch {i//batch_size + 1}")
                    
                except Exception as e:
                    session.rollback()
                    logger.error(f"Batch commit failed: {e}")
                    # 如果批量失败，尝试单个记录处理
                    stats_single = self._process_records_individually(batch_success, model_class, id_field, source)
                    stats['inserted'] += stats_single['inserted']
                    stats['updated'] += stats_single['updated']
                    stats['failed'] += stats_single['failed']
                finally:
                    session.close()
        
        logger.info(f"Bulk upsert completed for {source}: {stats}")
        return stats
    
    def _validate_record_data(self, data: Dict[str, Any], model_class) -> Dict[str, Any]:
        """验证记录数据类型"""
        try:
            validated = {}
            for key, value in data.items():
                if hasattr(model_class, key):
                    column = getattr(model_class, key)
                    if hasattr(column.property, 'columns'):
                        column_type = column.property.columns[0].type
                        
                        # 处理布尔类型（包括 Boolean 和 Integer/TINYINT）
                        if isinstance(column_type, (Boolean,)):
                            if value is None:
                                validated[key] = None
                            elif isinstance(value, bool):
                                validated[key] = value
                            elif isinstance(value, int):
                                validated[key] = bool(value)
                            elif isinstance(value, str):
                                value_lower = value.lower()
                                if value_lower in ['yes', 'true', '1']:
                                    validated[key] = True
                                elif value_lower in ['no', 'false', '0']:
                                    validated[key] = False
                                elif value_lower in ['unknown', 'null', '']:
                                    validated[key] = None
                                else:
                                    validated[key] = None  # 默认为 NULL
                            else:
                                validated[key] = None
                        else:
                            # 其他类型直接使用
                            validated[key] = value
                    else:
                        validated[key] = value
                else:
                    # 字段不存在于模型中，跳过
                    continue
            
            return validated
            
        except Exception as e:
            logger.error(f"Data validation failed: {e}")
            return None
    
    def _process_records_individually(self, records: List[Dict[str, Any]], 
                                    model_class, id_field: str, source: str) -> Dict[str, int]:
        """单个记录处理（批量失败时的后备方案）"""
        stats = {'inserted': 0, 'updated': 0, 'failed': 0}
        
        for data in records:
            session = self.Session()
            try:
                # 应用字段映射
                data = self._apply_field_mapping(data)
                
                # 检查是否存在
                existing = session.query(model_class).filter(
                    getattr(model_class, id_field) == data[id_field]
                ).first()
                
                if existing:
                    # 更新
                    for key, value in data.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                    existing.modify_time = datetime.now()
                    stats['updated'] += 1
                else:
                    # 插入
                    new_record = model_class(**data)
                    session.add(new_record)
                    stats['inserted'] += 1
                
                session.commit()
                
            except Exception as e:
                session.rollback()
                logger.error(f"Individual record processing failed for {data.get(id_field)}: {e}")
                stats['failed'] += 1
            finally:
                session.close()
        
        logger.info(f"Individual processing completed for {source}: {stats}")
        return stats
    
    def get_stats(self, source: str = None) -> Dict[str, Any]:
        """
        获取数据库统计信息
        
        Args:
            source: 漏洞库名称（可选，不指定则返回所有）
        
        Returns:
            统计信息字典
        """
        session = self.Session()
        try:
            if source:
                # 单个源的统计
                model_class = self.models.get(source.lower())
                if not model_class:
                    return {}
                
                total = session.query(model_class).count()
                active = session.query(model_class).filter(
                    model_class.is_deleted.is_(False)
                ).count()
                
                return {
                    'source': source,
                    'total': total,
                    'active': active,
                    'deleted': total - active
                }
            else:
                # 所有源的统计
                all_stats = {}
                for src in self.config_loader.get_all_sources():
                    model_class = self.models.get(src.lower())
                    if model_class:
                        total = session.query(model_class).count()
                        active = session.query(model_class).filter(
                            model_class.is_deleted.is_(False)
                        ).count()
                        all_stats[src] = {
                            'total': total,
                            'active': active,
                            'deleted': total - active
                        }
                
                return all_stats
        finally:
            session.close()
    
    def upsert_subtable(self, records: List[Dict[str, Any]], source: str) -> bool:
        """
        插入或更新子表数据
        
        Args:
            records: 子表数据字典列表
            source: 漏洞库名称
        
        Returns:
            是否成功
        """
        if not records:
            return True
        
        session = self.Session()
        try:
            subtable_model = self.subtable_models.get(source.lower())
            if not subtable_model:
                logger.warning(f"No subtable model found for source: {source}")
                return False
            
            subtable_config = self.config_loader.get_subtable_config(source)
            foreign_key = subtable_config.get('foreign_key', 'cve_id')
            
            for data in records:
                if foreign_key not in data:
                    logger.warning(f"Missing foreign key '{foreign_key}' in subtable record")
                    continue
                
                # 验证数据类型
                validated_data = self._validate_record_data(data, subtable_model)
                if validated_data is None:
                    continue
                
                # 子表为一对多关系（每个CVE可有多条CVSS版本记录），直接插入
                # 注意：重复处理同一文件时会产生重复行，调用方需在处理前清理旧记录
                new_record = subtable_model(**validated_data)
                session.add(new_record)
            
            session.commit()
            logger.debug(f"Upserted {len(records)} subtable records for {source}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Subtable upsert failed for {source}: {e}", exc_info=True)
            return False
        finally:
            session.close()
    
    def bulk_upsert_subtable(self, records: List[Dict[str, Any]], source: str) -> Dict[str, int]:
        """
        批量插入或更新子表数据
        
        Args:
            records: 子表数据字典列表
            source: 漏洞库名称
        
        Returns:
            统计信息 {'inserted': 数量, 'updated': 数量, 'failed': 数量}
        """
        if not records:
            return {'inserted': 0, 'updated': 0, 'failed': 0}
        
        stats = {'inserted': 0, 'updated': 0, 'failed': 0}
        
        subtable_model = self.subtable_models.get(source.lower())
        if not subtable_model:
            logger.warning(f"No subtable model found for source: {source}")
            stats['failed'] = len(records)
            return stats
        
        subtable_config = self.config_loader.get_subtable_config(source)
        foreign_key = subtable_config.get('foreign_key', 'cve_id')
        
        session = self.Session()
        try:
            for data in records:
                try:
                    if foreign_key not in data:
                        logger.warning(f"Missing foreign key '{foreign_key}' in subtable record")
                        stats['failed'] += 1
                        continue
                    
                    # 验证数据类型
                    validated_data = self._validate_record_data(data, subtable_model)
                    if validated_data is None:
                        stats['failed'] += 1
                        continue
                    
                    # 子表为一对多关系（每个CVE可有多条CVSS版本记录），直接插入
                    new_record = subtable_model(**validated_data)
                    session.add(new_record)
                    stats['inserted'] += 1
                
                except Exception as e:
                    logger.error(f"Failed to process subtable record: {e}")
                    stats['failed'] += 1
            
            session.commit()
            logger.info(f"Bulk upsert subtable completed for {source}: {stats}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk subtable upsert failed for {source}: {e}", exc_info=True)
            stats['failed'] = len(records)
        finally:
            session.close()
        
        return stats
    
    def close(self):
        """关闭数据库连接"""
        self.engine.dispose()
        logger.info("Database connection closed")
