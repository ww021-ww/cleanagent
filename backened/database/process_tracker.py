"""
处理记录追踪器 - 记录已处理的文件，避免重复处理
Process Tracker - Track processed files to avoid duplication
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Set, Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()


class ProcessedFile(Base):
    """已处理文件记录表"""
    __tablename__ = 't_processed_files'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(50), nullable=False, index=True, comment='漏洞库来源')
    filename = Column(String(255), nullable=False, index=True, comment='文件名')
    filepath = Column(String(500), nullable=True, comment='文件完整路径')
    file_hash = Column(String(64), nullable=True, comment='文件MD5哈希')
    vuid = Column(String(100), nullable=True, index=True, comment='漏洞ID')
    status = Column(String(20), default='success', comment='处理状态: success/failed/skipped')
    error_message = Column(Text, nullable=True, comment='错误信息')
    process_time = Column(DateTime, default=datetime.now, comment='处理时间')
    create_time = Column(DateTime, default=datetime.now, comment='创建时间')
    
    def __repr__(self):
        return f"<ProcessedFile(source={self.source}, filename={self.filename}, status={self.status})>"


class ProcessTracker:
    """处理追踪器 - 管理已处理文件记录"""
    
    def __init__(self, db_uri: str):
        """
        初始化处理追踪器
        
        Args:
            db_uri: 数据库连接URI
        """
        self.engine = create_engine(db_uri, echo=False, pool_pre_ping=True)
        self.Session = sessionmaker(bind=self.engine)
        
        # 创建表
        Base.metadata.create_all(self.engine)
        logger.info("Process tracker initialized")
    
    def is_processed(self, filename: str, source: str = 'cert') -> bool:
        """
        检查文件是否已处理
        
        Args:
            filename: 文件名
            source: 漏洞库来源
        
        Returns:
            是否已处理
        """
        session = self.Session()
        try:
            exists = session.query(ProcessedFile).filter(
                ProcessedFile.filename == filename,
                ProcessedFile.source == source,
                ProcessedFile.status == 'success'
            ).first()
            
            return exists is not None
        finally:
            session.close()
    
    def mark_processed(self, filename: str, source: str = 'cert', 
                      filepath: str = None, vuid: str = None,
                      status: str = 'success', error_message: str = None) -> bool:
        """
        标记文件为已处理
        
        Args:
            filename: 文件名
            source: 漏洞库来源
            filepath: 文件完整路径
            vuid: 漏洞ID
            status: 处理状态 (success/failed/skipped)
            error_message: 错误信息
        
        Returns:
            是否成功
        """
        session = self.Session()
        try:
            # 检查是否已存在
            existing = session.query(ProcessedFile).filter(
                ProcessedFile.filename == filename,
                ProcessedFile.source == source
            ).first()
            
            if existing:
                # 更新记录
                existing.status = status
                existing.vuid = vuid
                existing.error_message = error_message
                existing.process_time = datetime.now()
                logger.debug(f"Updated processed file: {filename}")
            else:
                # 创建新记录
                record = ProcessedFile(
                    source=source,
                    filename=filename,
                    filepath=filepath,
                    vuid=vuid,
                    status=status,
                    error_message=error_message
                )
                session.add(record)
                logger.debug(f"Marked as processed: {filename}")
            
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to mark file as processed: {e}")
            return False
        finally:
            session.close()
    
    def get_processed_files(self, source: str = 'cert', 
                           status: str = None) -> List[str]:
        """
        获取已处理的文件列表
        
        Args:
            source: 漏洞库来源
            status: 过滤状态 (可选)
        
        Returns:
            文件名列表
        """
        session = self.Session()
        try:
            query = session.query(ProcessedFile.filename).filter(
                ProcessedFile.source == source
            )
            
            if status:
                query = query.filter(ProcessedFile.status == status)
            
            results = query.all()
            return [r[0] for r in results]
        finally:
            session.close()
    
    def get_unprocessed_files(self, directory: str, pattern: str = '*.html',
                             source: str = 'cert') -> List[Path]:
        """
        获取未处理的文件列表
        
        Args:
            directory: 目录路径
            pattern: 文件匹配模式
            source: 漏洞库来源
        
        Returns:
            未处理的文件路径列表
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return []
        
        # 获取所有文件
        all_files = list(dir_path.glob(pattern))
        
        # 获取已处理的文件名集合
        processed_set = set(self.get_processed_files(source, status='success'))
        
        # 过滤出未处理的文件
        unprocessed = [
            f for f in all_files 
            if f.name not in processed_set
        ]
        
        logger.info(f"Total files: {len(all_files)}, "
                   f"Processed: {len(processed_set)}, "
                   f"Unprocessed: {len(unprocessed)}")
        
        return unprocessed
    
    def get_failed_files(self, source: str = 'cert') -> List[dict]:
        """
        获取处理失败的文件列表
        
        Args:
            source: 漏洞库来源
        
        Returns:
            失败文件信息列表
        """
        session = self.Session()
        try:
            results = session.query(ProcessedFile).filter(
                ProcessedFile.source == source,
                ProcessedFile.status == 'failed'
            ).all()
            
            return [{
                'filename': r.filename,
                'filepath': r.filepath,
                'error_message': r.error_message,
                'process_time': r.process_time
            } for r in results]
        finally:
            session.close()
    
    def get_stats(self, source: str = 'cert') -> dict:
        """
        获取处理统计信息
        
        Args:
            source: 漏洞库来源
        
        Returns:
            统计信息字典
        """
        session = self.Session()
        try:
            total = session.query(ProcessedFile).filter(
                ProcessedFile.source == source
            ).count()
            
            success = session.query(ProcessedFile).filter(
                ProcessedFile.source == source,
                ProcessedFile.status == 'success'
            ).count()
            
            failed = session.query(ProcessedFile).filter(
                ProcessedFile.source == source,
                ProcessedFile.status == 'failed'
            ).count()
            
            skipped = session.query(ProcessedFile).filter(
                ProcessedFile.source == source,
                ProcessedFile.status == 'skipped'
            ).count()
            
            return {
                'source': source,
                'total': total,
                'success': success,
                'failed': failed,
                'skipped': skipped,
                'success_rate': f"{(success/total*100):.1f}%" if total > 0 else "0%"
            }
        finally:
            session.close()
    
    def reset_failed(self, source: str = 'cert') -> int:
        """
        重置失败的记录，以便重新处理
        
        Args:
            source: 漏洞库来源
        
        Returns:
            重置的记录数
        """
        session = self.Session()
        try:
            count = session.query(ProcessedFile).filter(
                ProcessedFile.source == source,
                ProcessedFile.status == 'failed'
            ).delete()
            
            session.commit()
            logger.info(f"Reset {count} failed records for {source}")
            return count
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to reset failed records: {e}")
            return 0
        finally:
            session.close()
    
    def clear_all(self, source: str = None) -> int:
        """
        清除所有处理记录（谨慎使用）
        
        Args:
            source: 漏洞库来源（可选，不指定则清除所有）
        
        Returns:
            清除的记录数
        """
        session = self.Session()
        try:
            query = session.query(ProcessedFile)
            if source:
                query = query.filter(ProcessedFile.source == source)
            
            count = query.delete()
            session.commit()
            logger.warning(f"Cleared {count} processed records")
            return count
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to clear records: {e}")
            return 0
        finally:
            session.close()
    
    def close(self):
        """关闭数据库连接"""
        self.engine.dispose()
        logger.info("Process tracker closed")
