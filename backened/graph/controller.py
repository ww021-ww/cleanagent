"""
LangGraph Controller - LangGraph 控制器
替代原有的 SimplifiedMultiAgentController
"""
import logging
import time
import uuid
import asyncio
from pathlib import Path
from typing import Dict, Any

from graph.state import create_initial_state
from graph.builder import build_vuln_processing_graph
from graph.utils import normalize_jvn_id
from agent.memory import AgentMemory

logger = logging.getLogger(__name__)


def _init_optional(cls, *args, label: str = '', **kwargs):
    """安全初始化可选模块，失败时返回 None 并记录警告"""
    try:
        obj = cls(*args, **kwargs)
        return obj
    except Exception as e:
        logger.warning(f"{label} 初始化失败（将禁用）: {e}")
        return None


class LangGraphController:
    """LangGraph 控制器 - 使用 LangGraph 管理处理流程"""
    
    def __init__(self, config: Dict):
        """
        初始化控制器
        
        Args:
            config: 配置字典
        """
        self.config = config
        agentic = config.get('agentic', {})
        dry_run = config.get('processing', {}).get('dry_run', False)

        # AgentMemory
        memory_cfg = agentic.get('memory', {})
        if memory_cfg.get('enabled', False):
            self.memory = AgentMemory(memory_cfg)
        else:
            self.memory = None

        # RAGRetriever (Milvus)
        if agentic.get('rag', {}).get('enabled', False) and not dry_run:
            from rag import RAGRetriever
            self.rag = _init_optional(RAGRetriever, config, label='RAGRetriever')
        else:
            self.rag = None

        # ToolAgent
        if agentic.get('tools', {}).get('enabled', False):
            from tools import ToolAgent
            from openai import OpenAI as _OpenAI
            try:
                _os = __import__('os')
                _base = _os.getenv('OPENAI_API_BASE', '').strip() or None
                _api_key = _os.getenv('OPENAI_API_KEY', '').strip()
                if _api_key:
                    kwargs = {'api_key': _api_key, 'timeout': 20}
                    if _base:
                        kwargs['base_url'] = _base
                    llm = _OpenAI(**kwargs)
                else:
                    llm = None
            except Exception:
                llm = None
            self.tool_agent = _init_optional(
                ToolAgent, config, llm, label='ToolAgent'
            )
        else:
            self.tool_agent = None

        # SkillRegistry
        if agentic.get('skills', {}).get('enabled', False):
            from agent.skills import SkillRegistry
            self.skill_registry = _init_optional(
                SkillRegistry, config, label='SkillRegistry'
            )
        else:
            self.skill_registry = None

        # PlannerAgent
        if agentic.get('planner', {}).get('enabled', True):
            from agent.planner import PlannerAgent
            self.planner = _init_optional(
                PlannerAgent, config, self.memory, label='PlannerAgent'
            )
        else:
            self.planner = None

        # ChatAgent（暴露为属性供 api/app.py 使用）
        if agentic.get('chat', {}).get('enabled', False):
            from agent.chat import ChatAgent
            self.chat_agent = _init_optional(
                ChatAgent, config,
                rag=self.rag, memory=self.memory, tool_agent=self.tool_agent,
                label='ChatAgent'
            )
        else:
            self.chat_agent = None

        # 初始化复用 Agent 实例（避免每个节点每次调用都重新建立 DB 连接）
        from agent.storage import StorageAgent
        from agent.extractor import ExtractorAgent
        from agent.cleaner_validator import CleanerValidatorAgent
        _shared_cfg = {**config, '_memory': self.memory, '_rag': self.rag,
                       '_tool_agent': self.tool_agent, '_skill_registry': self.skill_registry}
        self.storage_agent = None if dry_run else _init_optional(
            StorageAgent, _shared_cfg, None, label='StorageAgent'
        )
        self.extractor_agent = _init_optional(ExtractorAgent,         _shared_cfg, None, label='ExtractorAgent')
        self.cleaner_agent   = _init_optional(CleanerValidatorAgent,  _shared_cfg, None, label='CleanerAgent')

        # 受约束恢复循环：复用 Cleaner 的模型，只在显式开关开启时初始化
        self.recovery_planner = None
        self.recovery_registry = None
        self.recovery_guard = None
        self.recovery_verifier = None
        self.recovery_budget = None
        recovery_cfg = agentic.get('recovery', {})
        if recovery_cfg.get('enabled') and recovery_cfg.get('agent_loop_enabled'):
            from agent.recovery.guard import RecoveryActionGuard
            from agent.recovery.models import RecoveryBudget
            from agent.recovery.planner import ConstrainedRecoveryPlanner
            from agent.recovery.tool_registry import RecoveryToolRegistry
            from agent.recovery.verifier import EvidenceVerifier
            self.recovery_budget = RecoveryBudget(
                max_steps=recovery_cfg.get('max_steps', 3),
                max_tool_calls=recovery_cfg.get('max_tool_calls', 5),
                max_llm_calls=recovery_cfg.get('max_llm_calls', 2),
                deadline_seconds=recovery_cfg.get('deadline_seconds', 30),
            )
            self.recovery_registry = RecoveryToolRegistry(
                nvd_api_key=agentic.get('tools', {}).get('nvd_api_key', ''),
                max_result_chars=recovery_cfg.get('max_result_chars', 2000),
            )
            self.recovery_guard = RecoveryActionGuard(self.recovery_budget)
            if self.cleaner_agent:
                self.recovery_verifier = EvidenceVerifier(self.cleaner_agent.config_loader)
                self.recovery_planner = ConstrainedRecoveryPlanner(
                    self.cleaner_agent.llm, self.recovery_registry
                )

        # 注入全部对象到 config，节点通过 config.get('_xxx') 访问
        self.config = {
            **config,
            '_memory': self.memory,
            '_rag': self.rag,
            '_tool_agent': self.tool_agent,
            '_skill_registry': self.skill_registry,
            '_storage': self.storage_agent,
            '_extractor': self.extractor_agent,
            '_cleaner': self.cleaner_agent,
            '_recovery_planner': self.recovery_planner,
            '_recovery_registry': self.recovery_registry,
            '_recovery_guard': self.recovery_guard,
            '_recovery_verifier': self.recovery_verifier,
            '_recovery_budget': self.recovery_budget,
        }

        self.graph = build_vuln_processing_graph(self.config)
        self._file_strategies: dict = {}

        self.stats = {
            'total': 0, 'success': 0, 'failed': 0,
            'low_quality': 0, 'skipped': 0,
            'start_time': None, 'end_time': None,
        }

        active = [n for n, o in [
            ('Memory', self.memory), ('RAG', self.rag),
            ('ToolAgent', self.tool_agent), ('SkillRegistry', self.skill_registry),
            ('Planner', self.planner), ('ChatAgent', self.chat_agent),
            ('RecoveryAgent', self.recovery_planner),
        ] if o]
        logger.info(f"LangGraphController initialized. 活跃模块: {active or ['基础']}")
    
    async def process_file(self, file_path: str) -> Dict[str, Any]:
        """
        处理单个文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            处理结果
        """
        task_id = str(uuid.uuid4())
        strategy = self._file_strategies.get(file_path, '')
        initial_state = create_initial_state(task_id, file_path)
        if strategy:
            initial_state = {**initial_state, 'extraction_strategy': strategy}
        
        file_name = Path(file_path).name
        logger.info(f"🚀 开始处理: {file_name}")
        
        try:
            final_state = await self.graph.ainvoke(initial_state)
            self.update_stats(final_state)
            
            # 简化完成日志
            status = final_state.get('final_status')
            if status == 'success':
                logger.info(f"🎉 处理完成: {file_name} - 成功")
            elif status == 'low_quality':
                logger.warning(f"⚠️ 处理完成: {file_name} - 低质量")
            elif status == 'skipped':
                logger.info(f"⏭️ 处理完成: {file_name} - 跳过")
            else:
                logger.error(f"💥 处理完成: {file_name} - 失败")
            
            return final_state
        
        except Exception as e:
            logger.error(f"💥 处理异常: {file_name} - {str(e)}")
            self.stats['failed'] += 1
            return {
                **initial_state,
                'final_status': 'failed',
                'errors': [f"Graph execution error: {str(e)}"]
            }
    
    async def process_directory(self, directory: str, pattern: str = '*.html',
                               max_workers: int = 4, timeout: int = 3600) -> Dict[str, Any]:
        """
        批量处理目录 (并发)
        
        Args:
            directory: 目录路径
            pattern: 文件匹配模式
            max_workers: 最大并发数
            timeout: 超时时间（秒）
        
        Returns:
            统计信息字典
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return self.get_stats()
        
        files = []
        if pattern == '*.html':
            files = list(dir_path.rglob('*.html')) + list(dir_path.rglob('*.htm'))
        elif pattern == '*.json':
            files = list(dir_path.rglob('*.json'))
        elif pattern == '*':
            files = list(dir_path.rglob('*.html')) + \
                   list(dir_path.rglob('*.htm')) + \
                   list(dir_path.rglob('*.json'))
        else:
            files = list(dir_path.rglob(pattern))
        
        if not files:
            logger.warning(f"No files found matching pattern '{pattern}' in {directory}")
            return self.get_stats()
        
        logger.info(f"Found {len(files)} files to process")
        
        # 批量预过滤：按来源跳过数据库中已存在的漏洞
        try:
            storage = self.storage_agent
            extractor = self.extractor_agent
            if not storage or not extractor or not getattr(storage, 'db', None):
                raise RuntimeError('StorageAgent 或 ExtractorAgent 未初始化')
 
            existing_ids_by_source = {}
            for src, model_class in storage.db.models.items():
                src_config = storage.db.config_loader.get_source_config(src)
                id_field = src_config.get('id_field')
                if not id_field:
                    continue
                session = storage.db.Session()
                try:
                    rows = session.query(getattr(model_class, id_field)).all()
                    existing_ids_by_source[src.lower()] = {r[0] for r in rows if r[0]}
                finally:
                    session.close()

            before_count = len(files)
            filtered_files = []
            for f in files:
                try:
                    source = extractor.identify_source(str(f), '')
                    source_ids = existing_ids_by_source.get(source.lower(), set())
                    if normalize_jvn_id(source, f.stem) in source_ids:
                        continue
                except Exception:
                    pass
                filtered_files.append(f)

            skipped_count = before_count - len(filtered_files)
            files = filtered_files

            if skipped_count > 0:
                logger.info(f"⏭️ 预过滤跳过已存在: {skipped_count} 个，剩余: {len(files)} 个")
            self.stats['skipped'] += skipped_count
        except Exception as e:
            logger.warning(f"预过滤查询失败，将处理全部文件: {e}")

        # PlannerAgent：分析文件、分配策略、生成优先级排序
        if self.planner and files:
            plan = self.planner.plan(files)
            file_strategies = plan.get('file_strategies', {})
            self._file_strategies = {
                str(k): v for k, v in file_strategies.items()
            }
            priority_strs = plan.get('priority_order', [])
            files_by_path = {str(f): f for f in files}
            files = [
                files_by_path[p] for p in priority_strs if p in files_by_path
            ] + [
                f for f in files if str(f) not in set(priority_strs)
            ]
            logger.info(
                f"📋 Planner: 估算 LLM 调用 {plan.get('estimated_llm_calls', 0)} 次"
            )
        else:
            self._file_strategies = {}

        self.stats['start_time'] = time.time()
        self.stats['total'] = len(files) + self.stats.get('skipped', 0)

        semaphore = asyncio.Semaphore(max_workers)

        async def process_with_limit(file_path: Path):
            async with semaphore:
                return await self.process_file(str(file_path))

        logger.info(f"Processing {len(files)} files with {max_workers} workers...")
        results = await asyncio.gather(
            *[process_with_limit(f) for f in files],
            return_exceptions=True
        )
        
        self.stats['end_time'] = time.time()
        logger.info(f"All files processed: {len(results)}")

        if self.memory:
            self.memory.end_batch()

        return self.get_stats()
    
    def update_stats(self, result: Dict):
        """更新统计信息"""
        status = result.get('final_status')
        if status == 'success':
            self.stats['success'] += 1
        elif status == 'low_quality':
            self.stats['low_quality'] += 1
        elif status == 'skipped':
            self.stats['skipped'] += 1
        else:
            self.stats['failed'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = self.stats.copy()
        
        if stats['total'] > 0:
            stats['success_rate'] = stats['success'] / stats['total']
        else:
            stats['success_rate'] = 0.0
        
        if stats['start_time'] and stats['end_time']:
            elapsed = stats['end_time'] - stats['start_time']
            stats['elapsed_seconds'] = elapsed
            stats['files_per_second'] = stats['total'] / elapsed if elapsed > 0 else 0
        
        return stats
    
    def print_stats(self):
        """打印统计信息"""
        stats = self.get_stats()
        
        print("\n" + "="*60)
        print("处理统计")
        print("="*60)
        print(f"总文件数:     {stats['total']}")
        print(f"成功:         {stats['success']}")
        print(f"失败:         {stats['failed']}")
        print(f"低质量:       {stats['low_quality']}")
        print(f"跳过:         {stats['skipped']}")
        print(f"成功率:       {stats['success_rate']:.2%}")
        
        if stats.get('elapsed_seconds'):
            print(f"耗时:         {stats['elapsed_seconds']:.1f} 秒")
            print(f"处理速度:     {stats['files_per_second']:.2f} 文件/秒")
        
        print("="*60 + "\n")
