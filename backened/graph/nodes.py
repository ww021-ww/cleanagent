"""
LangGraph Node Functions - 节点函数
定义图中的各个处理节点
"""
import asyncio
import logging
import time
from pathlib import Path
from typing import Dict

from graph.state import VulnProcessingState
from graph.recovery_nodes import append_trace_event
from graph.utils import normalize_jvn_id

logger = logging.getLogger(__name__)


async def extract_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """
    提取节点（async）

    支持三级策略：rule → hybrid → llm_full
    策略读取项: state.extraction_strategy > memory推荐 > 默认 rule
    使用 config['_extractor'] / config['_storage'] 复用已初始化的 Agent 实例。
    """
    llm_call_count = state.get('llm_call_count', 0)
    try:
        from agent.extractor import ExtractorAgent

        file_name = Path(state['file_path']).name
        extractor = config.get('_extractor') or ExtractorAgent(config, None)

        # 异步文件读取（避免阻塞事件循环）
        content = await asyncio.to_thread(
            Path(state['file_path']).read_text, encoding='utf-8'
        )

        source = extractor.identify_source(state['file_path'], content)
        source_lower = source.lower()

        dry_run = config.get('processing', {}).get('dry_run', False)

        # 单文件去重检查（Dry Run 必须绕过数据库）
        compare_id = normalize_jvn_id(source, Path(state['file_path']).stem)
        memory = config.get('_memory')
        if not dry_run and memory and memory.is_seen(compare_id, source):
            logger.info(f"⏭️ 跳过(Memory已见): {file_name}")
            return {
                **state,
                'source': source,
                'extracted_data': {},
                'extracted_subtable_data': None,
                'extraction_confidence': 0.0,
                'final_status': 'skipped',
            }
        if not dry_run:
            try:
                from agent.storage import StorageAgent
                storage_check = config.get('_storage') or StorageAgent(config, None)
                model_class = storage_check.db.models.get(source_lower)
                if model_class:
                    src_cfg = storage_check.db.config_loader.get_source_config(source)
                    id_field = src_cfg.get('id_field')
                    if id_field:
                        def _db_exists():
                            session = storage_check.db.Session()
                            try:
                                return session.query(model_class).filter(
                                    getattr(model_class, id_field) == compare_id
                                ).first() is not None
                            finally:
                                session.close()
                        if await asyncio.to_thread(_db_exists):
                            logger.info(f"⏭️ 跳过(已存在): {file_name}")
                            return {
                                **state,
                                'source': source,
                                'extracted_data': {},
                                'extracted_subtable_data': None,
                                'extraction_confidence': 0.0,
                                'final_status': 'skipped',
                            }
            except Exception as e:
                logger.debug(f"去重检查失败，继续处理: {e}")

        if source_lower not in extractor.extractors:
            raise ValueError(f"No extractor found for source: {source}")

        source_extractor = extractor.extractors[source_lower]

        # 策略优先级：state 设置 > memory 推荐 > 默认 rule
        strategy = state.get('extraction_strategy', '')
        if not strategy:
            if memory:
                strategy = memory.get_recommended_strategy(source) or 'rule'
            else:
                strategy = 'rule'

        # RAG：仅 llm_full 策略时检索历史相似漏洞作为 few-shot 参考
        # hybrid 的 LLM 补全职责由 clean_validate_node.recover_fields 负责
        rag_context = ''
        rag = config.get('_rag')
        if rag and strategy == 'llm_full':
            similar = await asyncio.to_thread(
                rag.retrieve_similar, content[:2000], source
            )
            rag_context = rag.build_rag_context(similar)
            if rag_context:
                logger.info(f"🔍 RAG: 检索到 {len(similar)} 个相似漏洞作为参考")

        if strategy == 'llm_full':
            # 全量 LLM 重提取（反思机制最终兜底）
            logger.info(f"📄 LLM全量提取: {file_name} (策略=llm_full)")
            llm_call_count += 1
            extracted_list = await asyncio.to_thread(
                source_extractor.extract_by_strategy,
                content, 'llm_full', state['file_path'], rag_context
            )
        else:
            # rule / hybrid：规则提取，LLM 字段补全由 clean_validate 节点负责
            logger.info(f"📄 规则提取: {file_name} (策略={strategy})")
            extracted_list = await asyncio.to_thread(
                source_extractor.extract, content, state['file_path']
            )

        if not extracted_list:
            logger.warning(f"❌ 提取失败: {file_name} - 无数据")
            return {
                **state,
                'source': source,
                'raw_content': content,
                'extracted_data': {},
                'extracted_subtable_data': None,
                'extraction_confidence': 0.0,
                'errors': state.get('errors', []) + ['No data extracted'],
                'llm_call_count': llm_call_count,
                'final_status': 'failed'
            }

        extracted_data = extracted_list[0]
        confidence = source_extractor.calculate_confidence(extracted_data)

        # 保存完整的多漏洞列表（用于CISA等多漏洞文件批量存储）
        all_extracted_data = extracted_list if len(extracted_list) > 1 else None

        # 提取子表数据（如果支持）
        extracted_subtable_data = None
        subtable_count = 0
        if extractor.config_loader.has_subtable(source):
            try:
                if content.strip().startswith('{'):
                    import json
                    from agent.json_extractor import JSONExtractor
                    json_data = json.loads(content)
                    json_extractor = JSONExtractor(source, extractor.config_loader.get_source_config(source))
                    _, extracted_subtable_data = json_extractor.extract_with_subtable(json_data)
                    if extracted_subtable_data:
                        subtable_count = len(extracted_subtable_data)
            except Exception as e:
                logger.debug(f"子表提取失败: {e}")

        subtable_info = f" + {subtable_count}条评分" if subtable_count > 0 else ""
        logger.info(f"✅ 提取成功: {file_name} ({source}, 置信度:{confidence:.2f}{subtable_info})")

        return {
            **state,
            'source': source,
            'raw_content': content,
            'extracted_data': extracted_data,
            'all_extracted_data': all_extracted_data,
            'extracted_subtable_data': extracted_subtable_data,
            'extraction_confidence': confidence,
            'extraction_strategy': strategy,
            'is_multi_vuln': len(extracted_list) > 1,
            'vuln_count': len(extracted_list),
            'errors': [],
            'llm_call_count': llm_call_count,
        }

    except Exception as e:
        file_name = Path(state['file_path']).name
        logger.error(f"❌ 提取失败: {file_name} - {str(e)}")
        return {
            **state,
            'errors': state.get('errors', []) + [f"Extraction error: {str(e)}"],
            'retry_count': state.get('retry_count', 0) + 1,
            'llm_call_count': llm_call_count,
            'final_status': 'failed',
        }


async def clean_validate_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """
    清洗验证节点（async）

    增强：当有必填字段缺失且未尝试过修复时，调用 LLM recover_fields()
    使用 config['_cleaner'] 复用已初始化的 CleanerValidatorAgent 实例。
    """
    llm_call_count = state.get('llm_call_count', 0)
    try:
        from agent.cleaner_validator import CleanerValidatorAgent

        if not state.get('extracted_data'):
            logger.warning("🧹 清洗跳过: 无提取数据")
            return {**state, 'quality_score': 0.0, 'final_status': 'failed'}

        file_name = Path(state['file_path']).name
        logger.info(f"🧹 清洗验证: {file_name}")

        cleaner = config.get('_cleaner') or CleanerValidatorAgent(config, None)
        cleaned_data = cleaner.cleaner.clean(state['extracted_data'])
        validation_result = cleaner.validate(cleaned_data, state['source'])

        # LLM 字段修复：仅 hybrid 策略触发（rule=纯规则，llm_full=整体重提取）
        recovered_fields = []
        recovery_attempted = state.get('recovery_attempted', False)
        recovery_cfg = config.get('agentic', {}).get('field_recovery', {})
        agent_loop_enabled = config.get('agentic', {}).get('recovery', {}).get(
            'agent_loop_enabled', False
        )
        current_strategy = state.get('extraction_strategy', 'rule')
        if (
            recovery_cfg.get('enabled', False)
            and not agent_loop_enabled
            and current_strategy == 'hybrid'
            and validation_result.get('errors')
            and state.get('raw_content')
            and not recovery_attempted
        ):
            llm_call_count += 1
            cleaned_data, recovered_fields = await asyncio.to_thread(
                cleaner.recover_fields,
                cleaned_data, validation_result, state['source'], state['raw_content']
            )
            recovery_attempted = True  # 只在实际执行修复后才置 True
            if recovered_fields:
                validation_result = cleaner.validate(cleaned_data, state['source'])

                memory = config.get('_memory')
                if memory and validation_result.get('errors'):
                    still_missing = [
                        e.replace('Missing required field: ', '')
                        for e in validation_result['errors']
                        if e.startswith('Missing required field:')
                    ]
                    if still_missing:
                        memory.record_field_failures(state['source'], still_missing)

        # ToolAgent：LLM 修复后仍有缺失字段，尝试外部工具补全
        tool_agent = config.get('_tool_agent')
        if tool_agent and not agent_loop_enabled and validation_result.get('errors'):
            still_missing = [
                e.replace('Missing required field: ', '')
                for e in validation_result['errors']
                if e.startswith('Missing required field:')
            ]
            if still_missing:
                filled = await asyncio.to_thread(
                    tool_agent.auto_fill,
                    cleaned_data, still_missing,
                    state.get('source', ''), state.get('raw_content', '')
                )
                if filled:
                    for k, v in filled.items():
                        if not k.startswith('_') and v and not cleaned_data.get(k):
                            cleaned_data[k] = v
                    validation_result = cleaner.validate(cleaned_data, state['source'])

        quality_score = cleaner.calculate_quality_score(
            cleaned_data, validation_result, state['extraction_confidence']
        )

        # 清洗子表数据
        cleaned_subtable_data = None
        subtable_count = 0
        if state.get('extracted_subtable_data'):
            cleaned_subtable_data = [
                cleaner.cleaner.clean(r) for r in state['extracted_subtable_data']
            ]
            subtable_count = len(cleaned_subtable_data)

        subtable_info = f" + {subtable_count}条评分" if subtable_count > 0 else ""
        logger.info(f"✅ 清洗完成: {file_name} (质量分:{quality_score:.2f}{subtable_info})")

        return {
            **state,
            'cleaned_data': cleaned_data,
            'cleaned_subtable_data': cleaned_subtable_data,
            'validation_result': validation_result,
            'quality_score': quality_score,
            'warnings': validation_result.get('warnings', []),
            'recovery_attempted': recovery_attempted,
            'recovered_fields': recovered_fields,
            'llm_call_count': llm_call_count,
        }

    except Exception as e:
        file_name = Path(state['file_path']).name
        logger.error(f"❌ 清洗失败: {file_name} - {str(e)}")
        return {
            **state,
            'errors': state.get('errors', []) + [f"Cleaning error: {str(e)}"],
            'llm_call_count': llm_call_count,
            'final_status': 'failed',
        }


async def store_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """
    存储节点（async）

    增强：upsert 前可选调用 smart_merge() 保护已有数据；存储成功后将 ID 写入记忆
    使用 config['_storage'] 复用已初始化的 StorageAgent 实例，src_config 只查一次。
    """
    try:
        from agent.storage import StorageAgent

        file_name = Path(state['file_path']).name
        file_ext = Path(state['file_path']).suffix.lower()

        if not state.get('cleaned_data'):
            logger.warning(f"💾 存储跳过: {file_name} - 无清洗数据")
            return {
                **state,
                'stored': False, 'storage_status': 'skipped',
                'final_status': 'failed',
                'errors': state.get('errors', []) + ['No cleaned data to store'],
            }

        if config.get('processing', {}).get('dry_run', False):
            return {
                **state,
                'stored': False,
                'storage_status': 'dry_run',
                'final_status': 'success',
                'end_time': time.time(),
                'trace_events': append_trace_event(
                    state, 'store', 'dry_run', decision='PASS'
                ),
            }

        storage = config.get('_storage') or StorageAgent(config, None)
        source = state['source']

        # 一次性查询 src_config / id_field，后续复用
        src_config = storage.db.config_loader.get_source_config(source)
        id_field = src_config.get('id_field')

        # HTML 跳过检查（JSON 已处理过的漏洞不再重复入库）
        skip_html_enabled = config.get('agents', {}).get('storage', {}).get('skip_html_if_json_processed', False)
        if file_ext == '.html' and skip_html_enabled and id_field:
            vuln_id = state['cleaned_data'].get(id_field)
            if vuln_id:
                model_class = storage.db.models.get(source.lower())
                if model_class:
                    def _html_skip_check():
                        session = storage.db.Session()
                        try:
                            return session.query(model_class).filter(
                                getattr(model_class, id_field) == vuln_id
                            ).first() is not None
                        finally:
                            session.close()
                    if await asyncio.to_thread(_html_skip_check):
                        logger.info(f"⏭️ 跳过 HTML: {file_name} (已由 JSON 处理)")
                        return {
                            **state,
                            'stored': False, 'storage_status': 'skipped_html',
                            'final_status': 'skipped',
                        }

        logger.info(f"💾 存储数据: {file_name}")

        # 智能合并：保护数据库中已有的有效字段
        final_data = state['cleaned_data']
        if config.get('agentic', {}).get('smart_merge', {}).get('enabled', False):
            final_data = await asyncio.to_thread(storage.smart_merge, final_data, source)

        subtable_records = state.get('cleaned_subtable_data') or []
        success = await asyncio.to_thread(
            storage.db.upsert_with_outbox,
            final_data,
            source,
            subtable_records,
            state.get('review_task_id'),
        )
        subtable_success = success
        subtable_count = len(subtable_records) if success else 0

        if success and subtable_success:
            # 批量存储多漏洞文件的其余漏洞（如 CISA）
            multi_success = multi_failed = 0
            all_extracted = state.get('all_extracted_data')
            if all_extracted:
                from agent.cleaner_validator import CleanerValidatorAgent
                cleaner = config.get('_cleaner') or CleanerValidatorAgent(config, None)
                for vuln_data in all_extracted[1:]:
                    cleaned = cleaner.cleaner.clean(vuln_data)
                    if await asyncio.to_thread(
                        storage.db.upsert_with_outbox, cleaned, source
                    ):
                        multi_success += 1
                    else:
                        multi_failed += 1

            subtable_info = f" + {subtable_count}条评分" if subtable_count else ""
            total_info = f" (共{1 + multi_success}条, 失败{multi_failed}条)" if all_extracted else ""
            logger.info(f"✅ 存储成功: {file_name}{subtable_info}{total_info}")

            # MySQL 事务已创建向量 Outbox；Milvus 由独立 Worker 最终一致地写入。
            memory = config.get('_memory')
            vuln_id = final_data.get(id_field) if id_field else None
            if memory:
                if vuln_id:
                    memory.mark_seen(vuln_id, source)
                memory.record_success(
                    source,
                    quality_score=state.get('quality_score', 0.0),
                    strategy=state.get('extraction_strategy', 'rule'),
                )
            return {
                **state,
                'stored': True, 'storage_status': 'success_pending_index',
                'final_status': 'success', 'end_time': time.time(),
                'trace_events': append_trace_event(
                    state, 'store', 'storage_success', decision='PASS'
                ),
            }

        logger.error(f"❌ 存储失败: {file_name}")
        return {
            **state,
            'stored': False, 'storage_status': 'failed', 'final_status': 'failed',
            'errors': state.get('errors', []) + ['Storage failed'],
        }

    except Exception as e:
        file_name = Path(state['file_path']).name
        logger.error(f"❌ 存储异常: {file_name} - {str(e)}")
        return {
            **state,
            'stored': False, 'storage_status': 'failed', 'final_status': 'failed',
            'errors': state.get('errors', []) + [f"Storage error: {str(e)}"],
        }


def mark_low_quality_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """低质量标记节点 — 记录失败至记忆，供后续批次策略决策使用"""
    file_name = Path(state['file_path']).name
    logger.warning(f"⚠️ 低质量: {file_name} (质量分:{state['quality_score']:.2f})")

    memory = config.get('_memory')
    if memory and state.get('source'):
        memory.record_failure(
            state['source'],
            strategy=state.get('extraction_strategy', 'rule'),
        )

    decision = state.get('final_decision') or 'ABORT'
    reason = 'human_review_required' if decision == 'REVIEW' else 'recovery_exhausted'
    return {
        **state,
        'final_status': 'low_quality',
        'end_time': time.time(),
        'trace_events': append_trace_event(
            state, 'low_quality', reason, decision=decision
        ),
    }


def reflect_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """
    反思节点 — 分析失败原因，升级提取策略，清空中间状态准备重试

    策略升级顺序：rule → hybrid → llm_full
    """
    reflection_cfg = config.get('agentic', {}).get('reflection', {})
    escalation = reflection_cfg.get('strategy_escalation', ['rule', 'hybrid', 'llm_full'])

    current_strategy = state.get('extraction_strategy', '') or 'rule'
    retry_count = state.get('retry_count', 0)

    try:
        idx = escalation.index(current_strategy)
        next_strategy = escalation[min(idx + 1, len(escalation) - 1)]
    except ValueError:
        next_strategy = escalation[min(retry_count, len(escalation) - 1)]

    note = (
        f"[Reflect #{retry_count + 1}] score={state.get('quality_score', 0.0):.2f}, "
        f"策略 {current_strategy} → {next_strategy}"
    )
    file_name = Path(state['file_path']).name
    logger.info(f"🔄 反思重试: {file_name} - {note}")

    return {
        **state,
        'extraction_strategy': next_strategy,
        'retry_count': retry_count + 1,
        'reflection_notes': note,
        # 清空中间状态，让 extract → clean 重新运行
        'extracted_data': None,
        'cleaned_data': None,
        'validation_result': None,
        'quality_score': 0.0,
        'recovery_attempted': False,
        'recovered_fields': [],
        'trace_events': append_trace_event(
            state, 'reflect', 'quality_below_threshold', decision='REPLAN'
        ),
    }
