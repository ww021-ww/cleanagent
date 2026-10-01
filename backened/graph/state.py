"""
LangGraph State Definition - 状态定义
定义在节点间传递的状态对象
"""
import time
from typing import TypedDict, Optional, Dict, List


class VulnProcessingState(TypedDict):
    """漏洞处理状态 - 在所有节点间传递的状态对象"""
    
    # ========== 输入信息 ==========
    task_id: str                        # 任务ID
    file_path: str                      # 文件路径
    
    # ========== 提取阶段 ==========
    source: Optional[str]               # 漏洞库来源 (CVE/NVD/CNVD/CISA/CERT/JVN)
    raw_content: Optional[str]          # 原始文件内容
    extracted_data: Optional[Dict]      # 提取的原始数据
    all_extracted_data: Optional[List[Dict]]  # 多漏洞文件的完整列表（如CISA）
    extracted_subtable_data: Optional[List[Dict]]  # 提取的子表数据
    extraction_confidence: float        # 提取置信度 (0-1)
    is_multi_vuln: bool                # 是否多漏洞文件
    vuln_count: int                    # 漏洞数量
    
    # ========== 清洗阶段 ==========
    cleaned_data: Optional[Dict]        # 清洗后的数据
    cleaned_subtable_data: Optional[List[Dict]]  # 清洗后的子表数据
    validation_result: Optional[Dict]   # 验证结果
    quality_score: float               # 质量分 (0-1)
    
    # ========== 存储阶段 ==========
    stored: bool                       # 是否已存储
    storage_status: str                # 存储状态 (success/failed)
    
    # ========== 反思与修复 ==========
    extraction_strategy: str           # 当前提取策略 (rule / hybrid / llm_full)
    reflection_notes: str              # 反思分析笔记
    recovery_attempted: bool           # 是否已尝试 LLM 字段修复
    recovered_fields: List[str]        # 本次修复成功的字段列表
    failure_profile: Optional[Dict]     # 结构化失败诊断
    trace_events: List[Dict]            # 安全审计轨迹（不记录原始内容）

    # ========== 受约束恢复循环 ==========
    recovery_decision: Optional[Dict]
    pending_action: Optional[Dict]
    observations: List[Dict]
    proposed_patches: List[Dict]
    verification: Optional[Dict]
    final_decision: Optional[str]
    step_count: int
    tool_call_count: int
    llm_call_count: int
    deadline_at: float

    # ========== 错误处理 ==========
    errors: List[str]                  # 错误列表
    warnings: List[str]                # 警告列表
    retry_count: int                   # 重试次数
    
    # ========== 元数据 ==========
    start_time: float                  # 开始时间
    end_time: Optional[float]          # 结束时间
    final_status: str                  # 最终状态 (success/failed/low_quality)


def create_initial_state(task_id: str, file_path: str) -> VulnProcessingState:
    """
    创建初始状态
    
    Args:
        task_id: 任务ID
        file_path: 文件路径
    
    Returns:
        初始状态对象
    """
    return VulnProcessingState(
        task_id=task_id,
        file_path=file_path,
        source=None,
        raw_content=None,
        extracted_data=None,
        all_extracted_data=None,
        extracted_subtable_data=None,
        extraction_confidence=0.0,
        is_multi_vuln=False,
        vuln_count=0,
        cleaned_data=None,
        cleaned_subtable_data=None,
        validation_result=None,
        quality_score=0.0,
        stored=False,
        storage_status='',
        extraction_strategy='',
        reflection_notes='',
        recovery_attempted=False,
        recovered_fields=[],
        failure_profile=None,
        trace_events=[],
        recovery_decision=None,
        pending_action=None,
        observations=[],
        proposed_patches=[],
        verification=None,
        final_decision=None,
        step_count=0,
        tool_call_count=0,
        llm_call_count=0,
        deadline_at=0.0,
        errors=[],
        warnings=[],
        retry_count=0,
        start_time=time.time(),
        end_time=None,
        final_status='pending'
    )
