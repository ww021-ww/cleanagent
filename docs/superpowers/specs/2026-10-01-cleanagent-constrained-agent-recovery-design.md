# CleanAgent 受约束异常恢复 Agent 设计

日期：2026-10-01  
状态：待用户最终评审  
目标版本：CleanAgent 2.0

## 1. 背景与目标

CleanAgent 当前离线数据链路使用 LangGraph 编排漏洞文件读取、来源识别、字段提取、清洗验证、质量评分和 MySQL/Milvus 存储。主流程稳定，但 Agent 能力主要表现为固定规则选策略、固定 `rule → hybrid → llm_full` 升级以及有限的字段补全。

本次重构同时追求两个目标：

1. 保留确定性数据治理链路的可靠性、低成本和可解释性。
2. 对规则无法处理的少量异常样本，引入具备诊断、规划、工具选择、观察反馈、证据验证和人工介入能力的受约束 Agent Loop。

成功标准：

- 正常样本不增加不必要的 LLM 调用。
- Agent 不能直接修改权威字段或写数据库。
- 所有字段修复都有来源和证据，可审计、可拒绝。
- 异常旁路有步骤、工具、Token 和时间预算，不无限循环。
- MySQL 是主事实库，Milvus 是最终一致的派生索引。
- 能用固定失败样本集对比重构前后恢复率、准确率、成本和延迟。

## 2. 非目标

- 不把每一个节点改成 LLM Agent。
- 不构建多个相互对话的角色型 Agent 群。
- 不允许在线 Agent 自动修改解析器源码、Prompt 或生产策略。
- 不使用相似漏洞内容直接填充当前漏洞事实。
- 不追求 MySQL 与 Milvus 的跨库强事务。

## 3. 总体架构

```text
确定性主链路

Ingest
  → Rule Extract
  → Clean / Validate
  → Quality Gate
      ├─ PASS → Transactional Store(MySQL + Outbox)
      │              → Vector Worker → Milvus
      └─ ANOMALY → Recovery Agent Subgraph

Recovery Agent Subgraph

Diagnose Failure
  → Plan Recovery
  → Guard Action
  → Execute Tool
  → Verify Evidence
  → Decide Next
      ├─ PASS   → Transactional Store
      ├─ REPLAN → Plan Recovery
      ├─ REVIEW → Human Review
      └─ ABORT  → Quarantine / LowQuality
  → Record Experience
```

主链路和异常旁路共享同一份候选数据与验证规则。异常旁路只能生成待验证 Patch；只有验证器可以把 Patch 合并进 Candidate，只有 Store 节点可以提交数据库。

## 4. 模块与接口

### 4.1 Failure Diagnosis 模块

接口：

```python
diagnose(candidate, validation, trace) -> FailureProfile
```

职责：使用确定性代码把失败整理为结构化画像，不调用 LLM。

```python
class FailureProfile(BaseModel):
    failure_type: Literal[
        "missing_required_fields",
        "schema_mismatch",
        "source_unknown",
        "field_conflict",
        "evidence_missing",
        "external_dependency_failure",
    ]
    missing_fields: list[str] = []
    conflicting_fields: list[str] = []
    evidence_gaps: list[str] = []
    attempted_actions: list[str] = []
    quality_score: float
    source: str | None
```

### 4.2 Constrained Planner 模块

接口：

```python
plan(context: PlannerContext) -> RecoveryDecision
```

Planner 接收 FailureProfile、字段策略、工具 Schema、已有观察和剩余预算。它只输出结构化决策，不输出自由执行代码。

```python
class RecoveryDecision(BaseModel):
    decision: Literal["CALL_TOOL", "STOP", "REVIEW", "ABORT"]
    reason_code: str
    target_fields: list[str]
    tool_name: str | None = None
    tool_args: dict = {}
    expected_evidence: str = ""
```

不保存或展示模型隐藏思维链。Trace 只记录结构化 `reason_code`、目标、动作和预期证据。

### 4.3 Action Guard 模块

接口：

```python
authorize(decision, state, tool_registry) -> AuthorizedAction | Rejection
```

检查项：

- 工具是否在白名单中。
- 参数是否通过 Pydantic Schema。
- 目标字段是否允许该工具处理。
- 工具调用、步骤、Token 和 deadline 是否仍有预算。
- 当前漏洞是否具有调用该工具所需的真实 ID。
- 外部调用是否符合来源与域名限制。

### 4.4 Tool Registry 模块

接口保持较小：

```python
registry.describe_allowed(context) -> list[ToolSpec]
registry.invoke(name, args, execution_context) -> ToolResult
```

工具内部可以使用同步 SDK，但执行器负责 `asyncio.to_thread`、超时、重试和 Trace。

### 4.5 Evidence Verifier 模块

接口：

```python
verify(candidate, tool_result, field_policy) -> VerificationResult
```

代码校验优先，包括 Schema、ID、日期、CVSS、URL、来源等级、原文证据定位和字段冲突。语义等价无法由规则确定时，可以调用独立的受约束语义验证模型，但其输出仍需映射为 `supported/unsupported/uncertain`，无权直接写库。

### 4.6 Transactional Store 模块

接口：

```python
store_verified(candidate, patches, session) -> StoreResult
```

主表与子表使用同一 MySQL Session 和本地事务。事务内同时写入向量 Outbox 事件。Milvus 由后台 Worker 异步更新。

## 5. Agent State

```python
class RecoveryAgentState(TypedDict):
    # 输入与候选数据
    task_id: str
    file_path: str
    source: str | None
    raw_content: str
    content_hash: str
    candidate: dict
    subtable_rows: list[dict]

    # 校验与异常
    validation: dict
    quality_score: float
    failure_profile: FailureProfile | None

    # Agent Loop
    recovery_decision: RecoveryDecision | None
    pending_action: AuthorizedAction | None
    observations: list[ToolResult]
    proposed_patches: list[FieldPatch]
    verification: VerificationResult | None
    final_decision: Literal["PASS", "REPLAN", "REVIEW", "ABORT"] | None

    # 预算与审计
    step_count: int
    tool_call_count: int
    llm_call_count: int
    token_usage: int
    deadline_at: float
    trace_events: list[TraceEvent]
```

数据库连接、LLM Client、Milvus Client、Tool Registry 和配置不进入 State，通过节点依赖注入。

## 6. 工具白名单

### 6.1 第一阶段必须实现

| 工具 | 输入 | 输出 | 允许用途 |
|---|---|---|---|
| `search_raw_text` | field_hint、关键词 | 原文证据片段及位置 | 从当前文件重新定位证据 |
| `parse_json_path` | JSON path | 值和原始路径 | 重新读取嵌套 JSON |
| `extract_html_region` | selector_hint | 文本和 DOM 路径 | 重新解析目标区域 |
| `normalize_field` | 字段名、候选值 | 标准值和校验结果 | ID、日期、CVSS、版本格式化 |
| `lookup_mysql_by_id` | source、vuln_id | 现有记录 | 去重与冲突检测，只读 |
| `nvd_lookup` | CVE ID | NVD 结构化结果与 URL | 官方来源补查 |

### 6.2 第二阶段增加

- `vendor_advisory_fetch`：厂商公告取证。
- `retrieve_similar_vulns`：相似案例，仅供解析参考。
- `tavily_search`：线索发现，不能直接成为最高等级事实来源。
- `translate_evidence`：翻译证据，必须保留原文。
- `request_human_review`：创建人工审核项。
- `quarantine_sample`：隔离不可恢复样本。

## 7. 字段安全策略

### A 类：确定性只读字段

来源 ID、CVE/CNVD/JVN 编号、发布时间、更新时间、CVSS 数值、CWE 和原始 URL。只能来自规则解析或官方结构化接口，LLM 不得产生或修改。

### B 类：证据约束字段

标题、描述、影响产品、版本范围和修复建议。Agent 只能提出 `FieldPatch`：

```python
class FieldPatch(BaseModel):
    field: str
    old_value: Any
    proposed_value: Any
    method: str
    source_name: str
    source_url: str | None
    evidence: str
    evidence_location: str | None
    confidence: float
    verification_status: Literal["pending", "accepted", "rejected", "review"]
```

Verifier 通过后才能合并。没有证据时保留 null，不为提高完整率猜值。

### C 类：生成性派生字段

摘要、标签和面向用户的解释。单独标记 `generated`，不覆盖 A/B 类原始事实。

### 冲突规则

- 当前原文证据优先于相似案例。
- 官方结构化库和厂商公告优先于普通搜索结果。
- 两个权威来源冲突时进入 Human Review，Planner 不得自行选择。
- 每个最终字段保留来源、证据、提取方法和验证状态。

## 8. 工具调用执行机制

模型通过 `bind_tools` 接收工具的 name、description 和 args Schema，并返回 `tool_calls`。Python 执行器完成实际调用：

```text
Planner Model
  → tool_call(name, args)
  → Action Guard
  → Tool Registry.invoke
  → ToolResult
  → Evidence Verifier
  → Decision Router
```

执行约束：

- 单轮只执行一个动作，简化观察与责任归因。
- 默认最多 3 个 Agent step、5 次工具调用、2 次 LLM 调用。
- 外部工具具备连接/读取超时；临时网络错误最多有限重试。
- 非临时参数错误、权限错误和 Schema 错误不自动重试。
- 工具返回统一 `ToolResult`，包括 success、data、evidence、source、latency 和 error。

## 9. LangGraph 节点与路由

新增节点：

- `diagnose_failure_node`
- `plan_recovery_node`
- `guard_action_node`
- `execute_action_node`
- `verify_evidence_node`
- `decide_next_node`
- `human_review_node`
- `record_experience_node`

条件路由：

```text
quality_gate:
  pass    → transactional_store
  anomaly → diagnose_failure

guard_action:
  allowed → execute_action
  denied  → decide_next

decide_next:
  PASS    → transactional_store
  REPLAN  → plan_recovery
  REVIEW  → human_review
  ABORT   → low_quality
```

现有 `reflect_node` 在兼容期保留为 fallback，待新子图稳定后删除。

## 10. 数据一致性

### MySQL 主表与子表

同一漏洞的主表、子表和 Outbox 事件在同一个 Session/事务中提交。子表增加业务唯一键，避免重复处理产生重复行。

### MySQL 与 Milvus

使用 Transactional Outbox 实现最终一致性：

1. MySQL 事务提交漏洞数据和 `vector_outbox` 事件。
2. Vector Worker 使用稳定主键 `source:vuln_id` Upsert Milvus。
3. 失败事件指数退避，超限进入 dead 并告警。
4. 版本号或内容哈希阻止旧事件覆盖新向量。
5. 定时 Reconcile Job 对比 MySQL 与 Milvus 版本并补偿。

## 11. 经验记忆与策略更新

在线只记录结构化经验：

```text
FailureProfile
→ selected_action
→ tool_result
→ verification_result
→ final_quality
→ cost / latency
```

不允许在线模型直接修改 Prompt、工具说明、规则或代码。离线任务聚合相同来源和失败类型的动作效果，在固定回归集上比较恢复率、字段准确率、幻觉率、成本和延迟；只有评测通过的策略才人工批准并灰度发布。

## 12. Human-in-the-Loop

以下情况进入人工审核：

- 两个权威来源字段冲突。
- 高风险 A 类字段无法通过确定性来源确认。
- B 类字段只有低可信搜索证据。
- Agent 预算耗尽但候选数据接近通过阈值。
- 来源结构发生批量漂移。

审核界面至少展示原文、候选字段、证据位置、来源 URL、旧值、新值、Planner 动作和验证失败原因。人工决定接受、拒绝或隔离。

## 13. 可观测性与安全

每个 TraceEvent 记录：task_id、node、reason_code、tool、参数摘要、来源、耗时、Token、错误、Prompt/模型/工具版本和最终决策。敏感字段和 API Key 不进入 Trace。

安全要求：

- 工具白名单和参数 Schema 在代码层执行。
- 数据库工具使用只读账号；Agent 没有任意 SQL 工具。
- 用户输入、网页正文和检索文本均视为不可信数据。
- 外部网页内容不能改变工具权限或系统指令。
- Tool 输出进入 State 前执行大小限制与内容清洗。

## 14. 评测与测试

### 固定数据集

建立三组互不重叠的数据：

- 正常集：验证主链路无性能和准确率回退。
- 异常集：缺字段、结构变化、字段冲突、未知来源和外部服务失败。
- 对抗集：Prompt Injection、伪造 CVE、恶意 HTML、超长正文和冲突来源。

### 指标

| 维度 | 指标 |
|---|---|
| 抽取质量 | 字段完整率、字段准确率、证据匹配率 |
| Agent 恢复 | 异常恢复率、误接受率、HIL 转交率、平均 step |
| 安全 | A 类字段非法修改次数、无证据写入次数、注入成功次数 |
| 成本性能 | LLM 调用数、Token、平均/P95 延迟、工具失败率 |
| 一致性 | Outbox 积压、索引延迟、版本不一致率、补偿成功率 |

核心验收条件：A 类字段非法修改为 0；无证据 B 类字段自动入库为 0；正常集准确率不得低于重构前；异常集恢复率相对固定升级策略明显提升，并报告对应成本。

### 测试层次

- 模块测试：FailureProfile、Guard、Verifier、字段策略。
- 合约测试：每个 Tool 的参数与 ToolResult Schema。
- Graph 路由测试：PASS/REPLAN/REVIEW/ABORT 和预算终止。
- 故障注入：LLM 超时、工具 429、MySQL/Milvus 部分失败。
- 回归测试：固定样本集端到端输出对比。

## 15. 分阶段交付

### Phase 1：证据与可观测基础

- 引入 FailureProfile、FieldPatch、Evidence、TraceEvent。
- 扩展 Validate，输出字段级错误和证据缺口。
- 保留当前固定策略升级，不引入 LLM Planner。

### Phase 2：受约束 Agent Loop

- 实现 Planner、Guard、Registry 和四至六个核心工具。
- 实现预算、超时、有限循环和 Verifier。
- 新子图以 feature flag 开启，与旧 Reflect 并行 A/B。

### Phase 3：一致性与 HIL

- 主表/子表事务统一。
- 实现 Vector Outbox、Worker 和对账任务。
- 增加人工审核接口和 Trace 展示。

### Phase 4：经验学习与评测

- 建立异常 Benchmark。
- 聚合动作效果并形成离线策略建议。
- 人工审批、灰度发布和回归验证。

## 16. 预计代码改造范围

新增深模块：

- `backened/agent/recovery/models.py`
- `backened/agent/recovery/diagnosis.py`
- `backened/agent/recovery/planner.py`
- `backened/agent/recovery/guard.py`
- `backened/agent/recovery/verifier.py`
- `backened/agent/recovery/tool_registry.py`
- `backened/graph/recovery_nodes.py`
- `backened/database/vector_outbox.py`
- `backened/workers/vector_indexer.py`

修改现有文件：

- `graph/state.py`：增加恢复状态或组合 `RecoveryAgentState`。
- `graph/builder.py`：接入 Recovery 子图和 feature flag。
- `graph/nodes.py`：Quality Gate 输出结构化异常；Store 只接受已验证 Patch。
- `database/manager.py`：支持外部 Session、主子表单事务和原生 Upsert。
- `tools/registry.py`：迁移为带 Schema、权限和统一 ToolResult 的 Registry。
- `config/agent_config.yaml`：增加预算、工具策略、HIL 和 Outbox 配置。

保持现有 Extractor、Cleaner、ChatAgent 接口尽量不变，避免无关重写。

## 17. 主要风险与缓解

| 风险 | 缓解措施 |
|---|---|
| Agent 增加延迟和成本 | 只处理异常；严格预算；规则优先 |
| 模型生成非法工具参数 | Pydantic Schema + Guard |
| LLM 填错精确字段 | 字段分级 + Patch + Evidence Verifier |
| 相似案例污染当前事实 | Similarity 仅作为解析参考，不作为证据 |
| 循环不终止 | 最大 step/tool/token/deadline 四重限制 |
| 新策略回归 | feature flag、A/B、固定回归集、灰度发布 |
| 双写不一致 | Transactional Outbox + 幂等 Upsert + 对账 |

## 18. 最终决策

采用“确定性主链路 + 受约束异常恢复 Agent”方案。第一轮实施从 Phase 1 开始，不先引入多 Agent、不让模型直接写库、不在线自修改策略。Phase 1 的数据模型和 Trace 是后续 Planner、HIL、评测和经验学习的共同基础，完成后再进入 Phase 2。
