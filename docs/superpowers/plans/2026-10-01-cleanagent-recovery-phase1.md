# CleanAgent Recovery Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不改变现有 `rule → hybrid → llm_full` 存储链路的前提下，为异常样本增加字段级校验、结构化失败画像和可审计 Trace。

**Architecture:** 正常样本继续从 Clean/Validate 直接进入 Store；低质量样本先进入新的确定性 `diagnose_failure` 节点，再沿用现有 Reflect 或 LowQuality 路由。Phase 1 不调用新的 LLM Planner，不允许诊断模块修改字段或写数据库。

**Tech Stack:** Python 3.9+、Pydantic 2、LangGraph、pytest

**Spec:** `docs/superpowers/specs/2026-10-01-cleanagent-constrained-agent-recovery-design.md`

## Global Constraints

- 保持现有 Extractor、CleanerValidatorAgent、StorageAgent 和 ChatAgent 的公开调用方式不变。
- 正常样本不得新增 LLM 或外部工具调用。
- A 类权威字段不得被诊断模块修改；Phase 1 只定义 FieldPatch/Evidence Schema，不生成或应用 Patch。
- `validation_result` 必须继续保留 `errors`、`warnings`、`is_valid`，避免破坏现有调用方。
- Trace 不记录 API Key、完整原文或模型隐藏思维链。
- 不新增多 Agent、Outbox、HIL UI 或自动策略学习；它们分别留给 Phase 2–4。

## Review Focus

- `validation_result` 缺少新字段或使用旧格式时，诊断必须安全降级而不是抛异常。
- 未知来源、空候选和缺少原文时，必须生成明确 FailureProfile，不得猜测字段内容。
- 质量达标样本不得进入诊断节点，且原有 Store 路径保持不变。
- 低质量样本诊断后必须按现有重试预算进入 Reflect 或 LowQuality，不能形成新循环。
- Trace 参数必须是摘要，超长原文和疑似密钥不得写入 State。

---

### Task 1: Recovery 数据模型与确定性诊断

**Files:**
- Create: `backened/agent/recovery/__init__.py`
- Create: `backened/agent/recovery/models.py`
- Create: `backened/agent/recovery/diagnosis.py`
- Test: `backened/tests/test_recovery_diagnosis.py`

**Interfaces:**
- Consumes: 现有 `candidate: dict`、`validation: dict`、`quality_score: float`、`source: str | None`。
- Produces: `FailureProfile`、`FieldIssue`、`Evidence`、`EvidenceGap`、`FieldPatch`、`TraceEvent`，以及 `diagnose_failure(candidate, validation, quality_score, source) -> FailureProfile`。

- [ ] **Step 1: 编写失败测试**

覆盖缺少必填字段、类型不匹配、未知来源、空候选、旧版 validation 格式；断言 failure type、字段名、证据缺口和质量分正确，且输入 candidate 未被修改。验证 FieldPatch 拒绝未知字段和越界 confidence。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest backened/tests/test_recovery_diagnosis.py -v`

Expected: FAIL，原因是 `agent.recovery` 尚不存在。

- [ ] **Step 3: 实现最小模型**

在 `models.py` 定义：

```python
class FieldIssue(BaseModel): ...
class Evidence(BaseModel): ...
class EvidenceGap(BaseModel): ...
class FieldPatch(BaseModel): ...
class FailureProfile(BaseModel): ...
class TraceEvent(BaseModel): ...
```

固定 FailureProfile 类型为 `missing_required_fields`、`schema_mismatch`、`source_unknown`、`field_conflict`、`evidence_missing`、`external_dependency_failure`；模型禁止额外字段。

- [ ] **Step 4: 实现 `diagnose_failure`**

只根据 validation、candidate 和 source 进行确定性映射；多个问题同时出现时按 `source_unknown → field_conflict → missing_required_fields → schema_mismatch → evidence_missing` 选择主类型，其他问题保留在字段列表中。

- [ ] **Step 5: 运行测试确认通过**

Run: `python -m pytest backened/tests/test_recovery_diagnosis.py -v`

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add backened/agent/recovery backened/tests/test_recovery_diagnosis.py
git commit -m "feat: add deterministic recovery diagnosis"
```

### Task 2: 字段级验证结果与证据缺口

**Files:**
- Modify: `backened/agent/cleaner_validator.py`
- Test: `backened/tests/test_cleaner_validation_details.py`

**Interfaces:**
- Consumes: `CleanerValidatorAgent.validate(data: Dict, source: str) -> Dict`。
- Produces: 向兼容结果中新增 `field_issues: list[dict]` 和 `evidence_gaps: list[dict]`；旧键保持不变。

- [ ] **Step 1: 编写失败测试**

通过最小 fake config loader 构造必填缺失、类型错误和长度超限；断言旧的 errors/warnings 仍存在，新字段包含 `field`、`code`、`severity`、`message`、`evidence_required`。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest backened/tests/test_cleaner_validation_details.py -v`

Expected: FAIL，原因是结果中没有 `field_issues` 或 `evidence_gaps`。

- [ ] **Step 3: 扩展 `validate`**

必填缺失记录 `missing_required`；类型错误记录 `type_mismatch`；长度超限记录 `max_length_exceeded`。仅必填缺失和需要来源佐证的字段生成 evidence gap，不改变现有 errors/warnings 文本和 `is_valid` 语义。

- [ ] **Step 4: 运行相关测试**

Run: `python -m pytest backened/tests/test_cleaner_validation_details.py backened/tests/test_recovery_diagnosis.py -v`

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add backened/agent/cleaner_validator.py backened/tests/test_cleaner_validation_details.py
git commit -m "feat: expose field-level validation issues"
```

### Task 3: Recovery State、诊断节点和兼容路由

**Files:**
- Modify: `backened/graph/state.py`
- Create: `backened/graph/recovery_nodes.py`
- Modify: `backened/graph/builder.py`
- Modify: `backened/graph/nodes.py`
- Test: `backened/tests/test_recovery_graph_routing.py`

**Interfaces:**
- Consumes: Task 1 的 `diagnose_failure(...)` 和模型序列化结果。
- Produces: State 新增 `failure_profile: dict | None`、`trace_events: list[dict]`；节点 `diagnose_failure_node(state, config) -> VulnProcessingState`；路由 `route_after_clean(...)` 和 `route_after_diagnosis(...)`。

- [ ] **Step 1: 编写失败测试**

覆盖质量达标直接 Store、低质量先 Diagnose、重试未耗尽进入 Reflect、重试耗尽进入 LowQuality；验证诊断节点写入 FailureProfile 和不含原文的 TraceEvent。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest backened/tests/test_recovery_graph_routing.py -v`

Expected: FAIL，原因是新节点和路由不存在。

- [ ] **Step 3: 扩展 State 默认值**

在 `VulnProcessingState` 与 `create_initial_state` 中加入 `failure_profile`、`trace_events`，默认分别为 `None` 和空列表。

- [ ] **Step 4: 实现诊断节点**

`diagnose_failure_node` 调用 Task 1 的纯函数，把 Pydantic 模型序列化为 dict，并追加仅包含 `task_id`、`node`、`reason_code`、耗时和时间戳的 TraceEvent；不调用 LLM、工具或数据库。

- [ ] **Step 5: 调整 Graph 路由**

Graph 变为 `clean → store | diagnose_failure`，随后 `diagnose_failure → reflect | low_quality`。复用现有阈值和 `max_retries`，不改变 Reflect 的策略升级次序。

- [ ] **Step 6: 为终态追加简洁 Trace**

`reflect_node`、`mark_low_quality_node` 和成功 `store_node` 只追加结构化决策事件，不写入 raw_content、完整 candidate 或配置密钥。

- [ ] **Step 7: 运行 Graph 与回归测试**

Run: `python -m pytest backened/tests/test_recovery_graph_routing.py backened/tests/test_recovery_diagnosis.py backened/tests/test_cleaner_validation_details.py -v`

Expected: PASS。

- [ ] **Step 8: 提交**

```bash
git add backened/graph backened/tests/test_recovery_graph_routing.py
git commit -m "feat: route anomalies through deterministic diagnosis"
```

### Task 4: Phase 1 配置、回归夹具与使用说明

**Files:**
- Modify: `backened/config/agent_config.yaml`
- Create: `backened/tests/fixtures/recovery_cases.json`
- Create: `backened/tests/test_recovery_regression.py`
- Modify: `backened/IMPLEMENTATION_SUMMARY.md`

**Interfaces:**
- Consumes: Tasks 1–3 的诊断与路由接口。
- Produces: 可重复的正常/异常/对抗最小样本集，以及 Phase 1 的运行和 Trace 解释文档。

- [ ] **Step 1: 创建最小回归夹具和失败测试**

夹具至少包含：正常 CVE、缺失描述、伪造 ID、未知来源、冲突字段和带 Prompt Injection 文本六类；测试断言正常样本不进入诊断，异常样本分类稳定，注入文本不会改变 reason_code 或 Trace 结构。

- [ ] **Step 2: 运行测试确认夹具暴露未覆盖行为**

Run: `python -m pytest backened/tests/test_recovery_regression.py -v`

Expected: 在未补齐配置或映射时 FAIL。

- [ ] **Step 3: 增加 Phase 1 配置和说明**

在 `agentic.recovery` 下只增加 `enabled: true` 和 Trace 大小上限；Phase 1 不增加模型、Token、工具或 HIL 配置。文档说明节点执行顺序、Trace 字段和 Phase 2 边界。

- [ ] **Step 4: 运行完整最小验证**

Run: `python -m pytest backened/tests -v`

Expected: PASS。

Run: `python -m compileall -q backened rag`

Expected: exit 0。

Run: `npm run build`（目录：`Frontend`）

Expected: build success；允许保留现有 chunk-size warning。

- [ ] **Step 5: 检查敏感信息和差异**

Run: `git diff --check`

Expected: 新增或修改行无新的 whitespace error。

Run: `git status --short`

Expected: 只包含本计划列出的文件。

- [ ] **Step 6: 提交**

```bash
git add backened/config/agent_config.yaml backened/tests backened/IMPLEMENTATION_SUMMARY.md
git commit -m "test: add recovery phase one regression suite"
```

## Self-Review Result

- Spec coverage: Phase 1 的 FailureProfile、Evidence、FieldPatch Schema、字段级错误、证据缺口、Trace 和固定策略兼容均已覆盖；Patch 生成/应用、Planner、Guard、Outbox 和 HIL 明确留给后续独立计划。
- Type consistency: 所有跨任务接口统一使用 `FailureProfile`、`TraceEvent`、`failure_profile` 和 `trace_events`。
- Review focus coverage: 旧格式、空输入、正常路径、重试终止和 Trace 脱敏均落入对应测试。
- Proportion: 计划只决定接口、路由和验收，不展开实现函数体。
