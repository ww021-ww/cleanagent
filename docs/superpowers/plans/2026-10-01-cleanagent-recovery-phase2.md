# CleanAgent Recovery Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 Phase 1 的异常诊断增加受约束 Planner、工具执行、证据验证和有限循环，同时保持正常样本零额外 LLM 调用。

**Architecture:** 质量达标样本仍直接 Store；异常样本在 `agent_loop_enabled` 开启时进入 `Diagnose → Plan → Guard → Execute → Verify → Decide` 子图。Planner 只选择白名单工具，Guard 授权后 Python 才执行，Verifier 是唯一可合并 Patch 的组件；关闭开关时继续使用现有 Reflect 链路。

**Tech Stack:** Python 3.9+、Pydantic 2、LangChain `ChatOpenAI.bind_tools`、LangGraph、pytest

**Spec:** `docs/superpowers/specs/2026-10-01-cleanagent-constrained-agent-recovery-design.md`

## Global Constraints

- 正常样本不得新增 LLM、工具或外部网络调用。
- Planner 不接收完整原文，不输出自由代码，不保存隐藏思维链。
- Agent 不能直接修改候选字段或写数据库；只有 Verifier 能接受 Patch，只有 Store 能写库。
- A 类字段只能由当前原文的确定性解析或 NVD 官方结构化结果支持；无证据字段保持空值。
- 单次异常恢复默认最多 3 step、5 次工具调用、2 次 LLM 调用、30 秒 deadline。
- Phase 2 只实现 `search_raw_text`、`parse_json_path`、`normalize_field`、`nvd_lookup`；不增加 Tavily、任意网页抓取、任意 SQL、HIL UI、Outbox 或在线学习。
- `agent_loop_enabled: false` 时行为必须与 Phase 1 一致；旧 `field_recovery` 和 `ToolAgent.auto_fill` 仅在 Agent Loop 关闭时运行。
- 所有 Trace 继续脱敏，并截断工具参数摘要、错误和证据摘要。

## Review Focus

- Prompt Injection 出现在原始正文或工具结果中时，只作为数据处理，不能改变工具白名单或最终决策。
- 伪造或缺失漏洞 ID 时，Guard 必须拒绝 `nvd_lookup`，且不得自动构造 ID。
- Planner 超时、无 tool call、未知工具或参数 Schema 错误时，流程必须安全 REPLAN，预算耗尽后 ABORT。
- A 类字段的非官方 Patch 必须被拒绝；B 类字段没有证据时不得合并。
- Agent Loop 关闭或正常样本通过质量门时，Planner 和 Tool Registry 的调用计数必须保持 0。

---

### Task 1: Recovery Loop 数据合约与预算

**Files:**
- Modify: `backened/agent/recovery/models.py`
- Modify: `backened/agent/recovery/__init__.py`
- Modify: `backened/graph/state.py`
- Test: `backened/tests/test_recovery_contracts.py`

**Interfaces:**
- Consumes: Phase 1 的 `FailureProfile`、`FieldPatch`、`TraceEvent`。
- Produces: `RecoveryDecision`、`ToolSpec`、`ToolResult`、`AuthorizedAction`、`ActionRejection`、`VerificationResult`、`RecoveryBudget`；State 中对应 dict/list/counter 字段。

- [ ] **Step 1: 编写失败测试**

覆盖严格 Schema、未知字段拒绝、confidence 与计数范围、默认预算 `3/5/2/30s`、过期/耗尽判断；验证初始 State 中 decision/action/observations/patches 为空且计数为 0。

- [ ] **Step 2: 运行测试确认失败**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_contracts.py -v`（目录：`backened`）

Expected: FAIL，原因是 Phase 2 合约尚不存在。

- [ ] **Step 3: 实现最小合约**

在 `models.py` 增加：

- `RecoveryDecision(decision, reason_code, target_fields, tool_name, tool_args, expected_evidence)`
- `ToolSpec(name, description, args_schema, allowed_fields, external)`
- `ToolResult(success, tool_name, data, evidence, source_name, source_url, evidence_location, latency_ms, error)`
- `AuthorizedAction(tool_name, tool_args, target_fields)` 与 `ActionRejection(reason_code, details)`
- `VerificationResult(status, reason_code, accepted_patches, rejected_fields)`
- `RecoveryBudget(max_steps=3, max_tool_calls=5, max_llm_calls=2, deadline_seconds=30)`，提供 `is_exhausted(...) -> bool`。

State 增加 `recovery_decision`、`pending_action`、`observations`、`proposed_patches`、`verification`、`final_decision`、`step_count`、`tool_call_count`、`llm_call_count`、`deadline_at`。

- [ ] **Step 4: 运行测试确认通过并提交**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_contracts.py tests/test_recovery_diagnosis.py -v`

```bash
git add backened/agent/recovery backened/graph/state.py backened/tests/test_recovery_contracts.py
git commit -m "feat: add constrained recovery contracts"
```

### Task 2: 白名单 Tool Registry 与四个核心工具

**Files:**
- Create: `backened/agent/recovery/tool_registry.py`
- Modify: `backened/agent/recovery/__init__.py`
- Test: `backened/tests/test_recovery_tools.py`

**Interfaces:**
- Consumes: `ToolSpec`、`ToolResult`，以及执行时注入的 `raw_content`、`file_path`、`source`、`candidate`。
- Produces: `RecoveryToolRegistry.describe_allowed(context) -> List[ToolSpec]` 和 `invoke(name, args, context) -> ToolResult`。

- [ ] **Step 1: 编写失败测试**

覆盖：原文关键词证据及位置、只允许点分隔键的 JSON Path、CVE/日期/CVSS 规范化、复用现有 `tools.builtin.nvd_lookup`、未知工具拒绝、参数额外字段拒绝、超长结果截断、工具异常转为失败 `ToolResult`。网络工具使用 fake callable，不访问真实 NVD。

- [ ] **Step 2: 运行测试确认失败**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_tools.py -v`

Expected: FAIL，原因是 `RecoveryToolRegistry` 尚不存在。

- [ ] **Step 3: 实现最小 Registry**

注册四个工具及严格 Pydantic 参数：

- `search_raw_text(field_hint, keywords)`：只搜索当前文件内容，返回证据片段和字符位置。
- `parse_json_path(path, target_field)`：使用 `json.loads` 和逐级 dict/list 索引，不使用 `eval`。
- `normalize_field(field, value)`：仅处理 ID、ISO 日期和 CVSS 数值/向量格式，不补造事实。
- `nvd_lookup(cve_id, target_fields)`：校验 CVE 格式后调用现有 NVD 函数并保留官方 URL。

Registry 只返回统一 `ToolResult`；同步实现由 Graph 执行节点负责线程池、超时和计数。

- [ ] **Step 4: 运行测试确认通过并提交**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_tools.py -v`

```bash
git add backened/agent/recovery/tool_registry.py backened/agent/recovery/__init__.py backened/tests/test_recovery_tools.py
git commit -m "feat: add recovery tool registry"
```

### Task 3: Action Guard 与 Evidence Verifier

**Files:**
- Create: `backened/agent/recovery/guard.py`
- Create: `backened/agent/recovery/verifier.py`
- Test: `backened/tests/test_recovery_guard_verifier.py`

**Interfaces:**
- Consumes: `RecoveryDecision`、`ToolResult`、Candidate、Source、`FieldConfigLoader`、Registry 和剩余预算。
- Produces: `authorize(...) -> AuthorizedAction | ActionRejection`；`verify(...) -> VerificationResult`。

- [ ] **Step 1: 编写失败测试**

覆盖允许工具、未知工具、额外参数、预算耗尽、伪造 CVE、字段越权；验证 A 类字段只接受当前原文确定性工具或 NVD 官方证据，B 类字段必须有非空 evidence/location，冲突权威来源返回 `review`，不支持结果返回 `rejected`，输入 Candidate 不被修改。

- [ ] **Step 2: 运行测试确认失败**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_guard_verifier.py -v`

Expected: FAIL，原因是 Guard/Verifier 尚不存在。

- [ ] **Step 3: 实现 Guard**

`RecoveryActionGuard.authorize(decision, state, registry, now=None)` 调用 Registry 的严格参数校验，再按 allowed_fields、CVE ID、step/tool/deadline 预算依次检查；拒绝结果使用 `ActionRejection`，不抛出到 Graph。

- [ ] **Step 4: 实现 Verifier**

`EvidenceVerifier.verify(candidate, action, result, source) -> VerificationResult` 只从成功 ToolResult 生成 Patch；A/B 字段按来源规则验证。Verifier 返回接受/拒绝/审核结果，不在函数内修改 Candidate。

- [ ] **Step 5: 运行测试确认通过并提交**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_guard_verifier.py -v`

```bash
git add backened/agent/recovery/guard.py backened/agent/recovery/verifier.py backened/tests/test_recovery_guard_verifier.py
git commit -m "feat: guard and verify recovery actions"
```

### Task 4: 受约束 Planner 与安全降级

**Files:**
- Create: `backened/agent/recovery/planner.py`
- Test: `backened/tests/test_recovery_planner.py`

**Interfaces:**
- Consumes: `FailureProfile`、允许的 `ToolSpec`、观察摘要、剩余预算；LLM 通过构造函数注入。
- Produces: `ConstrainedRecoveryPlanner.plan(context) -> RecoveryDecision`。

- [ ] **Step 1: 编写失败测试**

使用 fake bind-tools model 覆盖：合法 tool call 映射为 `CALL_TOOL`；控制调用映射为 `STOP/REVIEW/ABORT`；无调用、未知工具、非法参数、模型超时或异常时返回 `ABORT`；断言发送给模型的上下文不含 `raw_content`、API Key 或完整 Candidate。

- [ ] **Step 2: 运行测试确认失败**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_planner.py -v`

Expected: FAIL，原因是 Planner 尚不存在。

- [ ] **Step 3: 实现 Planner**

`ConstrainedRecoveryPlanner(llm, registry)` 使用 `llm.bind_tools()` 绑定 Registry Schema 与一个 `recovery_control` Schema；每轮只接受一个 tool call，并把它转换成严格 `RecoveryDecision`。模型未配置或输出非法时使用确定性安全降级，不生成字段值。

- [ ] **Step 4: 运行测试确认通过并提交**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_planner.py -v`

```bash
git add backened/agent/recovery/planner.py backened/tests/test_recovery_planner.py
git commit -m "feat: add constrained recovery planner"
```

### Task 5: LangGraph Agent Loop、feature flag 与端到端回归

**Files:**
- Modify: `backened/graph/recovery_nodes.py`
- Modify: `backened/graph/builder.py`
- Modify: `backened/graph/nodes.py`
- Modify: `backened/graph/controller.py`
- Modify: `backened/config/agent_config.yaml`
- Create: `backened/tests/test_recovery_agent_graph.py`
- Modify: `backened/tests/test_recovery_regression.py`
- Modify: `backened/IMPLEMENTATION_SUMMARY.md`

**Interfaces:**
- Consumes: Tasks 1–4 的 contracts、Registry、Guard、Verifier、Planner。
- Produces: `plan_recovery_node`、`guard_action_node`、`execute_action_node`、`verify_evidence_node`、`decide_next_node` 及 PASS/REPLAN/REVIEW/ABORT 路由。

- [ ] **Step 1: 编写失败 Graph 测试**

用 fake Planner/Registry 构造：正常样本零调用；缺失描述经当前原文证据恢复后 Store；伪造 ID 被 Guard 拒绝；工具超时后有限 REPLAN；A 类非法 Patch 不合并；预算耗尽 ABORT；关闭 Agent Loop 时仍进入 Phase 1 Reflect。

- [ ] **Step 2: 运行测试确认失败**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_agent_graph.py -v`

Expected: FAIL，原因是 Phase 2 节点与路由尚不存在。

- [ ] **Step 3: 扩展 State 与节点**

节点职责：Planner 只写 decision；Guard 只写 authorized action/rejection；Execute 使用 `asyncio.to_thread` + `asyncio.wait_for` 调用 Registry，并更新调用计数；Verify 只合并 accepted Patch 后重新调用现有 Cleaner Validate/quality score；Decide 根据验证状态和预算生成最终决策与 Trace，其中 Planner `STOP/ABORT` 映射为 ABORT、`REVIEW` 映射为 REVIEW。

- [ ] **Step 4: 接入 Graph 与 Controller**

Controller 初始化并注入 Registry、Guard、Verifier、Planner。`agent_loop_enabled: true` 时 `diagnose_failure → plan → guard → execute → verify → decide`；REPLAN 回到 Plan，PASS 进入 Store，REVIEW/ABORT 进入 LowQuality。开关关闭时保持 `diagnose_failure → reflect/low_quality`。

- [ ] **Step 5: 隔离旧的不受约束修复**

`clean_validate_node` 在 Agent Loop 开启时跳过旧 `recover_fields` 和 `ToolAgent.auto_fill`，防止 LLM 或搜索结果在 Guard/Verifier 前直接写入 Candidate；关闭时完全保持旧行为。

- [ ] **Step 6: 增加配置与文档**

在 `agentic.recovery` 增加 `agent_loop_enabled: false`、预算、工具超时与结果大小上限。文档说明如何 A/B 开启、四个工具、字段安全边界和 Trace 决策。

- [ ] **Step 7: 运行完整验证并提交**

Run: `conda run -n LLFlow python -m pytest tests -v`（目录：`backened`）

Run: `conda run -n LLFlow python -m compileall -q .`（目录：`backened`）

Run: `npm run build`（目录：`Frontend`）

Run: `git diff --check`

Expected: 全部通过；允许保留现有 LangGraph annotation 和前端 chunk-size warning。

```bash
git add backened/graph backened/agent/recovery backened/config/agent_config.yaml backened/tests backened/IMPLEMENTATION_SUMMARY.md
git commit -m "feat: add constrained recovery agent loop"
```

## Self-Review Result

- Spec coverage: Phase 2 的 Planner、Guard、Registry、四个核心工具、Verifier、预算、超时、有限循环和 feature flag 均有对应任务；Outbox、HIL 和经验学习按设计留给 Phase 3–4。
- Type consistency: 所有任务统一使用 `RecoveryDecision`、`ToolSpec`、`ToolResult`、`AuthorizedAction`、`VerificationResult` 和 Phase 1 的 `FieldPatch`。
- Review focus coverage: 注入、伪造 ID、模型异常、字段越权和正常路径零调用分别落入 Tasks 2–5 测试。
- Proportion: 计划定义接口、边界和验收，不预写实现函数体。
