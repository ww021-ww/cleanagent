# CleanAgent Recovery HIL 与向量索引补偿设计

日期：2026-10-01  
状态：已确认，待实施

## 1. 背景

CleanAgent 当前使用确定性规则完成六类漏洞数据的提取、清洗与 MySQL 入库，并在质量不达标时进入受约束 Recovery Agent。现有实现仍保留 `rule -> hybrid -> llm_full` 旧恢复链路，人工审核只停留在 `REVIEW` 状态，MySQL 成功后同步写 Milvus，写入失败会造成事实库与向量索引不一致。

本次改造完成三个目标：

1. 为 Recovery Agent 增加可恢复与不可恢复异常 Benchmark，证明“有证据才修复、无证据不猜测”。
2. 使用 LangGraph 原生 `interrupt()` / `Command(resume=...)` 建立可持久化的人工审核闭环。
3. 使用 MySQL Transactional Outbox 和单进程 Worker 保证 MySQL 到 Milvus 的最终一致性。

同时移除生产路径中的 `hybrid`、`llm_full` 和 `reflect` 旧逻辑，使受约束 Recovery Agent 成为唯一异常恢复路径。

## 2. 范围与非目标

### 2.1 范围

- 六类既有来源：CVE、NVD、CNVD、CISA、CERT、JVN。
- 现有 LangGraph 数据处理图、FastAPI 服务、SQLAlchemy/MySQL 和 Milvus RAG 链路。
- 单机、小数据量部署。
- HIL 列表、详情、通过和拒绝 API。
- 独立命令启动的单进程向量索引 Worker。

### 2.2 非目标

- 不增加 Redis、Celery 或其他消息中间件。
- 不开发人工审核前端页面。
- 不支持多个 Worker 并行消费。
- 不让 LLM 或审核接口修改漏洞 ID、来源及系统字段。
- 不追求 MySQL 与 Milvus 的跨库强事务；Milvus 是可重建的派生索引。

## 3. 核心决策

1. **MySQL 是唯一事实库。** Milvus 只保存可重建的语义索引。
2. **所有自动修复必须有可定位证据。** 无证据、原始文本模糊命中或权威字段冲突均进入人工审核。
3. **HIL 使用 LangGraph 原生中断。** Checkpoint 保存暂停位置，MySQL `review_tasks` 提供可查询的审核队列。
4. **索引任务使用 Transactional Outbox。** 漏洞 Upsert、子表 Upsert、审核状态更新和 Outbox 写入在同一 MySQL 事务中提交。
5. **Outbox 不复制漏洞正文。** Worker 使用 `source + vuln_id` 从 MySQL 读取最新记录，避免 payload 过期与重复存储。
6. **旧方案只作为规则基线存在。** Benchmark 比较“纯规则、无恢复”与 Recovery Agent；生产代码不再维护旧 LLM 恢复实现。

## 4. 目标数据流

```text
Extract -> Clean/Validate
  |-- quality passed ---------------------------> Store transaction -> END
  `-- quality failed -> Diagnose -> Recovery Agent
                         |-- evidence accepted -> Revalidate -> Store transaction -> END
                         |-- review required --> Prepare Review -> Human Review interrupt
                         |                                         |
                         |                              Command(resume=decision)
                         |                                         |
                         |                     approve/edit -> Revalidate -> Store -> END
                         |                     reject --------------------------> END
                         `-- no evidence/budget exhausted -> Low Quality ------> END

Store transaction:
  vulnerability upsert + subtable upsert + outbox enqueue [+ review approved]

Vector worker:
  claim due outbox -> load latest MySQL record -> embed -> Milvus upsert
                    |-- success -> succeeded
                    `-- failure -> retry / failed
```

## 5. LangGraph HIL

### 5.1 Checkpoint

处理图使用 `AsyncSqliteSaver`，默认保存至 `logs/processing_state.db`。调用图时必须传入：

```python
{"configurable": {"thread_id": task_id}}
```

`task_id` 同时作为审核任务的稳定业务键。Checkpoint 只保存可序列化状态。进入中断前清除完整 `raw_content`，仅保留：

- `task_id`、来源、漏洞 ID 和文件路径；
- 清洗后的候选数据；
- 受限长度的证据片段与证据位置；
- 建议 Patch、验证结果和脱敏 Trace；
- 质量分与失败原因。

单机部署启用 SQLite WAL 和 busy timeout。当前不支持多主机共享 Checkpoint；升级为多实例部署时，再替换为集中式持久化 Checkpointer。

### 5.2 节点职责

- `prepare_review`：使用 `task_id` 幂等创建 `review_tasks`，压缩待持久化 Graph State。
- `human_review`：只调用一次 `interrupt()`，不得在调用前执行数据库副作用。
- `apply_review`：接收恢复值，检查动作和受保护字段，合并人工修正并重新验证。
- `reject_review`：将审核任务更新为 `rejected` 后结束。
- `store`：自动通过或人工通过后调用统一事务写入方法。

中断节点恢复时会从节点开头重新执行，因此创建审核任务与 `interrupt()` 必须位于不同节点。

### 5.3 审核恢复值

```json
{
  "action": "approve",
  "reviewer": "wangchuang",
  "note": "已对照原始公告修正描述",
  "corrected_fields": {
    "description": "修正后的漏洞描述"
  }
}
```

`action` 只允许 `approve` 或 `reject`。`corrected_fields` 只允许来源配置中存在且非受保护的业务字段。

## 6. 数据模型

### 6.1 `review_tasks`

| 字段 | 类型/约束 | 用途 |
|---|---|---|
| `id` | BigInteger PK | 内部主键 |
| `task_id` | String, Unique | 对应 LangGraph `thread_id` |
| `source` | String, Index | 漏洞来源 |
| `vuln_id` | String, Index, Nullable | 已识别的漏洞 ID |
| `file_path` | Text | 原始文件位置 |
| `reason_code` | String | 进入审核的原因 |
| `status` | String, Index | `pending/processing/approved/rejected` |
| `candidate_data` | JSON | 当前候选数据 |
| `proposed_patches` | JSON | Agent 建议和证据 |
| `subtable_data` | JSON | 待写入的子表数据 |
| `reviewer` | String, Nullable | 审核人声明 |
| `review_note` | Text, Nullable | 审核说明 |
| `corrected_data` | JSON, Nullable | 最终人工修正字段 |
| `last_error` | Text, Nullable | 最近恢复错误 |
| `locked_at` | DateTime, Nullable | 审核请求抢占时间 |
| `created_at` | DateTime | 创建时间 |
| `reviewed_at` | DateTime, Nullable | 完成审核时间 |
| `updated_at` | DateTime | 更新时间 |

`task_id` 唯一约束保证 `prepare_review` 重试不会创建重复任务。

### 6.2 `vector_index_outbox`

| 字段 | 类型/约束 | 用途 |
|---|---|---|
| `id` | BigInteger PK | 任务主键 |
| `source` | String | 漏洞来源 |
| `vuln_id` | String | 漏洞 ID |
| `status` | String, Index | `pending/processing/succeeded/failed` |
| `attempt_count` | Integer | 已执行次数 |
| `next_retry_at` | DateTime, Index | 下次可执行时间 |
| `last_error` | Text, Nullable | 最近失败原因 |
| `locked_at` | DateTime, Nullable | Worker 领取时间 |
| `created_at` | DateTime | 创建时间 |
| `updated_at` | DateTime | 更新时间 |

`source + vuln_id` 建立唯一约束。同一漏洞再次 Upsert 时，将现有任务重置为 `pending`，确保 Milvus 最终索引最新版本。

## 7. HIL API

### 7.1 路由

```text
GET  /api/v1/reviews?status=pending&page=1&page_size=20
GET  /api/v1/reviews/{review_id}
POST /api/v1/reviews/{review_id}/approve
POST /api/v1/reviews/{review_id}/reject
```

API 中的 `review_id` 使用公开且稳定的 `task_id`，不暴露数据库自增主键。

列表与详情不返回完整原始文件内容，只返回候选字段、有限证据、建议 Patch 和 Trace。

### 7.2 写接口保护

- `approve/reject` 必须提供与环境变量 `HIL_REVIEW_TOKEN` 匹配的 Bearer Token。
- 未配置 Token 时，写接口返回服务不可用，不允许无认证降级。
- 审核请求通过条件更新把 `pending` 或超时的 `processing` 任务置为 `processing`；其他状态返回 `409`。
- 审核执行异常时记录 `last_error`。未完成数据库提交的任务可以重新领取。
- `approve` 校验失败返回 `422`，任务恢复为 `pending`。

### 7.3 受保护字段

至少包括：

- 当前来源配置的 ID 字段；
- `source`、`id`、`status`、`is_deleted`；
- `create_time`、`modify_time`；
- 任何未在来源字段配置中声明的字段。

人工修正后重新执行 Cleaner/Validator 和来源质量门槛。校验不通过不得入库。

## 8. MySQL 事务与 Outbox

`DatabaseManager` 提取复用当前 Session 的内部 Upsert 方法，并提供统一事务入口：

```text
upsert vulnerability
upsert subtable rows
enqueue/reset vector outbox
optional: mark review approved
commit
```

任一步失败均回滚。`store_node` 不再同步调用 Milvus；MySQL 事务成功即返回 `success_pending_index`，向量索引状态由 Outbox 单独观察。

人工审核通过和普通自动入库必须使用同一事务入口，避免产生两套写入语义。

## 9. 向量索引 Worker

### 9.1 启动方式

```powershell
python -m workers.vector_index_worker
python -m workers.vector_index_worker --once
```

当前明确只运行一个 Worker。它按 `next_retry_at` 领取小批量 `pending/failed` 任务，并将其置为 `processing`。启动和每轮轮询时，超过租约时间的 `processing` 任务重新置为可执行状态。

### 9.2 执行过程

1. 根据 `source + vuln_id` 从 MySQL 动态来源表读取最新记录。
2. 构建与现有 RAG 相同的文档内容并生成 Embedding。
3. 调用 Milvus Upsert。
4. 成功后标记 `succeeded`。
5. 失败时保存截断后的异常信息并增加 `attempt_count`。
6. 未达到最大次数时使用指数退避设置 `next_retry_at`；达到上限后保持 `failed`，等待人工重新触发或数据再次 Upsert。

默认最多 5 次，退避间隔为 10、20、40、80、160 秒，并设置最大间隔。具体值进入现有 YAML 配置。

`RAGRetriever.index_vulnerability()` 不再吞掉写入异常。它必须明确成功，或抛出可供 Worker 记录的异常。

## 10. Recovery Benchmark

### 10.1 样本与异常

每个来源从真实 JSON 数据中选择一条包含 ID 和描述的基准样本，生成：

- `layout_drift`：移除已配置描述字段，把同一真实值移动至 `recovery_evidence.description`。规则基线应失败，Recovery Agent 应调用 `parse_json_path` 精确恢复。
- `missing_evidence`：删除描述内容并只保留真实 ID。Recovery Agent 必须进入 `REVIEW/ABORT`，不得自动生成描述。

若某来源没有可用 JSON 样本，则该来源明确报告为跳过，不用 HTML 模糊片段伪造“自动精确恢复”。HTML 原始文本证据仍必须进入人工审核。

### 10.2 对照与指标

对照组为纯规则提取并关闭 Recovery Agent；实验组启用 Recovery Agent。全程 `dry_run`，不写 MySQL、Milvus、审核表或持久化 Checkpoint。Benchmark 在产生 `REVIEW` 决策时直接记录安全拦截结果并结束该案例，不进入真实人工等待。

指标包括：

- 可恢复字段精确恢复率；
- 无证据安全拦截率；
- 非目标字段误修改率；
- 受保护 ID 保持率；
- `REVIEW/ABORT` 比例；
- LLM/Tool 调用次数；
- 总耗时。

单元测试使用固定 Planner/Tool Mock；真实 Benchmark 保存模型名称、时间和逐案例结果，避免把单次随机结果写成稳定承诺。

## 11. 旧链路清理

### 11.1 删除

- `reflect_node`、相关路由和回环 Edge；
- `hybrid`、`llm_full` 策略分支及旧 LLM 字段恢复；
- `reflection`、`field_recovery`、`agent_loop_enabled` 配置；
- State 中只服务于旧链路的 `extraction_strategy`、`reflection_notes`、`recovery_attempted`、`recovered_fields` 和 `retry_count`；
- 只验证旧策略的测试。

### 11.2 保留并简化

- Planner 保留目录级去重和确定性处理顺序，不再分配 LLM 提取策略。
- Memory 保留 ID 去重、来源成功/失败和质量统计，不再推荐提取策略。
- RAG 保留问答检索和异步索引，不再向旧 `llm_full` 提供 few-shot 上下文。
- `recovery.enabled` 是唯一恢复总开关；关闭后质量不合格数据直接进入 Low Quality。

### 11.3 迁移顺序

1. 先接入默认 Recovery Agent、HIL 和 Outbox，并通过现有回归测试。
2. 运行六来源新 Benchmark，确认无证据不自动写入。
3. 删除旧策略代码和配置，更新测试。
4. 再次运行完整测试、静态引用检查和真实 Benchmark。

以上步骤分别提交，便于定位问题和回退。

## 12. 错误处理与幂等性

- `prepare_review` 按 `task_id` Upsert。
- 审核操作只允许合法状态迁移；重复请求返回 `409`。
- 人工审核恢复后即使节点重试，漏洞 Upsert、Outbox 唯一约束和审核最终状态也不会创建重复业务记录。
- Worker 只运行一个实例；陈旧 `processing` 任务按租约恢复。
- Milvus 故障不回滚已经成功提交的 MySQL 数据。
- Checkpoint 孤立或缺失时，审核详情明确返回不可恢复状态，不绕过 Graph 直接写库。
- Checkpoint 中不保存完整原始正文，降低 SQLite 文件体积和敏感数据暴露。

## 13. 配置

现有 YAML 增加：

```yaml
agentic:
  recovery:
    enabled: true
    checkpoint_path: logs/processing_state.db

  human_review:
    enabled: true
    processing_lease_seconds: 900

  vector_outbox:
    enabled: true
    batch_size: 20
    poll_interval_seconds: 5
    max_attempts: 5
    processing_lease_seconds: 300
    retry_base_seconds: 10
    retry_max_seconds: 300
```

密钥只通过环境变量提供：

```text
HIL_REVIEW_TOKEN
```

## 14. 测试与验收

### 14.1 自动测试

- Graph：质量通过、自动恢复、审核中断、批准恢复、拒绝结束、预算耗尽。
- Checkpoint：使用同一 `thread_id` 重建 Controller 后仍可恢复。
- HIL API：列表、详情、认证、字段保护、`409`、`422` 和重复请求。
- 事务：漏洞写入、子表、Outbox 和审核状态共同提交或共同回滚。
- Worker：成功、失败重试、最大次数、陈旧锁恢复和读取最新 MySQL 数据。
- Benchmark：`layout_drift` 精确恢复，`missing_evidence` 不产生虚构 Patch。
- 旧链路：生产代码不再引用 `hybrid`、`llm_full` 或 `reflect_node`。

### 14.2 完成标准

- 全部现有有效测试与新增测试通过。
- 真实六来源 Benchmark 生成报告；有证据案例能恢复，无证据案例全部安全拦截。
- Graph 中断后没有等待线程；进程重启后可以通过 `thread_id` 恢复。
- 人工无法修改漏洞 ID、来源和系统字段。
- MySQL 成功而 Milvus 暂时失败时，Outbox 保留任务并能在恢复后写入。
- FastAPI 请求不等待 Embedding 或 Milvus 写入。
- 不新增 Redis、Celery，也不包含审核前端。

## 15. 已知边界与升级条件

- 当前只支持单机共享 SQLite Checkpoint 文件；需要多主机部署时替换集中式 Checkpointer。
- 当前只运行一个向量 Worker；任务积压或延迟达到不可接受水平时再引入并行领取或消息队列。
- 当前使用共享审核 Token；需要细粒度身份、权限和审计时接入统一认证系统。
- 当前 Benchmark 每来源使用少量真实样本；需要发布稳定质量指标时扩充人工标注集并进行多轮统计。
