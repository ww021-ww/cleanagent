# Recovery HIL and Vector Outbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy LLM extraction fallback with an evidence-constrained Recovery Agent, durable LangGraph HIL review, and reliable MySQL-to-Milvus indexing.

**Architecture:** MySQL remains the system of record. LangGraph pauses review cases with `interrupt()` and persists state through `AsyncSqliteSaver`; approved records and vector-index intents commit atomically through a MySQL Outbox, and a single worker updates Milvus asynchronously.

**Tech Stack:** Python 3.9+, LangGraph 1.1, `langgraph-checkpoint-sqlite` 3.1, FastAPI, SQLAlchemy 2, MySQL, SQLite, Milvus, pytest.

**Spec:** `docs/superpowers/specs/2026-10-01-recovery-hil-outbox-design.md`

## Global Constraints

- Support the existing CVE, NVD, CNVD, CISA, CERT, and JVN source configurations.
- Do not add Redis, Celery, a review frontend, or multi-worker consumption.
- Never auto-change a source ID, source name, or system-managed field.
- Never synthesize a vulnerability field without located evidence.
- Do not store full raw input in review rows or durable checkpoints.
- Keep MySQL as the only fact store; Milvus is a rebuildable derived index.
- Run Python tests from `backened/` with `conda run -n LLFlow python -m pytest`.
- Use existing dependencies where possible; add only `langgraph-checkpoint-sqlite>=3.1,<4` explicitly.

## Review Focus

- Two reviewers approve the same task concurrently: one claim succeeds, the other receives `409`, and only one store transaction runs (Task 3).
- A reviewer attempts to change the source ID: validation returns `422`, the graph is not resumed, and the task remains pending (Task 3).
- MySQL fails after vulnerability Upsert but before Outbox enqueue: the vulnerability write, subtable writes, review transition, and Outbox row all roll back (Task 1).
- The process restarts while waiting for review: reopening the same SQLite checkpoint and `thread_id` resumes without full `raw_content` (Task 2).
- A Worker or review request dies while status is `processing`: the expired lease makes the item claimable again without creating duplicates (Tasks 1 and 4).

---

### Task 1: Reliability Tables and Atomic Storage

**Files:**
- Create: `backened/database/reliability.py`
- Modify: `backened/database/manager.py`
- Modify: `backened/database/__init__.py`
- Test: `backened/tests/test_reliability_storage.py`

**Interfaces:**
- Produces: `ReviewTask`, `VectorIndexOutbox`, and `ReliabilityBase` SQLAlchemy models.
- Produces: `ReliabilityStore(session_factory)` with review queue and Outbox claim/update operations.
- Produces: `DatabaseManager.upsert_with_outbox(data, source, subtable_records=None, review_task_id=None) -> bool`.
- Produces: `DatabaseManager.get_record(source, vuln_id) -> Optional[Dict[str, Any]]`.
- Consumes: existing dynamic source models, source ID configuration, and SQLAlchemy Session factory.

- [ ] **Step 1: Write failing model and transaction tests**

Add tests named:

```python
def test_enqueue_review_is_idempotent_by_task_id(): ...
def test_claim_review_rejects_active_processing_task(): ...
def test_claim_review_reclaims_expired_processing_task(): ...
def test_upsert_with_outbox_commits_main_subtable_and_unique_job(): ...
def test_upsert_with_outbox_rolls_back_everything_on_outbox_failure(): ...
def test_review_approval_rolls_back_with_failed_store_transaction(): ...
def test_new_upsert_resets_existing_outbox_job_to_pending(): ...
```

Use a temporary SQLite database and the real field configuration. Assert the unique keys `review_tasks.task_id` and `(vector_index_outbox.source, vector_index_outbox.vuln_id)`.

- [ ] **Step 2: Run the new tests and verify they fail**

Run: `conda run -n LLFlow python -m pytest tests/test_reliability_storage.py -q`

Expected: FAIL because `database.reliability` and `upsert_with_outbox` do not exist.

- [ ] **Step 3: Add the reliability models and store**

Implement in `database/reliability.py`:

```python
class ReviewTask(ReliabilityBase): ...
class VectorIndexOutbox(ReliabilityBase): ...

class ReliabilityStore:
    def create_tables(self, engine) -> None: ...
    def enqueue_review(self, *, task_id: str, source: str, vuln_id: str | None,
                       file_path: str, reason_code: str, candidate_data: dict,
                       proposed_patches: list, subtable_data: list) -> dict: ...
    def list_reviews(self, *, status: str | None, page: int,
                     page_size: int) -> dict: ...
    def get_review(self, task_id: str) -> dict | None: ...
    def claim_review(self, *, task_id: str, reviewer: str, note: str,
                     corrected_data: dict, lease_seconds: int) -> dict | None: ...
    def release_review(self, task_id: str, error: str) -> None: ...
    def mark_review_rejected(self, task_id: str, reviewer: str, note: str) -> bool: ...
    def claim_vector_jobs(self, *, limit: int, lease_seconds: int) -> list[dict]: ...
    def mark_vector_success(self, job_id: int) -> None: ...
    def mark_vector_failure(self, *, job_id: int, error: str,
                            max_attempts: int, retry_base_seconds: int,
                            retry_max_seconds: int) -> None: ...
```

Serialize only JSON-compatible snapshots and truncate stored errors. Reclaim only `processing` rows whose `locked_at` lease has expired.

- [ ] **Step 4: Refactor the current Upsert into one transaction boundary**

Add internal Session-based helpers to `DatabaseManager` and implement:

```python
def upsert_with_outbox(
    self,
    data: Dict[str, Any],
    source: str,
    subtable_records: Optional[List[Dict[str, Any]]] = None,
    review_task_id: Optional[str] = None,
) -> bool: ...

def get_record(self, source: str, vuln_id: str) -> Optional[Dict[str, Any]]: ...
```

The single transaction must Upsert the main record, Upsert any subtable rows, enqueue/reset the unique Outbox row, optionally transition the claimed review row to `approved`, then commit once. Any exception rolls back all four effects.

- [ ] **Step 5: Run Task 1 tests**

Run: `conda run -n LLFlow python -m pytest tests/test_reliability_storage.py -q`

Expected: all Task 1 tests PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add backened/database backened/tests/test_reliability_storage.py
git commit -m "feat: add review and vector outbox storage"
```

### Task 2: Durable Native LangGraph HIL

**Files:**
- Create: `backened/graph/checkpoint.py`
- Create: `backened/graph/hil_nodes.py`
- Modify: `backened/requirements.txt`
- Modify: `backened/graph/state.py`
- Modify: `backened/graph/builder.py`
- Modify: `backened/graph/controller.py`
- Modify: `backened/graph/nodes.py`
- Modify: `backened/main.py`
- Modify: `backened/config/agent_config.yaml`
- Test: `backened/tests/test_hil_graph.py`

**Interfaces:**
- Consumes: Task 1 `ReliabilityStore` and `DatabaseManager.upsert_with_outbox`.
- Produces: `open_checkpointer(path: str)` async context manager.
- Produces: `build_vuln_processing_graph(config, checkpointer=None)`.
- Produces: `LangGraphController(config, checkpointer=None)` and `await controller.resume_review(task_id, review_input)`.
- Produces state keys: `review_task_id`, `review_response`, and `review_status`.

- [ ] **Step 1: Write failing HIL graph tests**

Add tests named:

```python
async def test_review_decision_interrupts_without_storing_raw_content(): ...
async def test_approved_review_resumes_same_thread_and_stores(): ...
async def test_rejected_review_resumes_and_ends_without_storage(): ...
async def test_checkpoint_reopens_and_resumes_by_thread_id(): ...
async def test_dry_run_records_review_without_persistent_interrupt(): ...
```

Use an in-memory checkpointer for ordinary tests and a temporary `AsyncSqliteSaver` file for the restart test. Mock the LLM decision and storage boundary, not LangGraph `interrupt()`.

- [ ] **Step 2: Run the HIL tests and verify they fail**

Run: `conda run -n LLFlow python -m pytest tests/test_hil_graph.py -q`

Expected: FAIL because the HIL nodes and checkpointer integration do not exist.

- [ ] **Step 3: Add checkpoint lifecycle support**

Add `langgraph-checkpoint-sqlite>=3.1,<4` to requirements. Implement `open_checkpointer(path)` around `AsyncSqliteSaver.from_conn_string`, configure SQLite WAL/busy timeout, and close it through the async context manager.

Change graph compilation to accept a checkpointer. Invoke every processing thread with `configurable.thread_id = task_id`.

- [ ] **Step 4: Add the HIL nodes and routes**

Implement in `graph/hil_nodes.py`:

```python
async def prepare_review_node(state, config) -> VulnProcessingState: ...
def human_review_node(state, config) -> VulnProcessingState: ...
async def apply_review_node(state, config) -> VulnProcessingState: ...
async def reject_review_node(state, config) -> VulnProcessingState: ...
```

`prepare_review_node` must idempotently enqueue the review before clearing `raw_content`. `human_review_node` performs no side effect before its single `interrupt()` call. `apply_review_node` rejects protected/unknown fields, re-cleans and validates, and only then routes to `store`. `reject_review_node` marks the review rejected and ends.

In `dry_run`, return a review-required result without writing a review row, opening a durable checkpoint, or waiting for input.

- [ ] **Step 5: Add controller resume support and update the CLI lifecycle**

Implement:

```python
async def resume_review(self, task_id: str, review_input: Dict[str, Any]) -> Dict[str, Any]: ...
```

Resume with `Command(resume=review_input)` and the same `thread_id`. Update CLI startup to open the configured checkpoint for the Controller lifetime. Count `review_pending` separately from failures.

- [ ] **Step 6: Run Task 2 and recovery graph tests**

Run: `conda run -n LLFlow python -m pytest tests/test_hil_graph.py tests/test_recovery_agent_graph.py tests/test_recovery_graph_routing.py -q`

Expected: all selected tests PASS.

- [ ] **Step 7: Commit Task 2**

```bash
git add backened/requirements.txt backened/config/agent_config.yaml backened/graph backened/main.py backened/tests/test_hil_graph.py
git commit -m "feat: add durable LangGraph human review"
```

### Task 3: Secured HIL Review API

**Files:**
- Create: `backened/api/runtime.py`
- Create: `backened/api/schemas/review.py`
- Create: `backened/api/services/review_service.py`
- Create: `backened/api/routers/reviews.py`
- Modify: `backened/api/app.py`
- Modify: `backened/api/deps.py`
- Modify: `backened/api/routers/__init__.py`
- Test: `backened/tests/test_review_api.py`

**Interfaces:**
- Consumes: Task 1 `ReliabilityStore` and Task 2 `LangGraphController.resume_review`.
- Produces: `ProcessingRuntime` FastAPI lifespan resource.
- Produces: list, detail, approve, and reject endpoints under `/api/v1/reviews`.
- Produces: `ReviewDecisionRequest(reviewer, note, corrected_fields)`.

- [ ] **Step 1: Write failing API tests**

Add tests named:

```python
def test_list_and_detail_reviews_do_not_expose_raw_content(): ...
def test_review_write_requires_configured_bearer_token(): ...
def test_approve_rejects_protected_id_change_with_422(): ...
def test_approve_rejects_unknown_field_with_422(): ...
def test_duplicate_or_concurrent_approve_returns_409(): ...
def test_invalid_correction_returns_422_and_releases_claim(): ...
def test_missing_checkpoint_returns_conflict_and_releases_claim(): ...
def test_approve_resumes_graph_and_returns_final_status(): ...
def test_reject_resumes_graph_without_storing(): ...
```

Use FastAPI `TestClient`, dependency overrides, a temporary database, and a fake Controller.

- [ ] **Step 2: Run API tests and verify they fail**

Run: `conda run -n LLFlow python -m pytest tests/test_review_api.py -q`

Expected: FAIL with missing router/schema/runtime imports.

- [ ] **Step 3: Implement API schemas, auth, and review service**

Require `Authorization: Bearer <HIL_REVIEW_TOKEN>` for approve/reject. Refuse write operations when the environment variable is missing. Validate correction keys against source field configuration before claiming the review, and run Cleaner/Validator before resuming so invalid input does not consume the interrupt.

`ReviewService.approve(...)` must claim `pending` or expired `processing`, call `resume_review`, and release the claim only when no final database transition occurred. `ReviewService.reject(...)` follows the same claim rule.

- [ ] **Step 4: Add the router and FastAPI runtime**

Register:

```text
GET  /api/v1/reviews
GET  /api/v1/reviews/{task_id}
POST /api/v1/reviews/{task_id}/approve
POST /api/v1/reviews/{task_id}/reject
```

The app lifespan must open one `AsyncSqliteSaver`, create one processing Controller, and close the saver on shutdown. Preserve all existing chat/vulnerability routes.

- [ ] **Step 5: Run Task 3 tests**

Run: `conda run -n LLFlow python -m pytest tests/test_review_api.py -q`

Expected: all Task 3 tests PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add backened/api backened/tests/test_review_api.py
git commit -m "feat: add secured human review API"
```

### Task 4: MySQL-to-Milvus Outbox Worker

**Files:**
- Create: `backened/workers/__init__.py`
- Create: `backened/workers/vector_index_worker.py`
- Modify: `backened/rag/retriever.py`
- Modify: `backened/graph/nodes.py`
- Modify: `backened/config/agent_config.yaml`
- Test: `backened/tests/test_vector_index_worker.py`

**Interfaces:**
- Consumes: Task 1 `ReliabilityStore.claim_vector_jobs`, `DatabaseManager.get_record`, and Outbox status methods.
- Produces: `VectorIndexWorker.run_once() -> Dict[str, int]` and `VectorIndexWorker.run_forever() -> None`.
- Changes: `RAGRetriever.index_vulnerability(vuln_data, source) -> None` succeeds or raises; it no longer swallows failures.

- [ ] **Step 1: Write failing Worker tests**

Add tests named:

```python
def test_worker_indexes_latest_mysql_record_and_marks_success(): ...
def test_worker_records_failure_and_exponential_retry(): ...
def test_worker_stops_retrying_at_max_attempts(): ...
def test_worker_reclaims_expired_processing_job(): ...
def test_store_node_does_not_call_milvus_inline(): ...
```

Mock Embedding/Milvus only; use real temporary SQLAlchemy tables for Outbox state.

- [ ] **Step 2: Run Worker tests and verify they fail**

Run: `conda run -n LLFlow python -m pytest tests/test_vector_index_worker.py -q`

Expected: FAIL because the Worker does not exist and store still calls Milvus inline.

- [ ] **Step 3: Make RAG indexing failure observable and remove inline indexing**

Change `index_vulnerability` to raise on disabled client, missing indexable data, embedding mismatch, or Milvus Upsert failure. Remove the RAG call from `store_node`; successful MySQL transaction returns `storage_status='success_pending_index'`.

- [ ] **Step 4: Implement the single-process Worker and CLI**

Implement:

```python
class VectorIndexWorker:
    def run_once(self) -> Dict[str, int]: ...
    def run_forever(self) -> None: ...
```

Support `python -m workers.vector_index_worker` and `--once`. Read batch size, polling, lease, attempts, and retry values from `agentic.vector_outbox`.

- [ ] **Step 5: Run Task 4 tests**

Run: `conda run -n LLFlow python -m pytest tests/test_vector_index_worker.py -q`

Expected: all Task 4 tests PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add backened/workers backened/rag/retriever.py backened/graph/nodes.py backened/config/agent_config.yaml backened/tests/test_vector_index_worker.py
git commit -m "feat: add Milvus outbox worker"
```

### Task 5: Recoverable and Safe-Failure Benchmark

**Files:**
- Modify: `backened/recovery_ab.py`
- Modify: `backened/recovery_benchmark.py`
- Modify: `backened/tests/test_recovery_benchmark.py`

**Interfaces:**
- Produces benchmark variants `baseline` (rule-only, recovery disabled) and `agent` (Recovery Agent enabled).
- Produces mutations `layout_drift` and `missing_evidence`.
- Produces metrics `recoverable_field_accuracy`, `safe_block_rate`, `false_modification_rate`, `protected_id_preservation_rate`, LLM/tool calls, and elapsed time.

- [ ] **Step 1: Replace benchmark tests with the new contracts**

Add or update tests named:

```python
def test_layout_drift_keeps_exact_evidence_at_recovery_json_path(): ...
def test_missing_evidence_contains_no_recoverable_description(): ...
def test_score_separates_recoverable_accuracy_from_safe_block_rate(): ...
def test_html_only_source_is_reported_as_not_auto_recoverable(): ...
def test_benchmark_variants_are_rule_baseline_and_recovery_agent(): ...
```

- [ ] **Step 2: Run benchmark tests and verify they fail**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_benchmark.py -q`

Expected: FAIL because existing mutations are only `id_only/empty_body` and metrics do not separate recovery from safe blocking.

- [ ] **Step 3: Implement controlled evidence mutations and metrics**

For JSON sources, remove the configured description from its known source location and preserve the exact value at `recovery_evidence.<target_field>`. For CNVD/JVN HTML-only samples, report the auto-recovery case as ineligible and retain a safe-review case. Keep the run dry: no MySQL, Milvus, review row, or durable Checkpoint.

Rename report keys from `legacy` to `baseline`; no production `hybrid/llm_full` path may be used by the baseline.

This task builds and unit-tests the benchmark contract only. Do not publish an end-to-end result yet: the current HTML extractor still contains the legacy low-confidence LLM fallback until Task 6. The real report is generated only in Task 7 after cleanup.

- [ ] **Step 4: Run Task 5 tests**

Run: `conda run -n LLFlow python -m pytest tests/test_recovery_benchmark.py -q`

Expected: all Task 5 tests PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add backened/recovery_ab.py backened/recovery_benchmark.py backened/tests/test_recovery_benchmark.py
git commit -m "test: add evidence-backed recovery benchmark"
```

### Task 6: Remove Legacy Hybrid, Full-LLM, and Reflect Paths

**Files:**
- Modify: `backened/agent/extractor.py`
- Modify: `backened/agent/cleaner_validator.py`
- Modify: `backened/agent/memory.py`
- Delete: `backened/agent/planner.py`
- Modify: `backened/graph/controller.py`
- Modify: `backened/graph/builder.py`
- Modify: `backened/graph/nodes.py`
- Modify: `backened/graph/state.py`
- Modify: `backened/main.py`
- Modify: `backened/config/agent_config.yaml`
- Modify/Delete: legacy-only tests under `backened/tests/`
- Test: `backened/tests/test_legacy_cleanup.py`

**Interfaces:**
- Consumes: Recovery Agent and HIL path from Tasks 2-3.
- Produces: one production extraction mode (deterministic rules) and one recovery mode (constrained Recovery Agent).
- Preserves: directory database prefilter, small-file-first ordering, Memory ID deduplication, failure counts, and quality statistics.

- [ ] **Step 1: Write the cleanup guard test**

Add tests named:

```python
def test_production_graph_has_no_reflect_node(): ...
def test_source_extractor_html_path_never_calls_llm_fallback(): ...
def test_directory_processing_keeps_deterministic_small_file_order(): ...
def test_memory_keeps_dedup_and_quality_without_strategy_recommendation(): ...
```

- [ ] **Step 2: Run cleanup tests before deletion**

Run: `conda run -n LLFlow python -m pytest tests/test_legacy_cleanup.py -q`

Expected: FAIL because legacy nodes and strategy code still exist.

- [ ] **Step 3: Remove the legacy extraction and reflection implementation**

Delete `reflect_node`, its Edge and routes; remove `extract_by_llm`, `merge_results`, `extract_by_strategy`, `recover_fields`, and the implicit low-confidence HTML LLM fallback. Extractor output must come only from existing deterministic source parsers.

Remove `reflection`, `field_recovery`, and `agent_loop_enabled`; `recovery.enabled` becomes the only recovery switch and defaults to `true`.

- [ ] **Step 4: Simplify Planner and Memory without removing useful behavior**

Delete `PlannerAgent` and replace its only retained behavior with deterministic size ordering in `process_directory`. Keep existing database prefilter and Memory ID deduplication. Remove strategy escalation/recommendation/effectiveness data while preserving source success/failure counts and quality history.

Remove the old CLI `--agent-recovery` flag because Recovery Agent is already controlled by YAML and enabled by default.

- [ ] **Step 5: Remove obsolete state and tests**

Remove `extraction_strategy`, `reflection_notes`, `recovery_attempted`, `recovered_fields`, and `retry_count` from `VulnProcessingState`. Delete or rewrite tests whose only purpose is the removed legacy behavior.

- [ ] **Step 6: Run cleanup and recovery suites**

Run: `conda run -n LLFlow python -m pytest tests/test_legacy_cleanup.py tests/test_recovery_agent_graph.py tests/test_recovery_regression.py -q`

Expected: all selected tests PASS.

Run: `rg -n "hybrid|llm_full|reflect_node|field_recovery|strategy_escalation" backened -g '*.py' -g '*.yaml' -g '!docs/**'`

Expected: no production-code matches; only intentionally historical test/report text may remain and should be renamed where practical.

- [ ] **Step 7: Commit Task 6**

```bash
git add -A backened
git commit -m "refactor: remove legacy LLM recovery paths"
```

### Task 7: Full Verification and Operational Documentation

**Files:**
- Modify: `backened/IMPLEMENTATION_SUMMARY.md`
- Modify: `backened/config/README.md`
- Modify: `backened/.env.example` if present
- Test: all tests under `backened/tests/`

**Interfaces:**
- Consumes all earlier tasks.
- Produces operator commands for processing, reviewing, resuming, and running the vector Worker.

- [ ] **Step 1: Update operational documentation**

Document:

```text
HIL_REVIEW_TOKEN
logs/processing_state.db
review API examples
python -m workers.vector_index_worker [--once]
outbox status and retry behavior
new recovery benchmark command and metric meanings
single-host / single-worker boundary
```

- [ ] **Step 2: Run formatting and import checks**

Run: `conda run -n LLFlow python -m compileall -q .`

Expected: exit code 0.

Run in PowerShell:

```powershell
$changed = git diff --name-only main...HEAD -- '*.py'
conda run -n LLFlow ruff check $changed
```

Expected: no lint errors in changed Python files. Existing errors in untouched files are outside this change.

- [ ] **Step 3: Run the full automated suite**

Run: `conda run -n LLFlow python -m pytest -q`

Expected: all tests PASS; pre-existing LangGraph annotation warnings may remain, but no new failure or error is accepted.

- [ ] **Step 4: Run the real six-source dry benchmark**

Run the documented `recovery_benchmark.py` command with the configured local environment.

Expected:

- all available sources appear in the report;
- eligible `layout_drift` cases report exact field recovery;
- every `missing_evidence` case reports safe `REVIEW/ABORT` with no invented Patch;
- protected ID preservation is 100%;
- no MySQL, Milvus, review table, or persistent Checkpoint write occurs.

- [ ] **Step 5: Run optional live infrastructure checks when services are reachable**

Process one known-good sample, verify a MySQL record and pending Outbox row exist, run `python -m workers.vector_index_worker --once`, then verify the Outbox row becomes `succeeded`. Create one forced review case, restart the runtime, and resume it by `task_id`.

If MySQL or Milvus is unavailable, report this check as unverified rather than fabricating success; automated tests remain mandatory.

- [ ] **Step 6: Commit Task 7**

```bash
git add backened/IMPLEMENTATION_SUMMARY.md backened/config/README.md
git commit -m "docs: document HIL and vector indexing operations"
```

- [ ] **Step 7: Verify branch state and review the complete diff**

Run:

```bash
git status --short
git log --oneline --decorate -10
git diff main...HEAD --check
git diff main...HEAD --stat
```

Expected: clean worktree, no whitespace errors, and one focused commit per completed task.
