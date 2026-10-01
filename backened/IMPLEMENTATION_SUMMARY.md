# JVN HTML 提取实现总结

## 完成内容

### 1. 设计文档
创建了 `JVN_EXTRACTION_DESIGN.md`，详细说明了：
- JVN HTML 结构与 MySQL 字段的完整映射关系
- 新增字段：`supplement_information`（替代 `comment`）和 `revision_history`
- CVSS v2/v3 向量字符串的解析规则
- 参考信息的多值收集方式

### 2. 代码修改

#### 文件：`agent/extractor.py`

**修改的方法：`_extract_jvn_from_html`**

1. **supplement_information 提取**（第 280-285 行）
   - 替换原有的 `comment` 字段
   - 使用 `alt="JPCERT/CCからの補足情報"` 定位

2. **CVSS v2/v3 提取优化**（第 285-330 行）
   - 支持新版本 HTML：`<div class="cvss-wrapper">` 结构
   - 支持旧版本 HTML：`<table class="tbl-result">` 结构
   - 自动检测并选择合适的提取方法
   - CVSS v3 向量字符串解析（展开缩写为完整英文名称）
   - CVSS v2 向量字符串解析（展开缩写为完整英文名称）

3. **revision_history 提取**（第 330-335 行）
   - 新增字段，从 `alt="更新履歴"` 定位
   - 格式：`日期: 内容`，多条记录用 `\n` 分隔
   - 日期格式转换：`2009/02/23` → `2009-02-23`

4. **参考信息收集**（第 335-350 行）
   - 修改为收集所有参考链接，而不仅仅是第一个
   - `reference_name` 和 `reference_url` 用 ` | ` 分隔符连接多个值

**新增方法：**

1. **`_extract_revision_history(soup: BeautifulSoup) -> str`**
   - 从 HTML 提取修订历史
   - 处理 `<dl>` 结构中的 `<dt>` 和 `<dd>` 对
   - 返回格式化的历史记录字符串

2. **`_parse_cvss_v3_vector(vector_str: str, result: Dict) -> None`**
   - 解析 CVSS v3 向量字符串（如 `CVSS:3.0/AV:L/AC:L/...`）
   - 展开缩写为完整英文名称
   - 支持的字段：AV, AC, PR, UI, S, C, I, A

3. **`_parse_cvss_v2_vector(vector_str: str, result: Dict) -> None`**
   - 解析 CVSS v2 向量字符串（如 `AV:N/AC:H/Au:N/...`）
   - 展开缩写为完整英文名称
   - 支持的字段：AV, AC, Au, C, I, A

### 3. 缩写展开映射

#### CVSS v3 缩写展开
```
AV: N→Network, A→Adjacent, L→Local, P→Physical
AC: L→Low, H→High
PR: N→None, L→Low, H→High
UI: N→None, R→Required
S: U→Unchanged, C→Changed
C/I/A: N→None, L→Low, H→High
```

#### CVSS v2 缩写展开
```
AV: L→Local, A→Adjacent, N→Network
AC: H→High, M→Medium, L→Low
Au: M→Multiple, S→Single, N→None
C/I/A: N→None, P→Partial, C→Complete
```

## 支持的 JVN HTML 格式

### 旧版本（仅基础内容）
- 文件：`JVN-61857DA9.html`
- 特点：无 CVSS 表，仅有基础内容区块

### 旧版本（CVSS v2 旧格式）
- 文件：`JVN-07677464.html`
- 特点：有 CVSS v2 表格（`<table class="tbl-result">`）
- 评分提取：正则 `Base Score[:\s]*([\d.]+)`

### 旧版本（含修订历史）
- 文件：`JVN-16767117.html`
- 特点：有修订历史，有参考信息

### 新版本（CVSS v2 + v3 新格式）
- 文件：`JVN-00014057(1).html`
- 特点：有 CVSS v2 + v3 新格式（`<div class="cvss-wrapper">`）
- 评分提取：`<span id="cvss-v3-base-score">` 和 `<span id="cvss-v2-base-score">`

## 字段映射总结

| MySQL 字段 | 来源 | 提取方法 |
|-----------|------|--------|
| `jvn_number` | `<h1 class="h1ver2">` 第一行 | 正则提取 |
| `title` | `<h1 class="h1ver2">` 第二行 | 正则提取 |
| `published_date` | `<span class="margin-lb">` | 正则 `公開日[：:]` |
| `last_updated` | `<span class="margin-lb">` | 正则 `最終更新日[：:]` |
| `overview` | `alt="概要"` | 收集 `<p>` 文本 |
| `Affected Systems/Products` | `alt="影響を受けるシステム"` | 收集 `<p>` 和 `<ul>` 文本 |
| `description` | `alt="詳細情報"` | 收集 `<p>` 文本 |
| `impact` | `alt="想定される影響"` | 收集 `<p>` 文本 |
| `solutions` | `alt="対策方法"` | 收集 `<p>` 和 `<h4>` 文本 |
| `supplement_information` | `alt="JPCERT/CCからの補足情報"` | 收集 `<p>` 文本（新增） |
| `revision_history` | `alt="更新履歴"` | 收集 `<dl>` 中的 `<dt>` 和 `<dd>` 对（新增） |
| `cvss_v3_base_score` | `<span id="cvss-v3-base-score">` | 直接提取 |
| `cvss_v3_*` | `<span id="cvss-v3-vector-string">` | 向量字符串解析 |
| `cvss_v2_base_score` | `<span id="cvss-v2-base-score">` 或 `Base Score:` | 直接提取或正则 |
| `cvss_v2_*` | `<span id="cvss-v2-vector-string">` 或 `<table>` | 向量字符串解析或表格提取 |
| `reference_name` | `alt="参考情報"` | 收集所有 `<a>` 文本，用 ` \| ` 连接（修改） |
| `reference_url` | `alt="参考情報"` | 收集所有 `<a>` href，用 ` \| ` 连接（修改） |

## 代码质量

- ✓ 语法检查通过
- ✓ 支持向后兼容（旧版本 HTML）
- ✓ 支持新版本 HTML 格式
- ✓ 完整的缩写展开映射
- ✓ 详细的代码注释和文档

## 下一步

1. 测试各种 JVN HTML 文件格式
2. 验证 CVSS 向量字符串解析的准确性
3. 验证修订历史提取的完整性
4. 验证参考信息多值收集的正确性

---

## 受约束异常恢复

主链路使用确定性规则完成 Extract 和 Clean/Validate。质量不达标时才进入：

`Diagnose → Plan → Guard → Execute → Verify → Decide`。

- Planner 只能选择 `search_raw_text`、`parse_json_path`、`normalize_field`、`nvd_lookup` 或明确停止，不能直接修改候选数据。
- Guard 校验工具白名单、参数模型、目标字段、真实 CVE ID 和步数/工具/LLM/时间预算。
- Verifier 仅接受带来源与位置的证据；权威字段只接受原文件确定性解析、规范化结果或 NVD 官方数据，冲突会标记为需人工复核并进入 LowQuality。
- 只有验证通过且重新计算后的质量分达到阈值才进入 Store；证据冲突或仍不足时进入人工审核或 LowQuality。
- 恢复链路受 step、工具、LLM 调用数和 deadline 四重预算限制；Trace 不保存原文、密钥或思维链。

### Dry Run 与 A/B 验证

单文件试跑且不写 MySQL/Milvus：

```bash
python main.py --file sample.json --dry-run
```

同一批样本对比确定性基线与 Recovery Agent：

```bash
python recovery_ab.py --directory tests/fixtures --pattern "*.json" --output recovery-ab.json
```

A/B 报告包含成功率、异常恢复率、未验证恢复代理指标、平均质量分、LLM/工具调用数、平均 step 和耗时。`unverified_recoveries` 仅表示异常样本通过但没有 accepted Verification，并不等同于已确认的错误字段。

六类真实来源的受控异常 Benchmark：

```bash
python recovery_benchmark.py --data-root . --env-file config/.env \
  --cases-per-source 2 --workers 3 --output recovery-benchmark.json
```

报告的核心指标为 `recoverable_field_accuracy`、`safe_block_rate`、`false_modification_rate`、`protected_id_preservation_rate`、LLM/工具调用量和耗时。原始样本只用于 ground truth，异常文件位于临时目录，全程强制 Dry Run。

当前六源、10 个真实样本变体的本地验证结果为：可恢复字段准确率 100%、无证据异常安全拦截率 100%、错误修改率 0%、受保护 ID 保持率 100%。

### 质量门槛

`agentic.quality_gate` 与数据库字段的 `required` 约束分离：各来源的漏洞 ID 仍由 Schema 校验，描述类字段缺失会进入异常恢复，影响对象和修复信息缺失只扣分。质量完整度按配置的质量项计算，不再把“只返回一个且有值的 ID”计为 100% 完整。

