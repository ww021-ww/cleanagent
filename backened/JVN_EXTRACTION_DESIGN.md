# JVN HTML 提取设计方案 v2.0

## 概述

基于实际 JVN HTML 文件分析，本文档详细说明 JVN 漏洞数据从 HTML 提取到 MySQL 字段的完整映射关系，包括新增字段 `supplement_information` 和 `revision_history`。

---

## 1. 基本信息提取

| MySQL 字段 | 数据类型 | HTML 位置 | 提取方法 | 示例 |
|-----------|---------|---------|--------|------|
| `jvn_number` | string(50) | `<h1 class="h1ver2">` 第一行 | 正则提取第一行文本 | `JVN#61857DA9` / `CPNI-957037` |
| `title` | string(500) | `<h1 class="h1ver2">` 第二行 | 正则提取第二行文本 | `DNSキャッシュサーバのTCP SYN_SENT 状態によるリソース消費` |
| `published_date` | datetime | `<span class="margin-lb">` | 正则 `公開日[：:](\d{4}/\d{2}/\d{2})` | `2004-10-20` |
| `last_updated` | datetime | `<span class="margin-lb">` | 正则 `最終更新日[：:](\d{4}/\d{2}/\d{2})` | `2005-10-04` |

---

## 2. 内容区块提取（按 img alt 属性定位）

### 2.1 基础内容区块

| MySQL 字段 | img alt 关键词 | HTML 结构 | 提取逻辑 |
|-----------|--------------|---------|--------|
| `overview` | `概要` | `<img alt="概要">` → 父 textbox → `<h2>` 后的 `<p>` | 收集所有 `<p>` 文本，用 `\n\n` 连接 |
| `Affected Systems/Products` | `影響を受けるシステム` | `<img alt="影響を受けるシステム">` → 父 textbox | 收集 `<p>` 和 `<ul>` 文本 |
| `description` | `詳細情報` | `<img alt="詳細情報">` → 父 textbox | 收集 `<p>` 文本（不含 CVSS 表） |
| `impact` | `想定される影響` | `<img alt="想定される影響">` → 父 textbox | 收集 `<p>` 文本 |
| `solutions` | `対策方法` | `<img alt="対策方法">` → 父 textbox | 收集 `<p>` 和 `<h4>` 文本 |
| `supplement_information` | `JPCERT/CCからの補足情報` | `<img alt="JPCERT/CCからの補足情報">` → 父 textbox | 收集 `<p>` 文本（新增字段） |

### 2.2 修订历史提取（新增）

| MySQL 字段 | img alt 关键词 | HTML 结构 | 提取逻辑 |
|-----------|--------------|---------|--------|
| `revision_history` | `更新履歴` | `<img alt="更新履歴">` → 父 textbox → `<dl>` | 收集所有 `<dt>` 和 `<dd>` 对，格式：`日期: 内容` |

**HTML 示例（JVN-16767117.html）：**
```html
<div class="textbox">
  <h2><img src="/img/m_rireki.gif" alt="更新履歴" /></h2>
  <dl>
    <dt>2009/02/23</dt>
    <dd>参考情報に IPA 注意喚起を追記しました。</dd>
    <dt>2009/03/09</dt>
    <dd>ソニー株式会社の JVN#16767117への対応が更新されました。</dd>
  </dl>
</div>
```

**提取结果：**
```
2009/02/23: 参考情報に IPA 注意喚起を追記しました。
2009/03/09: ソニー株式会社の JVN#16767117への対応が更新されました。
```

---

## 3. CVSS 评分提取

### 3.1 CVSS v3 提取（新版本 HTML）

**HTML 位置：** `JPCERT/CCによる脆弱性分析結果` 区块内的 `<div class="cvss-wrapper">`

**结构示例（JVN-00014057(1).html）：**
```html
<div class="cvss-wrapper">
  <div id="cvss-v3-line" class="cvss-line">
    <span class="cvss-version">CVSS v3</span>
    <span id="cvss-v3-vector-string" class="cvss-vector-string">CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</span>
    <div class="cvss-right-elem clearfix">
      <div class="base-score">
        <span class="base-score-label">基本値:</span>
        <span id="cvss-v3-base-score">4.8</span>
      </div>
    </div>
  </div>
  <table id="cvss-v3-table" class="cvss-table">
    <tr>
      <th>攻撃元区分(AV)</th>
      <td class="selected">ネットワーク (N)</td>
    </tr>
    <!-- ... 其他行 ... -->
  </table>
</div>
```

| MySQL 字段 | 提取方法 | 示例 |
|-----------|--------|------|
| `cvss_v3_base_score` | 从 `<span id="cvss-v3-base-score">` 提取 | `4.8` |
| `cvss_v3_attackvector` | 从向量字符串 `AV:N` 解析，展开缩写 | `Network` |
| `cvss_v3_attackcomplexity` | 从向量字符串 `AC:H` 解析，展开缩写 | `High` |
| `cvss_v3_privilegesrequired` | 从向量字符串 `PR:N` 解析，展开缩写 | `None` |
| `cvss_v3_uesrinteraction` | 从向量字符串 `UI:N` 解析，展开缩写 | `None` |
| `cvss_v3_scope` | 从向量字符串 `S:U` 解析，展开缩写 | `Unchanged` |
| `cvss_v3_confidentialityimpact` | 从向量字符串 `C:L` 解析，展开缩写 | `Low` |
| `cvss_v3_integrityimpact` | 从向量字符串 `I:L` 解析，展开缩写 | `Low` |
| `cvss_v3_availabilityimpact` | 从向量字符串 `A:N` 解析，展开缩写 | `None` |

### 3.2 CVSS v2 提取

#### 新版本（JVN-00014057(1).html）

**HTML 位置：** `JPCERT/CCによる脆弱性分析結果` 区块内的 `<div class="cvss-wrapper">` (第二个)

```html
<div class="cvss-wrapper">
  <div id="cvss-v2-line" class="cvss-line">
    <span class="cvss-version">CVSS v2</span>
    <span id="cvss-v2-vector-string" class="cvss-vector-string">AV:N/AC:H/Au:N/C:P/I:P/A:N</span>
    <div class="base-score">
      <span id="cvss-v2-base-score">4.0</span>
    </div>
  </div>
  <table id="cvss-v2-table" class="cvss-table">
    <tr>
      <th>攻撃元区分(AV)</th>
      <td class="selected">ネットワーク (N)</td>
    </tr>
    <!-- ... 其他行 ... -->
  </table>
</div>
```

| MySQL 字段 | 提取方法 | 示例 |
|-----------|--------|------|
| `cvss_v2_base_score` | 从 `<span id="cvss-v2-base-score">` 提取 | `4.0` |
| `cvss_v2_accessvector` | 从向量字符串 `AV:N` 解析，展开缩写 | `Network` |
| `cvss_v2_accesscomplexity` | 从向量字符串 `AC:H` 解析，展开缩写 | `High` |
| `cvss_v2_authentication` | 从向量字符串 `Au:N` 解析，展开缩写 | `None` |
| `cvss_v2_confidentialityimpact` | 从向量字符串 `C:P` 解析，展开缩写 | `Partial` |
| `cvss_v2_integrityimpact` | 从向量字符串 `I:P` 解析，展开缩写 | `Partial` |
| `cvss_v2_availabilityimpact` | 从向量字符串 `A:N` 解析，展开缩写 | `None` |

#### 旧版本（JVN-07677464.html）

**HTML 位置：** `JPCERT/CCによる脆弱性分析結果` 区块内的 `<table class="tbl-result">`

```html
<table border="0" cellspacing="1" cellpadding="0" width="100%">
  <tr>
    <th>攻撃元区分(AV)</th>
    <td class="cvss_v2_selected">ネットワーク (N)</td>
  </tr>
  <!-- ... 其他行 ... -->
</table>
<p style="font-weight: bold">Base Score:2.6</p>
```

| MySQL 字段 | 提取方法 | 示例 |
|-----------|--------|------|
| `cvss_v2_base_score` | 正则 `Base Score[:\s]*([\d.]+)` | `2.6` |
| `cvss_v2_accessvector` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `N` |
| `cvss_v2_accesscomplexity` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `H` |
| `cvss_v2_authentication` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `N` |
| `cvss_v2_confidentialityimpact` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `P` |
| `cvss_v2_integrityimpact` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `N` |
| `cvss_v2_availabilityimpact` | 从 `<td class="cvss_v2_selected">` 提取括号内缩写 | `N` |

**缩写展开映射（v2）：**
```python
{
  'AV': {'L': 'Local', 'A': 'Adjacent', 'N': 'Network'},
  'AC': {'H': 'High', 'M': 'Medium', 'L': 'Low'},
  'Au': {'M': 'Multiple', 'S': 'Single', 'N': 'None'},
  'C':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
  'I':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
  'A':  {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
}
```

---

## 4. 参考信息提取（修订）

### 4.1 参考情报链接提取

**HTML 位置：** `<img alt="参考情報">` 区块内的 `<ol class='list1'>` 或 `<table class='style_table'>`

**结构示例（JVN-61857DA9.html）：**
```html
<div class="textbox">
  <h2><img src="/img/m_sanko.gif" alt="参考情報" /></h2>
  <ol class='list1' style='padding-left:16px;margin-left:16px'>
    <li>
      <a href="http://www.nanog.org/mtg-0410/pdf/toyama.pdf" target="_top">NANOG PDF presentation</a><br />
      DNS Anomalies and Their Impacts on DNS Cache Servers
    </li>
    <li>
      <a href="http://www.nanog.org/mtg-0410/toyama.html" target="_top">NANOG Abstract</a><br />
      DNS Anomalies and Their Impacts on DNS Cache Servers
    </li>
  </ol>
</div>
```

| MySQL 字段 | 提取方法 | 示例 |
|-----------|--------|------|
| `reference_name` | 收集所有 `<a>` 的文本内容，用 ` \| ` 连接 | `NANOG PDF presentation \| NANOG Abstract \| IPA 脆弱性関連情報の調査結果` |
| `reference_url` | 收集所有 `<a>` 的 `href` 属性，用 ` \| ` 连接 | `http://www.nanog.org/mtg-0410/pdf/toyama.pdf \| http://www.nanog.org/mtg-0410/toyama.html \| ...` |

**提取逻辑：**
1. 定位 `alt="参考情報"` 的 `<img>` 标签
2. 获取其父 `<div class="textbox">`
3. 查找 `<ol class='list1'>` 或 `<table class='style_table'>`
4. 遍历所有 `<a>` 标签
5. 提取 `<a>` 的文本和 `href` 属性
6. 用 ` | ` 分隔符连接多个值

---

## 5. 代码修改位置

### 5.1 新增方法：`_extract_revision_history`

**文件：** `agent/extractor.py`

**位置：** 在 `_extract_jvn_from_html` 方法中，添加新方法用于提取修订历史

**代码位置：** 约在第 350-400 行（在 `_parse_cvss_v3_vector` 方法之前）

### 5.2 修改方法：`_extract_jvn_from_html`

**文件：** `agent/extractor.py`

**修改内容：**

1. **新增 supplement_information 提取** （约第 280-290 行）
   - 替换原有的 `comment` 字段提取
   - 使用 `alt="JPCERT/CCからの補足情報"` 定位

2. **新增 revision_history 提取** （约第 290-310 行）
   - 在 supplement_information 之后添加
   - 使用 `alt="更新履歴"` 定位
   - 调用新增的 `_extract_revision_history` 方法

3. **修改 reference_name 和 reference_url 提取** （约第 310-340 行）
   - 改为收集所有参考链接，而不仅仅是第一个
   - 用 ` | ` 分隔符连接多个值

4. **CVSS v2 提取逻辑优化** （约第 200-250 行）
   - 支持新版本的 `<div class="cvss-wrapper">` 结构
   - 支持旧版本的 `<table class="tbl-result">` 结构
   - 自动检测并选择合适的提取方法

### 5.3 新增方法：`_parse_cvss_v2_vector`

**文件：** `agent/extractor.py`

**位置：** 在 `_parse_cvss_v3_vector` 方法之后

**功能：** 解析 CVSS v2 向量字符串，展开缩写

---

## 6. 字段映射总结

### 6.1 新增 MySQL 字段

| 字段名 | 数据类型 | 来源 | 说明 |
|-------|---------|------|------|
| `supplement_information` | TEXT | `alt="JPCERT/CCからの補足情報"` | 替代原有的 `comment` 字段 |
| `revision_history` | TEXT | `alt="更新履歴"` | 新增字段，记录修订历史 |

### 6.2 修改的字段

| 字段名 | 原逻辑 | 新逻辑 | 说明 |
|-------|-------|-------|------|
| `reference_name` | 仅第一个 CVE | 所有参考链接文本 | 用 ` \| ` 连接多个值 |
| `reference_url` | 仅第一个 CVE URL | 所有参考链接 URL | 用 ` \| ` 连接多个值 |
| `comment` | 保留 | 删除 | 改用 `supplement_information` |

---

## 7. 提取流程图（更新版）

```
JVN HTML 文件
    ↓
1. 从 <h1 class="h1ver2"> 提取 jvn_number 和 title
    ↓
2. 从 <span class="margin-lb"> 提取 published_date 和 last_updated
    ↓
3. 按 img alt 属性定位各内容区块：
   ├─ 概要 → overview
   ├─ 影響を受けるシステム → Affected Systems/Products
   ├─ 詳細情報 → description + CVSS v3 表格
   ├─ 想定される影響 → impact
   ├─ 対策方法 → solutions
   ├─ JPCERT/CCからの補足情報 → supplement_information (新增)
   ├─ JPCERT/CCによる脆弱性分析結果 → CVSS v2/v3 表格
   ├─ ベンダ情報 → vendor_name, vendor_status, vendor_url, vendor_lastupdateddate
   ├─ 参考情報 → reference_name, reference_url (修改为收集所有)
   └─ 更新履歴 → revision_history (新增)
    ↓
4. 解析 CVSS v3 向量字符串，展开缩写
    ↓
5. 解析 CVSS v2 向量字符串，展开缩写（支持新旧版本）
    ↓
6. 返回完整的 MySQL 字段字典
```

---

## 8. 实现注意事项

1. **向后兼容性**：支持旧版本 HTML（仅 CVSS v2）和新版本 HTML（CVSS v2 + v3）
2. **多值字段**：使用 ` | ` 作为分隔符连接多个值
3. **日期格式**：统一转换为 `YYYY-MM-DD` 格式
4. **空值处理**：保留原始值，只过滤 `None`
5. **缩写展开**：使用映射表将单字母缩写转换为完整英文名称

---

## 9. 测试用例

| 文件 | 版本 | 特点 |
|------|------|------|
| `JVN-61857DA9.html` | 旧版本 | 仅有基础内容，无 CVSS 表 |
| `JVN-07677464.html` | 旧版本 | 有 CVSS v2 表格（旧格式） |
| `JVN-16767117.html` | 旧版本 | 有修订历史，有参考信息 |
| `JVN-00014057(1).html` | 新版本 | 有 CVSS v2 + v3 新格式，有修订历史 |


