# 多智能体系统配置指南

## 配置文件说明

### 1. 环境变量配置（推荐）

**文件位置：**
- `multiagent/config/.env` （本地配置，优先级最高）
- 或使用项目根目录的 `.env` （全局配置）

**创建步骤：**

```bash
# 方式1：在 multiagent/config/ 目录下创建
cd multiagent/config/
cp .env.example .env

# 方式2：使用项目根目录的 .env（推荐）
# 直接编辑项目根目录的 .env 文件即可
```

**必填配置：**

```bash
# LLM配置（必填）
OPENAI_API_KEY=your-api-key-here

# 如果使用本地部署的大模型
OPENAI_API_BASE=http://localhost:8000/v1

# 数据库配置（必填）
DB_URI=mysql+pymysql://root:password@localhost/vuln_db1
```

**可选配置：**

```bash
# 模型配置
DEFAULT_LLM_MODEL=gpt-4o-mini
LLM_TEMPERATURE=0

# 性能配置
MAX_WORKERS=4
STORAGE_BATCH_SIZE=50

# 功能开关
ENABLE_ENRICHMENT=false
```

### 2. YAML配置文件

#### agent_config.yaml
智能体系统配置，包含：
- 智能体启用/禁用
- 超时时间
- 批量大小
- 日志配置

**注意：** 敏感信息（API Key、数据库密码）不要写在此文件中，请使用环境变量。

#### field_mappings.yaml
字段映射配置，定义6个漏洞库的字段提取规则：
- CVE
- NVD
- CNVD
- CISA
- CERT
- JVN

## 配置优先级

```
命令行参数 > 环境变量 > agent_config.yaml > 默认值
```

## 快速开始

### 步骤1：配置环境变量

```bash
# 复制示例文件
cp multiagent/config/.env.example multiagent/config/.env

# 编辑配置文件
vim multiagent/config/.env
```

最少需要配置：
```bash
OPENAI_API_KEY=sk-your-key-here
DB_URI=mysql+pymysql://root:password@localhost/vuln_db1
```

### 步骤2：测试配置

```bash
# 测试环境变量加载
python multiagent/config/env_loader.py

# 测试系统
python multiagent/test_system.py
```

### 步骤3：运行系统

```bash
# 处理单个文件
python multiagent/main.py --file html/cnvd/2024/CNVD-2024-12345.html

# 处理整个目录
python multiagent/main.py --directory html/cnvd/2024/
```

## 配置示例

### 个人使用（小规模数据）

```bash
# .env 文件
OPENAI_API_KEY=your-key
OPENAI_API_BASE=http://localhost:8000/v1
DB_URI=mysql+pymysql://root:password@localhost/vuln_db1

MAX_WORKERS=2
STORAGE_BATCH_SIZE=20
ENABLE_ENRICHMENT=false
```

### 公司使用（中等规模数据）

```bash
# .env 文件
OPENAI_API_KEY=your-key
OPENAI_API_BASE=http://your-company-llm.com/v1
DB_URI=mysql+pymysql://user:password@db-server/vuln_db1

MAX_WORKERS=4
STORAGE_BATCH_SIZE=50
ENABLE_ENRICHMENT=false
QUALITY_THRESHOLD=0.7
```

### 高性能处理（大规模数据）

```bash
# .env 文件
OPENAI_API_KEY=your-key
OPENAI_API_BASE=http://your-company-llm.com/v1
DB_URI=mysql+pymysql://user:password@db-server/vuln_db1

MAX_WORKERS=8
STORAGE_BATCH_SIZE=100
ENABLE_ENRICHMENT=false
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
```

## 使用Python代码加载配置

```python
from multiagent.config import load_config_from_env, get_env_loader

# 方式1：加载所有配置
config = load_config_from_env()
print(config['llm'])
print(config['db'])
print(config['agents'])

# 方式2：使用配置加载器
loader = get_env_loader()
llm_config = loader.get_llm_config()
db_config = loader.get_db_config()
agent_config = loader.get_agent_config()

# 方式3：获取单个配置项
api_key = loader.get('OPENAI_API_KEY')
max_workers = loader.get('MAX_WORKERS', 4, int)
enable_enrichment = loader.get('ENABLE_ENRICHMENT', False, bool)
```

## 配置项说明

### LLM配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| OPENAI_API_KEY | API密钥（必填） | - | sk-xxx |
| OPENAI_API_BASE | API地址 | - | http://localhost:8000/v1 |
| DEFAULT_LLM_MODEL | 模型名称 | gpt-4o-mini | gpt-4 |
| LLM_TEMPERATURE | 温度参数 | 0 | 0-2 |
| MAX_RETRIES | 最大重试次数 | 2 | 3 |

### 数据库配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| DB_URI | 数据库URI（必填） | - | mysql+pymysql://... |
| DB_POOL_SIZE | 连接池大小 | 10 | 20 |
| DB_MAX_OVERFLOW | 最大溢出 | 20 | 40 |

### 智能体配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| EXTRACTOR_TIMEOUT | 提取超时（秒） | 30 | 60 |
| QUALITY_THRESHOLD | 质量阈值 | 0.7 | 0.8 |
| ENABLE_ENRICHMENT | 启用增强 | false | true |
| STORAGE_BATCH_SIZE | 批量大小 | 50 | 100 |
| STORAGE_TIMEOUT | 存储超时（秒） | 60 | 120 |

### 处理配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| MAX_WORKERS | 最大并发数 | 4 | 8 |
| TASK_TIMEOUT | 任务超时（秒） | 3600 | 7200 |
| ENABLE_CHECKPOINT | 启用断点续传 | true | false |
| CHECKPOINT_FILE | 检查点文件 | progress.json | checkpoint.json |

### 日志配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| LOG_LEVEL | 日志级别 | INFO | DEBUG |
| LOG_FILE | 日志文件 | logs/multiagent.log | app.log |
| LOG_CONSOLE | 控制台输出 | true | false |

### 性能配置

| 环境变量 | 说明 | 默认值 | 示例 |
|---------|------|--------|------|
| QUEUE_TIMEOUT | 队列超时（秒） | 30 | 60 |
| BATCH_INTERVAL | 批处理间隔（秒） | 5 | 10 |
| MAX_HTML_LENGTH | HTML最大长度 | 8000 | 10000 |
| MAX_DESCRIPTION_LENGTH | 描述最大长度 | 2000 | 3000 |
| MAX_REFERENCES | 最大参考链接数 | 10 | 20 |

## 常见问题

### Q1: 配置文件放在哪里？

**A:** 有两个选择：
1. `multiagent/config/.env` - 多智能体系统专用配置
2. 项目根目录 `.env` - 全局配置（推荐）

系统会自动按优先级查找：指定文件 > multiagent/config/.env > 根目录.env

### Q2: 如何使用本地部署的大模型？

**A:** 在 `.env` 文件中配置：
```bash
OPENAI_API_KEY=your-local-key
OPENAI_API_BASE=http://localhost:8000/v1
DEFAULT_LLM_MODEL=your-model-name
```

### Q3: 如何提高处理速度？

**A:** 调整以下参数：
```bash
MAX_WORKERS=8              # 增加并发数
STORAGE_BATCH_SIZE=100     # 增加批量大小
ENABLE_ENRICHMENT=false    # 关闭增强功能
```

### Q4: 数据质量不好怎么办？

**A:** 调整质量阈值：
```bash
QUALITY_THRESHOLD=0.8      # 提高质量要求（0-1）
```

### Q5: 如何启用数据增强？

**A:** 在 `.env` 文件中设置：
```bash
ENABLE_ENRICHMENT=true
```

注意：启用增强会显著增加处理时间（约2-3倍）。

## 安全提示

1. ⚠️ **不要将 .env 文件提交到 Git**
   - 已在 `.gitignore` 中排除
   - 包含敏感信息（API Key、数据库密码）

2. ⚠️ **不要在 agent_config.yaml 中写明文密码**
   - 使用环境变量代替
   - YAML文件可以提交到Git

3. ⚠️ **定期更换API Key**
   - 建议每3-6个月更换一次
   - 发现泄露立即更换

4. ⚠️ **限制文件访问权限**
   ```bash
   chmod 600 .env
   ```

## 更多帮助

- 查看完整文档：`multiagent/README.md`
- 查看设计方案：`FIELD_MAPPING_DESIGN_V2.md`
- 运行测试：`python multiagent/test_system.py`
- 查看示例：`multiagent/config/.env.example`
