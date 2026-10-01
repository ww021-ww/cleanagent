# 配置文件对比说明

## .env.example vs agent_config.yaml

### 核心区别

| 特性 | .env.example | agent_config.yaml |
|------|-------------|-------------------|
| **用途** | 敏感信息和环境配置 | 业务逻辑和系统行为 |
| **是否提交Git** | ❌ 不提交（.gitignore） | ✅ 可以提交 |
| **是否包含密码** | ✅ 是（API Key、DB密码） | ❌ 否 |
| **环境差异** | ✅ 开发/测试/生产不同 | ✅ 通常相同 |
| **格式** | KEY=VALUE | YAML结构化 |
| **优先级** | 高（覆盖YAML） | 低（被环境变量覆盖） |

---

## 配置项分类

### 🔐 应该放在 .env 中的配置（敏感信息）

```bash
# ❌ 不要提交到Git
# ✅ 每个环境不同

# API密钥
OPENAI_API_KEY=sk-your-secret-key

# 数据库密码
DB_URI=mysql+pymysql://user:PASSWORD@localhost/db

# 服务器地址（可能不同）
OPENAI_API_BASE=http://localhost:8000/v1
```

### 📝 应该放在 agent_config.yaml 中的配置（业务逻辑）

```yaml
# ✅ 可以提交到Git
# ✅ 所有环境通用

agents:
  extractor:
    enabled: true
    timeout: 30
  
  cleaner_validator:
    quality_threshold: 0.7
  
  storage:
    batch_size: 50

processing:
  max_workers: 4
  
logging:
  level: INFO
```

---

## 详细配置项对比

### LLM配置

| 配置项 | .env | agent_config.yaml | 说明 |
|-------|------|-------------------|------|
| API Key | ✅ OPENAI_API_KEY | ❌ | 敏感信息，必须在.env |
| API Base | ✅ OPENAI_API_BASE | ❌ | 服务器地址，可能不同 |
| 模型名称 | ✅ DEFAULT_LLM_MODEL | ✅ llm_config.model | 两处都可以，.env优先 |
| 温度参数 | ✅ LLM_TEMPERATURE | ✅ llm_config.temperature | 两处都可以，.env优先 |

**推荐做法：**
```bash
# .env - 敏感信息
OPENAI_API_KEY=sk-xxx
OPENAI_API_BASE=http://localhost:8000/v1
```

```yaml
# agent_config.yaml - 默认值
llm_config:
  model: gpt-4o-mini
  temperature: 0
```

### 数据库配置

| 配置项 | .env | agent_config.yaml | 说明 |
|-------|------|-------------------|------|
| 数据库URI | ✅ DB_URI | ❌ | 包含密码，必须在.env |
| 连接池大小 | ✅ DB_POOL_SIZE | ❌ | 性能参数，建议.env |
| 最大溢出 | ✅ DB_MAX_OVERFLOW | ❌ | 性能参数，建议.env |

**推荐做法：**
```bash
# .env - 包含密码
DB_URI=mysql+pymysql://user:PASSWORD@localhost/vuln_db1
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
```

```yaml
# agent_config.yaml - 占位符（不使用）
db_uri: ${DB_URI:mysql+pymysql://user:password@localhost/vuln_db1}
```

### 智能体配置

| 配置项 | .env | agent_config.yaml | 说明 |
|-------|------|-------------------|------|
| 启用/禁用 | ❌ | ✅ agents.*.enabled | 业务逻辑 |
| 超时时间 | ✅ *_TIMEOUT | ✅ agents.*.timeout | 两处都可以 |
| 质量阈值 | ✅ QUALITY_THRESHOLD | ✅ quality_threshold | 两处都可以 |
| 批量大小 | ✅ STORAGE_BATCH_SIZE | ✅ batch_size | 两处都可以 |

**推荐做法：**
```bash
# .env - 环境相关的性能参数
EXTRACTOR_TIMEOUT=30
QUALITY_THRESHOLD=0.7
STORAGE_BATCH_SIZE=50
ENABLE_ENRICHMENT=false
```

```yaml
# agent_config.yaml - 业务逻辑和默认值
agents:
  extractor:
    enabled: true
    timeout: 30  # 默认值，会被.env覆盖
  
  cleaner_validator:
    enabled: true
    quality_threshold: 0.7  # 默认值
  
  enrichment:
    enabled: false  # 默认值
  
  storage:
    enabled: true
    batch_size: 50  # 默认值
```

### 处理配置

| 配置项 | .env | agent_config.yaml | 说明 |
|-------|------|-------------------|------|
| 最大并发数 | ✅ MAX_WORKERS | ✅ max_workers | 两处都可以 |
| 任务超时 | ✅ TASK_TIMEOUT | ✅ timeout | 两处都可以 |
| 断点续传 | ✅ ENABLE_CHECKPOINT | ✅ enable_checkpoint | 两处都可以 |
| 检查点文件 | ✅ CHECKPOINT_FILE | ✅ checkpoint_file | 两处都可以 |

**推荐做法：**
```bash
# .env - 环境相关的性能参数
MAX_WORKERS=4
TASK_TIMEOUT=3600
```

```yaml
# agent_config.yaml - 默认值和业务逻辑
processing:
  max_workers: 4  # 默认值
  timeout: 3600  # 默认值
  enable_checkpoint: true
  checkpoint_file: progress.json
```

### 日志配置

| 配置项 | .env | agent_config.yaml | 说明 |
|-------|------|-------------------|------|
| 日志级别 | ✅ LOG_LEVEL | ✅ level | 两处都可以 |
| 日志文件 | ✅ LOG_FILE | ✅ file | 两处都可以 |
| 控制台输出 | ✅ LOG_CONSOLE | ✅ console | 两处都可以 |
| 日志格式 | ❌ | ✅ format | 业务逻辑 |

**推荐做法：**
```bash
# .env - 环境相关
LOG_LEVEL=INFO  # 开发环境用DEBUG，生产用INFO
LOG_FILE=logs/multiagent.log
```

```yaml
# agent_config.yaml - 格式定义
logging:
  level: INFO  # 默认值
  file: logs/multiagent.log  # 默认值
  console: true
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
```

---

## 使用场景示例

### 场景1：开发环境

```bash
# .env (开发环境)
OPENAI_API_KEY=sk-dev-key
OPENAI_API_BASE=http://localhost:8000/v1
DB_URI=mysql+pymysql://root:dev123@localhost/vuln_dev
MAX_WORKERS=2
LOG_LEVEL=DEBUG
ENABLE_ENRICHMENT=true
```

```yaml
# agent_config.yaml (所有环境通用)
agents:
  extractor:
    enabled: true
  cleaner_validator:
    enabled: true
    quality_threshold: 0.7
  enrichment:
    enabled: false  # 会被.env的ENABLE_ENRICHMENT覆盖
  storage:
    enabled: true
    batch_size: 50
```

### 场景2：生产环境

```bash
# .env (生产环境)
OPENAI_API_KEY=sk-prod-key
OPENAI_API_BASE=http://company-llm.com/v1
DB_URI=mysql+pymysql://prod_user:prod_pass@db-server/vuln_prod
MAX_WORKERS=8
LOG_LEVEL=INFO
ENABLE_ENRICHMENT=false
STORAGE_BATCH_SIZE=100
```

```yaml
# agent_config.yaml (相同，不需要修改)
agents:
  extractor:
    enabled: true
  cleaner_validator:
    enabled: true
    quality_threshold: 0.7
  enrichment:
    enabled: false
  storage:
    enabled: true
    batch_size: 50  # 会被.env的STORAGE_BATCH_SIZE覆盖
```

---

## 最佳实践

### ✅ 推荐的配置方式

1. **敏感信息 → .env**
   ```bash
   OPENAI_API_KEY=sk-xxx
   DB_URI=mysql+pymysql://user:PASSWORD@host/db
   ```

2. **性能参数 → .env**
   ```bash
   MAX_WORKERS=4
   STORAGE_BATCH_SIZE=50
   ```

3. **业务逻辑 → agent_config.yaml**
   ```yaml
   agents:
     extractor:
       enabled: true
     cleaner_validator:
       quality_threshold: 0.7
   ```

4. **默认值 → agent_config.yaml**
   ```yaml
   processing:
     max_workers: 4  # 默认值，可被.env覆盖
     timeout: 3600
   ```

### ❌ 不推荐的做法

1. **不要在 agent_config.yaml 中写密码**
   ```yaml
   # ❌ 错误
   db_uri: mysql+pymysql://user:password123@localhost/db
   
   # ✅ 正确
   db_uri: ${DB_URI}  # 从环境变量读取
   ```

2. **不要在 .env 中写业务逻辑**
   ```bash
   # ❌ 不推荐（虽然可以工作）
   EXTRACTOR_ENABLED=true
   CLEANER_ENABLED=true
   
   # ✅ 推荐在 agent_config.yaml 中配置
   ```

3. **不要重复配置**
   ```bash
   # .env
   MAX_WORKERS=4
   ```
   
   ```yaml
   # agent_config.yaml
   processing:
     max_workers: 8  # ❌ 会被.env覆盖，造成混淆
   ```

---

## 配置加载流程

```
1. 加载 agent_config.yaml (默认值)
   ↓
2. 加载 .env 文件 (覆盖YAML中的值)
   ↓
3. 读取命令行参数 (最高优先级)
   ↓
4. 最终配置
```

**示例：**

```yaml
# agent_config.yaml
processing:
  max_workers: 4
```

```bash
# .env
MAX_WORKERS=8
```

```bash
# 命令行
python main.py --workers 16
```

**结果：** `max_workers = 16` (命令行优先级最高)

---

## 总结

### .env.example 的作用
- ✅ 存储敏感信息（API Key、密码）
- ✅ 存储环境相关配置（服务器地址、性能参数）
- ✅ 每个环境可以不同
- ❌ 不提交到Git

### agent_config.yaml 的作用
- ✅ 存储业务逻辑配置（启用/禁用功能）
- ✅ 存储默认值
- ✅ 提供结构化配置
- ✅ 可以提交到Git

### 它们不是重复的
- **互补关系**：.env 处理敏感信息，YAML 处理业务逻辑
- **优先级关系**：.env 可以覆盖 YAML 中的值
- **分工明确**：敏感信息用 .env，业务配置用 YAML

---

## 快速决策指南

**问自己：**

1. 这个配置包含密码或密钥吗？
   - ✅ 是 → 放在 .env
   - ❌ 否 → 继续下一步

2. 这个配置在不同环境中会不同吗？
   - ✅ 是 → 放在 .env
   - ❌ 否 → 继续下一步

3. 这个配置是业务逻辑还是性能参数？
   - 业务逻辑 → 放在 agent_config.yaml
   - 性能参数 → 两处都可以，建议 .env

4. 不确定？
   - 默认放在 .env（更安全，更灵活）
