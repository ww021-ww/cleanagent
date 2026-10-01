# cleanagent 跨电脑连接远程 MySQL 操作文档

## 1. 使用场景

你当前项目要从一台电脑迁移到另一台电脑运行，数据库放在服务器 Docker MySQL 容器中。

你的服务器 MySQL 启动参数是：

```bash
-p 0.0.0.0:33066:3306
-e MYSQL_DATABASE=shared_db
```

所以：
- 远程连接端口是 **33066**（不是 3306）
- 目标数据库是 **shared_db**

---

## 2. 架构结论（本项目）

- 前端不直接连 MySQL
- 前端只调后端 API（`frontend/src/api/client.ts`）
- 后端通过 `DB_URI` 连接数据库

因此迁移到新电脑后，核心只需要改：
1. 后端数据库连接配置 `DB_URI`
2. 前端 API 基地址（仅当后端地址变化时）

---

## 3. 服务器侧必须确认的项

### 3.1 Docker 容器状态

```bash
docker ps | grep wangchuang02_vuln_db
```

确认容器在运行，且端口映射包含 `33066->3306`。

### 3.2 账号授权（推荐新建业务账号）

进入 MySQL 后执行（示例）：

```sql
CREATE USER 'vuln_user'@'%' IDENTIFIED BY 'StrongPass123!';
GRANT ALL PRIVILEGES ON shared_db.* TO 'vuln_user'@'%';
FLUSH PRIVILEGES;
```

> 生产建议把 `%` 改成新电脑的固定公网 IP。

### 3.3 网络放行

- 云安全组放行 TCP `33066`
- 服务器防火墙放行 TCP `33066`

---

## 4. 新电脑需要改哪些位置

### 4.1 后端数据库连接（必须）

文件：`backened/config/database.env`

将 `DB_URI` 改成：

```env
DB_URI=mysql+pymysql://vuln_user:StrongPass123!@服务器IP:33066/shared_db
```

注意：
- 密码中如果有 `@`，写成 `%40`
- 端口必须用 `33066`
- 数据库名是 `shared_db`

### 4.2 前端 API 地址（按需）

文件：`frontend/src/api/client.ts`

只有当“新电脑上后端地址/端口变了”才需要改。

例如：
- 本地开发：`http://127.0.0.1:8000`
- 局域网访问：`http://新电脑IP:8000`

> 如果你仍在新电脑本机同时跑前后端，通常不用改。

### 4.3 启动后端（必须重启）

```bash
python main.py
# 或
uvicorn api.app:app --reload
```

---

## 5. 迁移后快速验证

按顺序检查：

1. 列表页能查到数据
2. 漏洞详情可打开
3. CVSS 页签有数据
   - CVE 用 `t_cve_metrics`
   - NVD 用 `t_nvd_metrics`

如果详情有但 CVSS 空：
- 确认远程库中子表有该 `cve_id`
- 确认后端已重启并加载新 `DB_URI`

---

## 6. 一键回滚到本地库

只改 `DB_URI`：

```env
DB_URI=mysql+pymysql://root:本地密码@127.0.0.1:3306/vuln_db1
```

然后重启后端。

---

## 7. 新电脑迁移清单（建议照顺序）

1. 拷贝项目代码到新电脑
2. 安装依赖（后端/前端）
3. 修改 `backened/config/database.env` 的 `DB_URI`
4. 检查 `frontend/src/api/client.ts` 是否需要改 API 地址
5. 启动后端，确认日志无数据库连接报错
6. 启动前端，打开页面验证列表/详情/CVSS

---

## 8. 你当前项目最常改的两个文件

1. `backened/config/database.env`（改远程数据库连接）
2. `frontend/src/api/client.ts`（仅在后端地址变化时改）

其余代码一般不需要修改。

---

## 9. 常见错误与修复

### 错误 1：`Access denied for user`

原因：账号权限不对或来源 IP 未授权。

处理：重新授权该用户到 `shared_db`，或改成固定 IP 授权。

### 错误 2：`Can't connect to MySQL server`

原因：端口/防火墙/安全组未放行。

处理：确认目标端口是 `33066`，并检查网络放行。

### 错误 3：连上了但页面没数据

原因：连到了错误数据库名，或库里没表/没数据。

处理：确认 DB 是 `shared_db`，并检查关键表是否存在：
- `t_cve_main`
- `t_cve_metrics`
- `t_nvd_main`
- `t_nvd_metrics`

### 错误 4：列表有数据但 CVSS 为空

原因：对应子表记录不存在或后端未重启。

处理：检查 `t_cve_metrics/t_nvd_metrics` 是否有该 `cve_id`，并重启后端。
