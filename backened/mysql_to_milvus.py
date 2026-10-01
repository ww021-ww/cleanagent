"""
MySQL → Milvus 漏洞数据迁移脚本
用途：将 MySQL 中已有的漏洞数据批量写入 Milvus 向量库，并测试 RAG 检索

运行方式：
    cd D:\\notebook\\cleanagent\\backened
    python mysql_to_milvus.py                  # 导入全部表 + 测试检索
    python mysql_to_milvus.py --test-only       # 仅测试检索（跳过导入）
    python mysql_to_milvus.py --limit 100       # 每张表只导入前 100 条
"""
import os
import sys
import argparse
import time
from pathlib import Path
from dotenv import load_dotenv

# ── 加载环境变量 ──────────────────────────────────────────────────────────────
_cfg_dir = Path(__file__).parent / "config"
for _name in ("database.env", ".env"):
    _p = _cfg_dir / _name
    if _p.exists():
        load_dotenv(_p, override=True)
        print(f"[ENV] 已加载 {_p}")
        break

# ── 路径修正（允许在任意目录运行）────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

# =============================================================================
# 各数据源的字段提取规则
#   table      : MySQL 表名
#   source     : 来源标识（写入 Milvus 的 source 字段）
#   id_cols    : 尝试作为 vuln_id 的列名（按顺序取第一个非空的）
#   text_cols  : 用于构建向量文本的列名（按顺序拼接）
# =============================================================================
SOURCE_RULES = [
    {
        "table": "t_cnvd_info",
        "source": "cnvd",
        "id_cols":   ["cnvd_id"],
        "text_cols": ["description", "severity", "products",
                      "vulnerabilitiestype", "solutions", "cveid"],
    },
    {
        "table": "t_cve_main",
        "source": "cve",
        "id_cols":   ["cveMetadata_cveId"],
        "text_cols": ["containers_cna_title", "containers_cna_descriptions_value",
                      "containers_cna_affected_product", "containers_cna_affected_vendor"],
    },
    {
        "table": "t_nvd_main",
        "source": "nvd",
        "id_cols":   ["cve_id"],
        "text_cols": ["descriptions_value", "vuln_status", "source_identifier"],
    },
    {
        "table": "t_cisa_info",
        "source": "cisa",
        "id_cols":   ["cveID"],
        "text_cols": ["vulnerabilityName", "shortDescription", "vendorProject",
                      "product", "requiredAction", "notes", "knownRansomwareCampaignUse"],
    },
    {
        "table": "t_cert_info",
        "source": "cert",
        "id_cols":   ["vuid", "idnumber"],
        "text_cols": ["name", "overview", "clean_desc", "impact",
                      "resolution", "sysaffected", "workarounds"],
    },
    {
        "table": "t_jvn_info",
        "source": "jvn",
        "id_cols":   ["jvn_number"],
        "text_cols": ["title", "overview", "description", "impact",
                      "solutions", "vendor_name", "critical"],
    },
]


# =============================================================================
# 工具函数
# =============================================================================

def _get_engine():
    db_uri = os.getenv("DB_URI", "")
    if not db_uri:
        print("[ERR] DB_URI 未设置")
        sys.exit(1)
    import sqlalchemy as sa
    return sa.create_engine(db_uri, pool_pre_ping=True)


def _get_milvus_client():
    from pymilvus import MilvusClient
    host = os.getenv("MILVUS_HOST", "localhost")
    port = int(os.getenv("MILVUS_PORT", "19530"))
    return MilvusClient(uri=f"http://{host}:{port}")


def _get_embedder():
    from rag.embeddings import OllamaEmbedding
    return OllamaEmbedding()


def _get_collection_vector_dim(client, collection_name: str) -> int:
    try:
        desc = client.describe_collection(collection_name)
    except Exception:
        return 0
    for field in desc.get("fields", []):
        if field.get("name") != "vector":
            continue
        params = field.get("params", {}) or {}
        dim = params.get("dim")
        if dim is None:
            dim = field.get("dim")
        try:
            return int(dim or 0)
        except Exception:
            return 0
    return 0


def _ensure_collection(client, embedder, collection_name="vuln_knowledge_v2", force_recreate: bool = False):
    from pymilvus import DataType
    expected_dim = embedder.detect_dim()
    if client.has_collection(collection_name):
        need_recreate = force_recreate
        try:
            desc = client.describe_collection(collection_name)
            actual_dim = _get_collection_vector_dim(client, collection_name)
            if actual_dim and actual_dim != expected_dim:
                print(f"[Milvus] vector dim mismatch: collection={actual_dim}, embedder={expected_dim}")
                need_recreate = True
            for f in desc.get("fields", []):
                if f.get("name") == "document":
                    params = f.get("params", {})
                    ml = int(params.get("max_length", 65535))
                    if ml < 65535:
                        print(f"[Milvus] document max_length={ml} 太小，需要重建...")
                        need_recreate = True
                    break
        except Exception as e:
            print(f"[Milvus] describe collection 失败: {e}")
        if need_recreate:
            print(f"[Milvus] 删除并重建 Collection '{collection_name}'...")
            client.drop_collection(collection_name)
        else:
            return
    schema = client.create_schema(auto_id=False, enable_dynamic_field=True)
    schema.add_field("id",       DataType.VARCHAR,      is_primary=True, max_length=128)
    schema.add_field("vector",   DataType.FLOAT_VECTOR, dim=expected_dim)
    schema.add_field("source",   DataType.VARCHAR,      max_length=32)
    schema.add_field("vuln_id",  DataType.VARCHAR,      max_length=64)
    schema.add_field("document", DataType.VARCHAR,      max_length=65535)

    idx = client.prepare_index_params()
    idx.add_index("vector", metric_type="IP", index_type="HNSW",
                  params={"M": 16, "efConstruction": 200})
    client.create_collection(collection_name=collection_name,
                              schema=schema, index_params=idx)
    print(f"[Milvus] Collection '{collection_name}' 已创建，dim={expected_dim}")


def _pick_id(row: dict, id_cols: list) -> str:
    for col in id_cols:
        v = row.get(col)
        if v and str(v).strip():
            return str(v).strip()
    return ""


def _build_doc(row: dict, text_cols: list, source: str, vuln_id: str) -> str:
    parts = []
    for col in text_cols:
        v = row.get(col)
        if v and str(v).strip() not in ("None", "null", ""):
            parts.append(str(v).strip())
    parts.append(f"来源: {source}")
    text = "\n".join(parts)
    # 按 UTF-8 字节截断，留 200 字节余量防止 Milvus 超限
    encoded = text.encode("utf-8")[:65000]
    return encoded.decode("utf-8", errors="ignore")


# =============================================================================
# 主流程：导入
# =============================================================================

def import_from_mysql(limit: int = 0, collection_name: str = "vuln_knowledge_v2",
                      batch_size: int = 50, force_recreate: bool = False):
    import sqlalchemy as sa

    engine  = _get_engine()
    client  = _get_milvus_client()
    embedder = _get_embedder()

    _ensure_collection(client, embedder, collection_name, force_recreate=force_recreate)

    total_written = 0
    insp = sa.inspect(engine)
    existing_tables = insp.get_table_names()

    for rule in SOURCE_RULES:
        table  = rule["table"]
        source = rule["source"]

        if table not in existing_tables:
            print(f"[跳过] 表 {table} 不存在")
            continue

        with engine.connect() as conn:
            sql = f"SELECT * FROM `{table}`"
            if limit:
                sql += f" LIMIT {limit}"
            rows = conn.execute(sa.text(sql)).mappings().all()

        print(f"\n[{source.upper()}] 表 {table}：共 {len(rows)} 条记录，开始向量化...")

        batch, written, skipped = [], 0, 0
        for row in rows:
            row = dict(row)
            vuln_id = _pick_id(row, rule["id_cols"])
            if not vuln_id:
                skipped += 1
                continue

            doc = _build_doc(row, rule["text_cols"], source, vuln_id)
            if not doc.strip():
                skipped += 1
                continue

            try:
                vector = embedder.embed(doc)
            except Exception as e:
                print(f"  [WARN] embed 失败 [{vuln_id}]: {e}")
                skipped += 1
                continue
            if len(vector) != embedder.dim:
                print(f"  [WARN] 向量维度异常 [{vuln_id}]: expected={embedder.dim}, actual={len(vector)}")
                skipped += 1
                continue

            record_id = f"{source}_{vuln_id}"[:128]
            batch.append({
                "id":       record_id,
                "vector":   vector,
                "source":   source[:32],
                "vuln_id":  vuln_id[:64],
                "document": doc,
            })

            if len(batch) >= batch_size:
                client.upsert(collection_name=collection_name, data=batch)
                written += len(batch)
                print(f"  已写入 {written}/{len(rows)}...", end="\r")
                batch.clear()

        if batch:
            client.upsert(collection_name=collection_name, data=batch)
            written += len(batch)

        print(f"  ✅ {source.upper()}: 写入 {written} 条，跳过 {skipped} 条")
        total_written += written

    # 查总量
    time.sleep(1)
    try:
        cnt = client.query(collection_name=collection_name,
                           filter="", output_fields=["count(*)"])
        total_in_milvus = cnt[0].get("count(*)", "?") if cnt else "?"
    except Exception:
        total_in_milvus = "?"

    print(f"\n{'='*50}")
    print(f"导入完成：本次写入 {total_written} 条")
    print(f"Milvus Collection '{collection_name}' 当前总量: {total_in_milvus} 条")
    print(f"{'='*50}")


# =============================================================================
# 主流程：RAG 检索测试
# =============================================================================

def test_rag(collection_name: str = "vuln_knowledge_v2"):
    client   = _get_milvus_client()
    embedder = _get_embedder()

    test_queries = [
        "Apache 远程代码执行漏洞",
        "SQL注入 高危",
        "缓冲区溢出",
        "CVE-2021-44228 Log4j",
        "权限提升 Windows",
    ]

    print(f"\n{'='*50}")
    print("RAG 检索测试")
    print(f"{'='*50}")

    expected_dim = embedder.detect_dim()
    for query in test_queries:
        print(f"\n🔍 查询: {query}")
        try:
            vec = embedder.embed(query)
            if len(vec) != expected_dim:
                print(f"  [ERR] 向量维度异常: expected={expected_dim}, actual={len(vec)}")
                continue
            results = client.search(
                collection_name=collection_name,
                data=[vec],
                limit=3,
                output_fields=["source", "vuln_id", "document"],
            )
            hits = results[0] if results else []
            if not hits:
                print("  (无结果)")
            for i, hit in enumerate(hits, 1):
                entity = hit.get("entity", {})
                vid  = entity.get("vuln_id", "?")
                src  = entity.get("source", "?")
                dist = hit.get("distance", 0)
                doc  = entity.get("document", "")[:80].replace("\n", " ")
                print(f"  [{i}] {src.upper()} {vid}  相似度={dist:.4f}")
                print(f"       {doc}...")
        except Exception as e:
            print(f"  [ERR] 检索失败: {e}")


# =============================================================================
# 入口
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MySQL → Milvus 导入 + RAG 测试")
    parser.add_argument("--test-only",  action="store_true", help="只测试检索，不导入")
    parser.add_argument("--limit",      type=int, default=0,  help="每张表最多导入 N 条（0=全量）")
    parser.add_argument("--batch-size", type=int, default=50, help="Milvus 批量写入大小")
    parser.add_argument("--collection", type=str, default="vuln_knowledge_v2", help="Milvus Collection 名")
    parser.add_argument("--force-recreate", action="store_true", help="若 collection 已存在则删除重建")
    args = parser.parse_args()

    if not args.test_only:
        import_from_mysql(
            limit=args.limit,
            collection_name=args.collection,
            batch_size=args.batch_size,
            force_recreate=args.force_recreate,
        )

    test_rag(collection_name=args.collection)
