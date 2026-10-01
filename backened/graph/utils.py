"""
Graph Utilities — 各节点共用的轻量工具函数
"""


def normalize_jvn_id(source: str, file_stem: str) -> str:
    """将 JVN 文件名格式规范化为数据库存储的 ID 格式"""
    if source.lower() != 'jvn':
        return file_stem
    vuln_id = file_stem.strip()
    for old, new in [
        ('JVNVU-#', 'JVNVU#'),
        ('JVNVU-', 'JVNVU#'),
        ('JVN-', 'JVN#'),
        ('JVNTA-', 'JVNTA'),
    ]:
        if vuln_id.startswith(old):
            return vuln_id.replace(old, new, 1)
    return vuln_id
