"""
监控处理进度
"""
import time
from config import get_db_uri
from sqlalchemy import create_engine, text

db_uri = get_db_uri()
engine = create_engine(db_uri)

print("监控CVE数据处理进度...")
print("按 Ctrl+C 停止监控\n")

last_count = 0

try:
    while True:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM t_cve_main"))
            current_count = result.fetchone()[0]
            
            if current_count != last_count:
                delta = current_count - last_count
                print(f"[{time.strftime('%H:%M:%S')}] t_cve_main: {current_count} 条记录 (+{delta})")
                last_count = current_count
        
        time.sleep(5)  # 每5秒检查一次
        
except KeyboardInterrupt:
    print("\n监控已停止")
    print(f"最终记录数: {last_count}")
