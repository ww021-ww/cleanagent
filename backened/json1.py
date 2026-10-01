import json
from pathlib import Path

def format_json_files(json_dir: str):
    """将目录下所有JSON文件格式化为美观的多行结构"""
    json_path = Path(json_dir)
    
    for json_file in json_path.glob("**/*.json"):
        try:
            # 读取原始JSON
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 写入格式化后的JSON
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"✓ 已格式化: {json_file.name}")
        except Exception as e:
            print(f"✗ 处理失败 {json_file.name}: {e}")

# 使用示例
format_json_files("d:/WC-project/agent/multiagent/json/cert")