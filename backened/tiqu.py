import json
import os
import re

def extract_fields(obj, prefix='', fields=None):
    """提取字段名，返回字段名的集合"""
    if fields is None:
        fields = set()
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_prefix = f"{prefix}_{key}" if prefix else key
            fields.add(new_prefix)
            extract_fields(value, new_prefix, fields)
    elif isinstance(obj, list):
        for item in obj:
            extract_fields(item, prefix, fields)
    
    return fields

def get_all_json_files(directory):
    """递归获取目录及其子目录中的所有JSON文件"""
    json_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files

def is_2020_or_later_vulnerability(data):
    """判断是否为2020年后的漏洞"""
    # 从CVE ID中提取年份
    if 'cveMetadata' in data and 'cveId' in data['cveMetadata']:
        cve_id = data['cveMetadata']['cveId']
        # 匹配CVE-YYYY-XXXX格式
        match = re.match(r'CVE-(\d{4})-', cve_id)
        if match:
            year = int(match.group(1))
            return year >= 2020
    
    # 从文件名中提取年份
    return False

def main():
    # 硬编码的根目录路径 - 可以直接修改这里指定要递归遍历的根目录
    # 示例：根目录路径
    target_path = r"D:\WC-project\scrapy爬虫\cve\cvelistV5-main\cvelistV5-main\2020up"
    
    json_files = []
    
    if os.path.isfile(target_path) and target_path.endswith('.json'):
        # 处理单个JSON文件
        json_files = [target_path]
    elif os.path.isdir(target_path):
        # 递归处理目录及其所有子目录中的JSON文件
        json_files = get_all_json_files(target_path)
    else:
        print(f"错误: {target_path} 不是有效的JSON文件或目录")
        return
    
    all_fields = set()
    processed_files = 0
    
    # 遍历所有JSON文件
    for json_file_path in json_files:
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 检查是否为2020年后的漏洞
            if is_2020_or_later_vulnerability(data):
                # 提取当前文件的字段
                file_fields = extract_fields(data)
                all_fields.update(file_fields)
                print(f"处理文件: {os.path.relpath(json_file_path, target_path)} - 提取到 {len(file_fields)} 个字段")
                processed_files += 1
            else:
                # 从文件名中提取年份进行检查
                filename = os.path.basename(json_file_path)
                match = re.match(r'CVE-(\d{4})-', filename)
                if match:
                    year = int(match.group(1))
                    if year >= 2020:
                        # 提取当前文件的字段
                        file_fields = extract_fields(data)
                        all_fields.update(file_fields)
                        print(f"处理文件: {os.path.relpath(json_file_path, target_path)} - 提取到 {len(file_fields)} 个字段")
                        processed_files += 1
        except Exception as e:
            print(f"处理文件 {os.path.relpath(json_file_path, target_path)} 时出错: {e}")
    
    # 排序并打印所有字段
    print(f"\n处理了 {processed_files} 个2020年后的漏洞文件")
    print("\n提取的字段列表：")
    for field in sorted(all_fields):
        print(field)
    
    print(f"\n总字段数：{len(all_fields)}")

if __name__ == "__main__":
    main()