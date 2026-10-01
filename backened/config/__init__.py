"""
Configuration module for multiagent system
配置模块 - 统一的配置入口
"""
import os
from .field_config_loader import FieldConfigLoader
from .env_loader import EnvConfigLoader, get_env_loader, load_yaml_config

get_env_loader()

# ============================================
# 便捷访问函数 - 兼容旧的导入方式
# ============================================

def get_llm_config() -> dict:
    """
    获取 LLM 配置
    
    Returns:
        配置字典，包含 api_key, base_url, model, temperature
    """
    loader = get_env_loader()
    llm_config = loader.get_llm_config()
    
    # 转换为 LangChain 格式
    config = {
        'api_key': llm_config['api_key'],
        'model': llm_config['model'],  # 确保返回model字段
        'temperature': llm_config['temperature'],
    }
    
    if llm_config.get('api_base'):
        config['base_url'] = llm_config['api_base']
    
    return config


def get_db_uri() -> str:
    """获取数据库 URI"""
    loader = get_env_loader()
    return loader.get_db_config()['uri']


# ============================================
# 常量定义 - 从环境变量读取
# ============================================

# LLM 设置
DEFAULT_LLM_MODEL = os.getenv('DEFAULT_LLM_MODEL', 'gpt-4o-mini')
LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', '0'))
MAX_HTML_LENGTH = int(os.getenv('MAX_HTML_LENGTH', '8000'))
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
OPENAI_API_BASE = os.getenv('OPENAI_API_BASE', None)

# 数据库设置
DEFAULT_DB_URI = os.getenv('DB_URI', 'sqlite:///vulns.db')

# 处理设置
DEFAULT_WORKERS = int(os.getenv('MAX_WORKERS', '4'))
MAX_RETRIES = int(os.getenv('MAX_RETRIES', '2'))
MAX_REFERENCES = 10
MAX_DESCRIPTION_LENGTH = 2000

# 日志设置
LOG_FILE = os.getenv('LOG_FILE', 'logs/multiagent.log')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# 源识别模式
SOURCE_PATTERNS = {
    'cnvd': r'cnvd[_-]',
    'jvn': r'jvn[_-]',
    'cisa': r'cisa[_-]',
    'cert': r'cert[_-]',
    'cve': r'cve[_-]',
    'nvd': r'nvd[_-]'
}

# 严重程度映射
SEVERITY_MAPPING = {
    'low': 'Low',
    'medium': 'Medium',
    'high': 'High',
    'critical': 'Critical',
    '0-3.9': 'Low',
    '4.0-6.9': 'Medium',
    '7.0-8.9': 'High',
    '9.0-10.0': 'Critical'
}

# ============================================
# 导出列表
# ============================================

__all__ = [
    # 配置加载器
    'FieldConfigLoader',
    'EnvConfigLoader',
    'get_env_loader',
    'load_yaml_config',
    
    # 便捷函数
    'get_llm_config',
    'get_db_uri',
    
    # 常量
    'DEFAULT_LLM_MODEL',
    'LLM_TEMPERATURE',
    'MAX_HTML_LENGTH',
    'OPENAI_API_KEY',
    'OPENAI_API_BASE',
    'DEFAULT_DB_URI',
    'DEFAULT_WORKERS',
    'MAX_RETRIES',
    'MAX_REFERENCES',
    'MAX_DESCRIPTION_LENGTH',
    'LOG_FILE',
    'LOG_FORMAT',
    'LOG_LEVEL',
    'SOURCE_PATTERNS',
    'SEVERITY_MAPPING',
]

