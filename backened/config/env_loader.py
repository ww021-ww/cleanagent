"""
环境变量配置加载器
Environment Variable Configuration Loader
"""

import os
from typing import Any, Dict, Optional
from pathlib import Path
from dotenv import load_dotenv
import yaml


class EnvConfigLoader:
    """环境变量配置加载器"""
    
    def __init__(self, env_file: Optional[str] = None):
        """
        初始化配置加载器
        
        Args:
            env_file: .env 文件路径，如果为None则自动查找
        """
        self._load_env_file(env_file)
    
    def _load_env_file(self, env_file: Optional[str] = None):
        """
        加载 .env 文件
        
        优先级：
        1. 指定的 env_file
        2. config/database.env
        3. config/.env
        4. 项目根目录 .env
        """
        if env_file and Path(env_file).exists():
            load_dotenv(env_file, override=True)
            return
        
        # 尝试加载 config/database.env
        config_dir = Path(__file__).parent
        database_env = config_dir / 'database.env'
        if database_env.exists():
            load_dotenv(database_env, override=True)
            return
        
        # 尝试加载 config/.env
        local_env = config_dir / '.env'
        if local_env.exists():
            load_dotenv(local_env, override=True)
            return
        
        # 尝试加载项目根目录 .env
        root_dir = config_dir.parent
        root_env = root_dir / '.env'
        if root_env.exists():
            load_dotenv(root_env, override=True)
            return
    
    def get(self, key: str, default: Any = None, cast_type: type = str) -> Any:
        """
        获取环境变量值
        
        Args:
            key: 环境变量名
            default: 默认值
            cast_type: 类型转换（str, int, float, bool）
        
        Returns:
            环境变量值或默认值
        """
        value = os.getenv(key)
        
        if value is None:
            return default
        
        # 类型转换
        try:
            if cast_type == bool:
                return value.lower() in ('true', '1', 'yes', 'on')
            elif cast_type == int:
                return int(value)
            elif cast_type == float:
                return float(value)
            else:
                return value
        except (ValueError, AttributeError):
            return default
    
    def get_llm_config(self) -> Dict[str, Any]:
        """
        获取LLM配置
        
        Returns:
            LLM配置字典
        """
        return {
            'api_key': self.get('OPENAI_API_KEY', ''),
            'api_base': self.get('OPENAI_API_BASE'),
            'model': self.get('DEFAULT_LLM_MODEL', 'gpt-4o-mini'),
            'temperature': self.get('LLM_TEMPERATURE', 0, float),
            'max_retries': self.get('MAX_RETRIES', 2, int),
        }
    
    def get_db_config(self) -> Dict[str, Any]:
        """
        获取数据库配置
        
        Returns:
            数据库配置字典
        """
        uri = self.get('DB_URI', '')
        # 不要解码 %40，SQLAlchemy 会自动处理
        # 只需确保格式正确：mysql+pymysql://user:password%40@host/db
        return {
            'uri': uri,
            'pool_size': self.get('DB_POOL_SIZE', 10, int),
            'max_overflow': self.get('DB_MAX_OVERFLOW', 20, int),
        }
    
    def get_agent_config(self) -> Dict[str, Any]:
        """
        获取智能体配置
        
        Returns:
            智能体配置字典
        """
        return {
            'extractor': {
                'enabled': True,
                'timeout': self.get('EXTRACTOR_TIMEOUT', 30, int),
            },
            'cleaner_validator': {
                'enabled': True,
                'quality_threshold': self.get('QUALITY_THRESHOLD', 0.7, float),
            },
            'enrichment': {
                'enabled': self.get('ENABLE_ENRICHMENT', False, bool),
            },
            'storage': {
                'enabled': True,
                'batch_size': self.get('STORAGE_BATCH_SIZE', 50, int),
                'timeout': self.get('STORAGE_TIMEOUT', 60, int),
            },
        }
    
    def get_processing_config(self) -> Dict[str, Any]:
        """
        获取处理配置
        
        Returns:
            处理配置字典
        """
        return {
            'max_workers': self.get('MAX_WORKERS', 4, int),
            'timeout': self.get('TASK_TIMEOUT', 3600, int),
            'enable_checkpoint': self.get('ENABLE_CHECKPOINT', True, bool),
            'checkpoint_file': self.get('CHECKPOINT_FILE', 'progress.json'),
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        """
        获取日志配置
        
        Returns:
            日志配置字典
        """
        return {
            'level': self.get('LOG_LEVEL', 'INFO'),
            'file': self.get('LOG_FILE', 'logs/multiagent.log'),
            'console': self.get('LOG_CONSOLE', True, bool),
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        }
    
    def get_performance_config(self) -> Dict[str, Any]:
        """
        获取性能配置
        
        Returns:
            性能配置字典
        """
        return {
            'queue_timeout': self.get('QUEUE_TIMEOUT', 30, int),
            'batch_interval': self.get('BATCH_INTERVAL', 5, int),
            'max_html_length': self.get('MAX_HTML_LENGTH', 8000, int),
            'max_description_length': self.get('MAX_DESCRIPTION_LENGTH', 2000, int),
            'max_references': self.get('MAX_REFERENCES', 10, int),
        }
    
    def get_all_config(self) -> Dict[str, Any]:
        """
        获取所有配置
        
        Returns:
            完整配置字典
        """
        return {
            'llm': self.get_llm_config(),
            'db': self.get_db_config(),
            'agents': self.get_agent_config(),
            'processing': self.get_processing_config(),
            'logging': self.get_logging_config(),
            'performance': self.get_performance_config(),
        }


# 全局配置加载器实例
_env_loader = None


def get_env_loader(env_file: Optional[str] = None) -> EnvConfigLoader:
    """
    获取全局配置加载器实例
    
    Args:
        env_file: .env 文件路径
    
    Returns:
        EnvConfigLoader实例
    """
    global _env_loader
    if _env_loader is None:
        _env_loader = EnvConfigLoader(env_file)
    else:
        _env_loader._load_env_file(env_file)
    return _env_loader


def _replace_env_vars(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _replace_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_env_vars(item) for item in obj]
    if isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
        return os.getenv(obj[2:-1], obj)
    return obj


def load_yaml_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    get_env_loader()
    path = Path(config_path) if config_path else Path(__file__).parent / 'agent_config.yaml'
    with open(path, 'r', encoding='utf-8') as f:
        return _replace_env_vars(yaml.safe_load(f) or {})


if __name__ == '__main__':
    # 测试配置加载
    loader = EnvConfigLoader()
    
    print("=== LLM配置 ===")
    print(loader.get_llm_config())
    
    print("\n=== 数据库配置 ===")
    print(loader.get_db_config())
    
    print("\n=== 智能体配置 ===")
    print(loader.get_agent_config())
    
    print("\n=== 处理配置 ===")
    print(loader.get_processing_config())
    
    print("\n=== 完整配置 ===")
    import json
    print(json.dumps(loader.get_all_config(), indent=2, ensure_ascii=False))
