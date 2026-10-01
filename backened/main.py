"""
LangGraph Multi-Agent System - Main Entry Point
LangGraph 多智能体系统 - 主入口
"""
import argparse
import asyncio
import copy
import logging
from pathlib import Path
from config import load_yaml_config
from graph.controller import LangGraphController
from graph.checkpoint import open_checkpointer


def build_parser() -> argparse.ArgumentParser:
    script_dir = Path(__file__).parent
    default_config = str(script_dir / 'config' / 'agent_config.yaml')
    parser = argparse.ArgumentParser(
        description='LangGraph 多智能体漏洞数据处理系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python main.py --file html/cnvd/2024/CNVD-2024-12345.html
  python main.py --directory html/cnvd/2024/
  python main.py --directory html/ --pattern "*"
        """,
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', type=str, help='处理单个文件')
    input_group.add_argument('--directory', '-d', type=str, help='处理目录中的所有文件')
    parser.add_argument('--config', '-c', type=str, default=default_config,
                        help=f'配置文件路径（默认: {default_config}）')
    parser.add_argument('--pattern', '-p', type=str, default='*.json',
                        help='文件匹配模式（默认: *.json，支持: *.html, *.json, *）')
    parser.add_argument('--workers', '-w', type=int, default=4,
                        help='最大并发数（默认: 4）')
    parser.add_argument('--timeout', '-t', type=int, default=3600,
                        help='超时时间（秒，默认: 3600）')
    parser.add_argument('--agent-recovery', action='store_true',
                        help='为本次运行启用受约束异常恢复 Agent Loop')
    parser.add_argument('--dry-run', action='store_true',
                        help='执行完整流程但不写入 MySQL 或 Milvus')
    return parser


def parse_cli_args(argv=None):
    return build_parser().parse_args(argv)


def apply_runtime_options(config: dict, agent_recovery: bool, dry_run: bool) -> dict:
    runtime = copy.deepcopy(config)
    if agent_recovery:
        runtime.setdefault('agentic', {}).setdefault('recovery', {})[
            'agent_loop_enabled'
        ] = True
    if dry_run:
        runtime.setdefault('processing', {})['dry_run'] = True
        runtime.setdefault('agentic', {}).setdefault('rag', {})['enabled'] = False
    return runtime

def setup_logging(config: dict):
    """设置日志"""
    log_config = config.get('logging', {})
    log_level = log_config.get('level', 'INFO')
    log_file = log_config.get('file', 'logs/multiagent.log')
    log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console = log_config.get('console', True)
    
    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
        ]
    )
    
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(console_handler)


async def main():
    """主函数"""
    args = parse_cli_args()
    
    print(f"加载配置文件: {args.config}")
    config = apply_runtime_options(
        load_yaml_config(args.config), args.agent_recovery, args.dry_run
    )
    
    if args.workers:
        config['processing']['max_workers'] = args.workers
    if args.timeout:
        config['processing']['timeout'] = args.timeout
    
    setup_logging(config)
    logger = logging.getLogger(__name__)
    
    logger.info("="*60)
    logger.info("LangGraph 多智能体漏洞数据处理系统启动")
    logger.info("="*60)
    
    async def run(controller):
        if args.file:
            logger.info(f"处理单个文件: {args.file}")
            result = await controller.process_file(args.file)
            print(f"\n处理结果: {result['final_status']}")
            if result.get('errors'):
                print(f"错误: {result['errors']}")
            if result.get('warnings'):
                print(f"警告: {result['warnings']}")
        
        elif args.directory:
            logger.info(f"处理目录: {args.directory}")
            logger.info(f"文件模式: {args.pattern}")
            await controller.process_directory(
                args.directory,
                pattern=args.pattern,
                max_workers=args.workers,
                timeout=args.timeout
            )
        
        controller.print_stats()
        logger.info("处理完成！")

    logger.info("初始化 LangGraph 控制器...")
    try:
        if config.get('processing', {}).get('dry_run', False):
            await run(LangGraphController(config))
        else:
            checkpoint_path = config.get('processing', {}).get(
                'checkpoint_db', 'logs/langgraph_checkpoints.sqlite'
            )
            async with open_checkpointer(checkpoint_path) as checkpointer:
                await run(LangGraphController(config, checkpointer=checkpointer))
    except KeyboardInterrupt:
        logger.warning("用户中断处理")
    except Exception as e:
        logger.error(f"处理失败: {e}", exc_info=True)
    finally:
        logger.info("系统已关闭")


if __name__ == '__main__':
    asyncio.run(main())
