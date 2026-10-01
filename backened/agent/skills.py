"""
Skill Registry — 可插拔技能注册表
将提取/清洗/验证逻辑模块化，新增来源只需添加技能文件
"""
import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  技能基类体系
# ──────────────────────────────────────────────

class Skill:
    """技能基类"""
    name: str = ""
    description: str = ""
    skill_type: str = ""   # extraction / cleaning / validation
    source: str = ""       # 适用来源（空=通用）
    priority: int = 0      # 优先级（高优先）

    def execute(self, data: Dict, context: Dict = None) -> Dict:
        raise NotImplementedError


class ExtractionSkill(Skill):
    """提取技能基类"""
    skill_type = "extraction"

    def extract(self, content: str, file_path: str = "") -> List[Dict]:
        raise NotImplementedError

    def execute(self, data: Dict, context: Dict = None) -> Dict:
        results = self.extract(data.get("content", ""), data.get("file_path", ""))
        return {"extracted": results}


class CleaningSkill(Skill):
    """清洗技能基类"""
    skill_type = "cleaning"

    def clean(self, data: Dict) -> Dict:
        raise NotImplementedError

    def execute(self, data: Dict, context: Dict = None) -> Dict:
        return self.clean(data)


class ValidationSkill(Skill):
    """验证技能基类"""
    skill_type = "validation"

    def validate(self, data: Dict) -> List[str]:
        """返回错误列表，空列表=通过"""
        raise NotImplementedError

    def execute(self, data: Dict, context: Dict = None) -> Dict:
        return {"errors": self.validate(data)}


# ──────────────────────────────────────────────
#  技能注册表
# ──────────────────────────────────────────────

_BASE_SKILL_TYPES = (Skill, ExtractionSkill, CleaningSkill, ValidationSkill)


class SkillRegistry:
    """
    技能注册表

    支持：
    1. 代码内直接注册
    2. 从目录自动扫描加载（热插拔）
    3. 按来源 / 类型 / 优先级查询
    """

    def __init__(self, config: Dict):
        self.config = config
        self.skills: Dict[str, Skill] = {}

        skill_cfg = config.get("agentic", {}).get("skills", {})
        self.enabled: bool = skill_cfg.get("enabled", False)
        self.skill_dirs: List[str] = skill_cfg.get("skill_dirs", ["skills/"])

        if self.enabled:
            self._auto_discover()

    # ── 注册 ────────────────────────────────────

    def register(self, skill: Skill):
        self.skills[skill.name] = skill
        logger.info(
            f"🎯 技能注册: {skill.name} "
            f"(type={skill.skill_type}, source={skill.source or '通用'})"
        )

    def _auto_discover(self):
        """扫描技能目录，自动实例化所有 Skill 子类"""
        for skill_dir in self.skill_dirs:
            dir_path = Path(skill_dir)
            if not dir_path.exists():
                continue
            for py_file in dir_path.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                self._load_skill_file(py_file)
        logger.info(f"🎯 SkillRegistry: 共加载 {len(self.skills)} 个技能")

    def _load_skill_file(self, py_file: Path):
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, Skill)
                    and attr not in _BASE_SKILL_TYPES
                ):
                    instance = attr()
                    if instance.name:
                        self.register(instance)
        except Exception as e:
            logger.warning(f"加载技能文件 {py_file} 失败: {e}")

    # ── 查询 ────────────────────────────────────

    def get_skills(self, skill_type: str = "", source: str = "") -> List[Skill]:
        """
        按类型和来源过滤技能（source 为空时返回通用技能）

        排序：priority 高的优先
        """
        results = []
        for skill in self.skills.values():
            if skill_type and skill.skill_type != skill_type:
                continue
            # 来源过滤：来源匹配 OR 技能来源为空（通用）
            if source and skill.source and skill.source != source.lower():
                continue
            results.append(skill)
        results.sort(key=lambda s: s.priority, reverse=True)
        return results

    def get_extraction_skills(self, source: str) -> List[ExtractionSkill]:
        return self.get_skills("extraction", source)

    def get_cleaning_skills(self, source: str = "") -> List[CleaningSkill]:
        return self.get_skills("cleaning", source)

    def get_validation_skills(self, source: str = "") -> List[ValidationSkill]:
        return self.get_skills("validation", source)
