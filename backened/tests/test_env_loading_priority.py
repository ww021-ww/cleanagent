import os
from unittest.mock import patch

import check_env
from config.env_loader import EnvConfigLoader


KEYS = ("OPENAI_API_KEY", "OPENAI_API_BASE", "DEFAULT_LLM_MODEL")


def write_env_files(config_dir):
    config_dir.mkdir()
    (config_dir / "database.env").write_text(
        "OPENAI_API_KEY=old-key\n"
        "OPENAI_API_BASE=https://old.example/v1\n"
        "DEFAULT_LLM_MODEL=old-model\n"
        "DB_URI=mysql://test\n",
        encoding="utf-8",
    )
    (config_dir / ".env").write_text(
        "OPENAI_API_KEY=new-key\n"
        "OPENAI_API_BASE=https://new.example/v1\n"
        "DEFAULT_LLM_MODEL=new-model\n",
        encoding="utf-8",
    )


def clear_llm_env(monkeypatch):
    for key in (*KEYS, "DB_URI"):
        monkeypatch.delenv(key, raising=False)


def assert_merged_values():
    assert os.environ["OPENAI_API_KEY"] == "new-key"
    assert os.environ["OPENAI_API_BASE"] == "https://new.example/v1"
    assert os.environ["DEFAULT_LLM_MODEL"] == "new-model"
    assert os.environ["DB_URI"] == "mysql://test"


def test_runtime_loader_prefers_config_env_but_keeps_database_settings(
    tmp_path, monkeypatch
):
    config_dir = tmp_path / "config"
    write_env_files(config_dir)
    clear_llm_env(monkeypatch)

    with patch("config.env_loader.Path", return_value=config_dir / "env_loader.py"):
        EnvConfigLoader()

    assert_merged_values()


def test_diagnostic_loader_uses_the_same_precedence(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    write_env_files(config_dir)
    clear_llm_env(monkeypatch)

    with patch("check_env.Path", return_value=tmp_path / "check_env.py"):
        check_env._load_env()

    assert_merged_values()
