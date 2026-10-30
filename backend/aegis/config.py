"""Central configuration, loaded from the repo-root .env file."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent
SANDBOX_DIR = BACKEND_DIR / "sandbox"
WORKSPACE_DIR = SANDBOX_DIR / "workspace"
RUNS_DIR = BACKEND_DIR / "runs"
CASSETTES_DIR = BACKEND_DIR / "cassettes"
SIMULATOR_DIR = ROOT_DIR / "simulator"
SITES_DIR = SIMULATOR_DIR / "attack_server"
SCENARIOS_DIR = SIMULATOR_DIR / "scenarios"
INBOXES_DIR = SIMULATOR_DIR / "inboxes"
RESULTS_DIR = SIMULATOR_DIR / "results"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_DIR / ".env", extra="ignore")

    ollama_url: str = "http://localhost:11434"
    agent_model: str = "qwen2.5:3b"
    ollama_num_ctx: int = 8192
    ollama_timeout_s: float = 300.0
    replay_mode: bool = False

    classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    classifier_enabled: bool = True
    block_threshold: float = 0.85
    sanitize_threshold: float = 0.5

    max_steps: int = 8
    policy_path: Path = BACKEND_DIR / "policy.yaml"
    db_url: str = f"sqlite:///{(BACKEND_DIR / 'aegis.db').as_posix()}"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()
