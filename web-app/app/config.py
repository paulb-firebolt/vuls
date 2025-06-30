"""Application configuration using Pydantic Settings"""

from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings"""

    # Database URL (from environment variable)
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379"

    # JWT
    jwt_secret_key: str = "your-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Application
    app_name: str = "Vuls Web"
    debug: bool = False

    # Vuls paths
    vuls_config_dir: str = "/app/config"
    vuls_results_dir: str = "/app/results"
    vuls_db_dir: str = "/app/db"
    vuls_logs_dir: str = "/app/logs"

    # Docker
    docker_socket: str = "unix:///var/run/docker.sock"

    # Executor service
    executor_url: str = "http://vuls-executor:8080"
    executor_api_key: str = "change-me-in-production"

    class Config:
        env_file = ".env"


settings = Settings()
