from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "ToolboxV8"
    DEBUG: bool = False
    SECRET_KEY: str = "changeme-in-production-use-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Hosts
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "api", "api:8000"]
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:3000",
    ]

    # URL interne de l'API, utilisée par le service web pour appeler l'API
    # (en docker-compose : http://api:8000)
    INTERNAL_API_URL: str = "http://api:8000"
    # Port d'écoute du service web (Jinja + proxy /api/*)
    WEB_PORT: int = 3000

    # Database
    DATABASE_URL: str = "postgresql://pentest:pentest@db:5432/pentestdb"

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/1"

    # MinIO
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "pentest-reports"
    MINIO_SECURE: bool = False

    # Fernet encryption key (generate: from cryptography.fernet import Fernet; Fernet.generate_key())
    FERNET_KEY: str = "changeme-generate-with-fernet"

    # VirusTotal
    VIRUSTOTAL_API_KEY: str = ""

    # ELK
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
