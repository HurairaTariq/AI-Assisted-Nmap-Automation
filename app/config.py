from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # App
    APP_NAME: str = "NmapMCP"
    DEBUG: bool = False

    # Auth
    SECRET_KEY: str = "change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # OpenAI
    OPENAI_API_KEY: str
    OPENAI_MODEL: str = "gpt-4.1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/nmapdb"

    # Docker
    DOCKER_KALI_IMAGE: str = "kalilinux/kali-rolling"
    DOCKER_SCAN_TIMEOUT: int = 120          # seconds
    DOCKER_MEM_LIMIT: str = "256m"
    DOCKER_CPU_QUOTA: int = 50000           # 0.5 CPU

    # Rate limiting
    MAX_SCANS_PER_HOUR: int = 20

    # Validation
    MAX_PORTS_PER_REQUEST: int = 1000
    MAX_CIDR_PREFIX: int = 24
    ALLOWED_TIMING_TEMPLATES: List[str] = ["T1", "T2", "T3", "T4"]

    # Blocked Nmap flags (hardcoded safety list)
    BLOCKED_FLAGS: List[str] = [
        "-f", "--mtu", "-D", "--spoof-mac", "--source-port",
        "--proxies", "--badsum", "--data-length", "-sI",
        "--script exploit", "--script brute", "--script dos",
        "--script intrusive", "--script malware",
    ]

    # Whitelisted NSE scripts only
    ALLOWED_NSE_SCRIPTS: List[str] = [
        "http-headers", "http-title", "http-methods", "http-robots.txt",
        "ssl-cert", "ssl-enum-ciphers", "ssh-hostkey", "ssh-auth-methods",
        "ftp-anon", "smtp-open-relay", "dns-zone-transfer",
        "banner", "finger", "ident-info", "uptime-agent",
    ]

    class Config:
        env_file = ".env"

settings = Settings()