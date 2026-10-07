from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    mongo_uri: str = "mongodb://localhost:27018/?replicaSet=rs0&directConnection=true"
    mongo_database: str = "vigilia"
    cognito_endpoint: str = "http://localhost:9229"
    cognito_issuer: str = "http://0.0.0.0:9229"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    public_url: str = "http://localhost:8000"
    cookie_secure: bool = False
    admin_email: str = "admin@example.org"
    admin_password: str = ""
    nvd_api_key: str = ""


def connect(settings: Settings):
    from pymongo import MongoClient
    from app.infrastructure.mongo import MongoRepository
    client = MongoClient(settings.mongo_uri, tz_aware=True, serverSelectionTimeoutMS=10000)
    return MongoRepository(client[settings.mongo_database])
