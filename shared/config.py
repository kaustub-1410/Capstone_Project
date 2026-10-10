from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

class DatabaseSettings(BaseSettings):
    postgres_host: str = Field(default="localhost", validation_alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, validation_alias="POSTGRES_PORT")
    postgres_user: str = Field(default="amcds", validation_alias="POSTGRES_USER")
    postgres_password: str = Field(default="amcds_password", validation_alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="amcds_db", validation_alias="POSTGRES_DB")

    redis_host: str = Field(default="localhost", validation_alias="REDIS_HOST")
    redis_port: int = Field(default=6379, validation_alias="REDIS_PORT")
    redis_password: Optional[str] = Field(default=None, validation_alias="REDIS_PASSWORD")

    neo4j_uri: str = Field(default="bolt://localhost:7687", validation_alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", validation_alias="NEO4J_USER")
    neo4j_password: str = Field(default="amcds_password", validation_alias="NEO4J_PASSWORD")

    kafka_bootstrap_servers: str = Field(default="localhost:9092", validation_alias="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic: str = Field(default="amcds-telemetry", validation_alias="KAFKA_TOPIC")

    clickhouse_host: str = Field(default="localhost", validation_alias="CLICKHOUSE_HOST")
    clickhouse_port: int = Field(default=8123, validation_alias="CLICKHOUSE_PORT")
    clickhouse_user: str = Field(default="default", validation_alias="CLICKHOUSE_USER")
    clickhouse_password: str = Field(default="", validation_alias="CLICKHOUSE_PASSWORD")
    clickhouse_database: str = Field(default="default", validation_alias="CLICKHOUSE_DATABASE")

    class Config:
        env_file = ".env"
        extra = "ignore"

class LLMSettings(BaseSettings):
    openai_api_key: Optional[str] = Field(default=None, validation_alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    local_model_url: str = Field(default="http://localhost:8000/v1", validation_alias="LOCAL_MODEL_URL")
    model_provider: str = Field(default="local", validation_alias="MODEL_PROVIDER") # local, openai, anthropic
    model_name: str = Field(default="llama3", validation_alias="MODEL_NAME")

    class Config:
        env_file = ".env"
        extra = "ignore"

class SimulationSettings(BaseSettings):
    max_ticks: int = Field(default=1000, validation_alias="SIM_MAX_TICKS")
    tick_rate_seconds: float = Field(default=1.0, validation_alias="SIM_TICK_RATE")
    telemetry_streaming_enabled: bool = Field(default=True, validation_alias="SIM_TELEMETRY_ENABLED")

    class Config:
        env_file = ".env"
        extra = "ignore"

# Global configurations
db_settings = DatabaseSettings()
llm_settings = LLMSettings()
sim_settings = SimulationSettings()
