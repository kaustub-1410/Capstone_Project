import psycopg2
from neo4j import GraphDatabase
import redis
import clickhouse_connect
from shared.config import db_settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Redis Connection
def get_redis_client() -> redis.Redis:
    return redis.Redis(
        host=db_settings.redis_host,
        port=db_settings.redis_port,
        password=db_settings.redis_password,
        decode_responses=True
    )

# Postgres Connection Pool
def get_postgres_connection():
    return psycopg2.connect(
        host=db_settings.postgres_host,
        port=db_settings.postgres_port,
        user=db_settings.postgres_user,
        password=db_settings.postgres_password,
        dbname=db_settings.postgres_db
    )

# Neo4j Driver
def get_neo4j_driver() -> GraphDatabase:
    return GraphDatabase.driver(
        db_settings.neo4j_uri,
        auth=(db_settings.neo4j_user, db_settings.neo4j_password)
    )

# ClickHouse Client
def get_clickhouse_client():
    return clickhouse_connect.get_client(
        host=db_settings.clickhouse_host,
        port=db_settings.clickhouse_port,
        username=db_settings.clickhouse_user,
        password=db_settings.clickhouse_password,
        database=db_settings.clickhouse_database
    )

def init_databases():
    """Initializes schemas across PostgreSQL and ClickHouse if they do not exist."""
    # 1. PostgreSQL Schema Initialization
    try:
        conn = get_postgres_connection()
        with conn.cursor() as cur:
            # Create Experiments Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    id UUID PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Create Simulation Runs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS simulation_runs (
                    id UUID PRIMARY KEY,
                    experiment_id UUID REFERENCES experiments(id) ON DELETE CASCADE,
                    status VARCHAR(50) DEFAULT 'running',
                    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP WITH TIME ZONE,
                    config JSONB NOT NULL,
                    metrics JSONB DEFAULT '{}'
                );
            """)
            conn.commit()
            logger.info("PostgreSQL schemas verified/created successfully.")
        conn.close()
    except Exception as e:
        logger.warning(f"Could not connect or initialize PostgreSQL schema: {e}")

    # 2. ClickHouse Schema Initialization
    try:
        ch_client = get_clickhouse_client()
        ch_client.command("""
            CREATE TABLE IF NOT EXISTS telemetry_events (
                timestamp DateTime64(3),
                event_id UUID,
                run_id UUID,
                host_id String,
                event_type String,
                source String,
                severity String,
                message String,
                metadata String
            ) ENGINE = MergeTree()
            ORDER BY (run_id, event_type, timestamp);
        """)
        logger.info("ClickHouse schemas verified/created successfully.")
    except Exception as e:
        logger.warning(f"Could not connect or initialize ClickHouse schema: {e}")

    # 3. Neo4j Index / Constraints Initialization
    try:
        driver = get_neo4j_driver()
        with driver.session() as session:
            # Create constraints for fast lookup
            session.run("CREATE CONSTRAINT unique_device_id IF NOT EXISTS FOR (d:Device) REQUIRE d.id IS UNIQUE")
            session.run("CREATE CONSTRAINT unique_user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE")
            session.run("CREATE CONSTRAINT unique_service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE")
            session.run("CREATE CONSTRAINT unique_credential_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE")
            logger.info("Neo4j constraints verified/created successfully.")
        driver.close()
    except Exception as e:
        logger.warning(f"Could not connect or initialize Neo4j constraints: {e}")
