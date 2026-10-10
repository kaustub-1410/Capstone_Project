import json
import logging
import time
import threading
from typing import List, Dict, Any
from shared.config import db_settings
from shared.db import get_clickhouse_client

logger = logging.getLogger(__name__)

class TelemetryConsumer(threading.Thread):
    def __init__(self, batch_size: int = 100, flush_interval_seconds: float = 2.0):
        super().__init__()
        self.daemon = True
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.buffer: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.running = False
        self.kafka_consumer = None
        self.clickhouse_client = None

        try:
            from kafka import KafkaConsumer
            self.kafka_consumer = KafkaConsumer(
                db_settings.kafka_topic,
                bootstrap_servers=db_settings.kafka_bootstrap_servers,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                group_id='amcds-telemetry-consumers'
            )
            logger.info("Kafka Telemetry Consumer initialized successfully.")
        except Exception as e:
            logger.warning(f"Could not initialize Kafka Consumer: {e}")

        try:
            self.clickhouse_client = get_clickhouse_client()
            logger.info("ClickHouse client connected for consumer writes.")
        except Exception as e:
            logger.warning(f"Could not initialize ClickHouse client: {e}")

    def run(self):
        if not self.kafka_consumer or not self.clickhouse_client:
            logger.error("Telemetry consumer aborted. Missing Kafka or ClickHouse clients.")
            return

        self.running = True
        last_flush = time.time()
        logger.info("Telemetry consumer polling loop started.")

        try:
            while self.running:
                # Poll events from Kafka
                message_pack = self.kafka_consumer.poll(timeout_ms=500)
                
                with self.lock:
                    for tp, messages in message_pack.items():
                        for message in messages:
                            self.buffer.append(message.value)
                
                # Check for buffer limits or timeout interval to flush
                now = time.time()
                if len(self.buffer) >= self.batch_size or (now - last_flush >= self.flush_interval and self.buffer):
                    self.flush()
                    last_flush = now
                    
        except Exception as e:
            logger.error(f"Error in telemetry consumer polling loop: {e}", exc_info=True)
        finally:
            self.flush()

    def flush(self):
        """Batch inserts collected events into ClickHouse."""
        with self.lock:
            if not self.buffer:
                return

            records = []
            for event in self.buffer:
                records.append({
                    'timestamp': event.get('timestamp'),
                    'event_id': event.get('event_id'),
                    'run_id': event.get('run_id'),
                    'host_id': event.get('host_id'),
                    'event_type': event.get('event_type'),
                    'source': event.get('source'),
                    'severity': event.get('severity'),
                    'message': event.get('message'),
                    'metadata': json.dumps(event.get('metadata', {}))
                })

            try:
                # Bulk insert into ClickHouse
                self.clickhouse_client.insert('telemetry_events', records)
                logger.info(f"Ingested {len(records)} events into ClickHouse.")
                self.buffer.clear()
            except Exception as e:
                logger.error(f"ClickHouse batch insert failed: {e}")

    def stop(self):
        self.running = False
        if self.kafka_consumer:
            self.kafka_consumer.close()
        logger.info("Telemetry consumer polling stopped.")
