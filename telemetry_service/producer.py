import json
import logging
from datetime import datetime
import uuid
from typing import Dict, Any, Optional
from shared.config import db_settings, sim_settings
from shared.models import TelemetryEvent

logger = logging.getLogger(__name__)

class TelemetryProducer:
    def __init__(self):
        self.enabled = sim_settings.telemetry_streaming_enabled
        self.kafka_producer = None
        self.offline_events = []
        
        if self.enabled:
            try:
                from kafka import KafkaProducer
                self.kafka_producer = KafkaProducer(
                    bootstrap_servers=db_settings.kafka_bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                    acks='all',
                    request_timeout_ms=5000
                )
                logger.info("Kafka Telemetry Producer initialized successfully.")
            except Exception as e:
                logger.warning(f"Could not initialize Kafka Producer (falling back to direct storage): {e}")

    def log_event(self, run_id: uuid.UUID, host_id: str, event_type: str, source: str, severity: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        """Construct and stream a telemetry event to Kafka, or record locally on fallback."""
        event = TelemetryEvent(
            timestamp=datetime.utcnow(),
            event_id=uuid.uuid4(),
            run_id=run_id,
            host_id=host_id,
            event_type=event_type,
            source=source,
            severity=severity,
            message=message,
            metadata=metadata or {}
        )

        self.offline_events.append(event)

        if not self.enabled:
            return

        event_dict = event.model_dump()
        
        # Stream to Kafka
        if self.kafka_producer:
            try:
                self.kafka_producer.send(db_settings.kafka_topic, value=event_dict)
                logger.debug(f"Streamed event {event.event_id} to topic {db_settings.kafka_topic}")
                return
            except Exception as e:
                logger.error(f"Failed to publish event to Kafka: {e}")

        # Fallback logging (writes to console or log files directly)
        logger.info(f"[TELEMETRY FALLBACK] {event.timestamp} | {event.event_type} | Host: {event.host_id} | Msg: {event.message}")

    def get_offline_events(self) -> list:
        return self.offline_events

    def clear_offline_events(self):
        self.offline_events.clear()

    def close(self):
        if self.kafka_producer:
            try:
                self.kafka_producer.flush()
                self.kafka_producer.close()
                logger.info("Kafka Telemetry Producer closed.")
            except Exception as e:
                logger.error(f"Error closing Kafka Producer: {e}")
