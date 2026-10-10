import json
import re
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from shared.models import TelemetryEvent

logger = logging.getLogger(__name__)

class TelemetryFileIngestor:
    """Parses real log files (Syslog, Snort IDS, and JSON logs) and converts them into normalized TelemetryEvents."""

    def __init__(self, run_id: Optional[uuid.UUID] = None):
        self.run_id = run_id or uuid.uuid4()

    def parse_syslog_file(self, file_path: str) -> List[TelemetryEvent]:
        """
        Parses Unix syslog files for sshd/auth failures.
        Example line: Jun 27 15:30:10 WEB-01 sshd[12345]: Failed password for admin from 10.0.3.25 port 55670 ssh2
        """
        events = []
        # Match Month Day Time Host Source[PID]: Message
        syslog_pattern = re.compile(
            r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<source>[^:\[]+)(?:\[\d+\])?:?\s+(?P<message>.*)$'
        )
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    match = syslog_pattern.match(line.strip())
                    if match:
                        data = match.groupdict()
                        
                        # Set event severity and type based on message content
                        msg = data["message"]
                        severity = "INFO"
                        event_type = "Auth_Log"
                        
                        if "failed" in msg.lower() or "invalid" in msg.lower() or "error" in msg.lower():
                            severity = "WARNING"
                        if "accepted" in msg.lower() or "success" in msg.lower():
                            severity = "INFO"

                        # Parse syslog time (assuming current year)
                        current_year = datetime.now().year
                        time_str = f"{current_year} {data['month']} {data['day']} {data['time']}"
                        try:
                            timestamp = datetime.strptime(time_str, "%Y %b %d %H:%M:%S")
                        except ValueError:
                            timestamp = datetime.utcnow()

                        event = TelemetryEvent(
                            timestamp=timestamp,
                            run_id=self.run_id,
                            host_id=data["host"].upper(),
                            event_type=event_type,
                            source=data["source"].strip(),
                            severity=severity,
                            message=msg,
                            metadata={"raw_log": line.strip()}
                        )
                        events.append(event)
            logger.info(f"Ingested {len(events)} events from syslog: {file_path}")
        except Exception as e:
            logger.error(f"Failed to parse syslog file {file_path}: {e}")
            
        return events

    def parse_snort_alert_file(self, file_path: str) -> List[TelemetryEvent]:
        """
        Parses Snort fast-alert format records.
        Example line: [**] [1:1000001:1] SMB Exploit Attempt [**] [Priority: 1] {TCP} 10.0.3.25:55432 -> 10.0.1.2:445
        """
        events = []
        snort_pattern = re.compile(
            r'^\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(?P<msg>[^\[]+)\[\*\*\](?:\s+\[Priority:\s+(?P<priority>\d+)\])?(?:\s+\{(?P<proto>\w+)\})?\s+(?P<src>[^:]+)(?::(?P<sport>\d+))?\s+->\s+(?P<dst>[^:]+)(?::(?P<dport>\d+))?$'
        )

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    match = snort_pattern.match(line.strip())
                    if match:
                        data = match.groupdict()
                        
                        priority = data.get("priority")
                        severity = "INFO"
                        if priority == "1":
                            severity = "CRITICAL"
                        elif priority == "2":
                            severity = "WARNING"

                        # Extract target destination as host ID
                        dst_ip = data["dst"]
                        
                        event = TelemetryEvent(
                            timestamp=datetime.utcnow(),
                            run_id=self.run_id,
                            host_id=dst_ip, # Assign alert to destination host
                            event_type="IDS_Alert",
                            source="Snort IDS",
                            severity=severity,
                            message=data["msg"].strip(),
                            metadata={
                                "source_ip": data["src"],
                                "source_port": data["sport"],
                                "destination_ip": dst_ip,
                                "destination_port": data["dport"],
                                "protocol": data["proto"],
                                "priority": priority
                            }
                        )
                        events.append(event)
            logger.info(f"Ingested {len(events)} events from Snort alert file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to parse Snort alerts file {file_path}: {e}")
            
        return events

    def parse_json_log_file(self, file_path: str) -> List[TelemetryEvent]:
        """Parses lines of standard JSON format logs."""
        events = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line.strip())
                        
                        # Match fields with TelemetryEvent fields
                        ts_str = record.get("timestamp") or record.get("time") or record.get("@timestamp")
                        try:
                            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.utcnow()
                        except ValueError:
                            timestamp = datetime.utcnow()
                            
                        event = TelemetryEvent(
                            timestamp=timestamp,
                            run_id=self.run_id,
                            host_id=(record.get("host_id") or record.get("host") or record.get("Computer") or "WS-01").upper(),
                            event_type=record.get("event_type") or record.get("Channel") or "Sysmon_ProcessCreation",
                            source=record.get("source") or record.get("ProviderName") or "Security-Audit",
                            severity=record.get("severity") or record.get("level") or "INFO",
                            message=record.get("message") or record.get("Description") or "N/A",
                            metadata=record.get("metadata") or record.get("EventData") or record
                        )
                        events.append(event)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse line as JSON: {line.strip()}")
            logger.info(f"Ingested {len(events)} events from JSON file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to parse JSON log file {file_path}: {e}")
            
        return events
