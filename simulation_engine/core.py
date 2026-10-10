import heapq
import time
import uuid
import logging
from typing import List, Dict, Any, Callable
from datetime import datetime, timedelta
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Event(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    handler_name: str
    payload: Dict[str, Any]

    def __lt__(self, other: 'Event') -> bool:
        return self.timestamp < other.timestamp

class SimulationEngine:
    def __init__(self, run_id: uuid.UUID = None):
        self.run_id = run_id or uuid.uuid4()
        self.current_time = datetime.utcnow()
        self.event_queue: List[Event] = []
        self.handlers: Dict[str, Callable[[Event], None]] = {}
        self.running = False
        
        # Performance logging / tracking metrics
        self.metrics = {
            "processed_events": 0,
            "failed_events": 0,
            "start_time": self.current_time.isoformat(),
            "end_time": None
        }

    def register_handler(self, name: str, handler: Callable[[Event], None]):
        """Register a handler callback for handling specific simulation event types."""
        self.handlers[name] = handler
        logger.debug(f"Registered event handler: {name}")

    def schedule_event(self, delay_seconds: float, event_type: str, handler_name: str, payload: Dict[str, Any]):
        """Schedule a future event with a delay in simulation time."""
        event_time = self.current_time + timedelta(seconds=delay_seconds)
        event = Event(
            id=str(uuid.uuid4()),
            timestamp=event_time,
            event_type=event_type,
            handler_name=handler_name,
            payload=payload
        )
        heapq.heappush(self.event_queue, event)
        logger.debug(f"Scheduled event {event_type} (handler: {handler_name}) in {delay_seconds}s at {event_time}")
        return event.id

    def cancel_event(self, event_id: str) -> bool:
        """Cancel an event by resetting its handler to a no-op (lazy deletion)."""
        for event in self.event_queue:
            if event.id == event_id:
                event.handler_name = "noop"
                return True
        return False

    def step(self) -> bool:
        """Process the single next event in the queue."""
        if not self.event_queue:
            return False

        event = heapq.heappop(self.event_queue)
        
        # Advance simulation virtual clock
        if event.timestamp > self.current_time:
            self.current_time = event.timestamp

        if event.handler_name == "noop":
            return True

        handler = self.handlers.get(event.handler_name)
        if handler:
            try:
                handler(event)
                self.metrics["processed_events"] += 1
            except Exception as e:
                logger.error(f"Error handling event {event.id} ({event.event_type}): {e}", exc_info=True)
                self.metrics["failed_events"] += 1
        else:
            logger.warning(f"No handler registered for name: {event.handler_name}")
            self.metrics["failed_events"] += 1
            
        return True

    def run(self, max_ticks: int = 1000, tick_delay: float = 0.0):
        """Run the simulation loop until empty or reaching max ticks limit."""
        self.running = True
        logger.info(f"Starting simulation run {self.run_id} at {self.current_time}")
        
        ticks = 0
        while self.running and self.event_queue and ticks < max_ticks:
            success = self.step()
            if not success:
                break
            ticks += 1
            if tick_delay > 0:
                time.sleep(tick_delay)
                
        self.metrics["end_time"] = datetime.utcnow().isoformat()
        self.running = False
        logger.info(f"Simulation completed. Total ticks: {ticks}. Processed events: {self.metrics['processed_events']}")
        return self.metrics
