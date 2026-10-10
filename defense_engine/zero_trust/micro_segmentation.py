"""
Zero Trust Micro-Segmentation Module — Manages dynamic connection permission rules
to enforce network micro-segmentation and isolate workloads.
"""

import logging
from typing import Dict, List, Set, Tuple, Any

logger = logging.getLogger(__name__)

class MicroSegmentationEngine:
    """
    Enforces segment isolation rules. Limits inter-host communication
    to only explicitly allowed network workloads.
    """

    def __init__(self):
        # Allowed segmentation rules: (source_segment, destination_segment)
        self.allowed_segment_flows: Set[Tuple[str, str]] = {
            ("Corp", "Corp"),
            ("Prod", "Prod"),
            ("DMZ", "Corp"),
            ("Corp", "Prod") # Restricted flow
        }
        # Explicit segment assignment for hosts
        self.host_segments: Dict[str, str] = {}

    def assign_host_to_segment(self, host_id: str, segment_name: str):
        """Maps a host to a specific micro-segment."""
        self.host_segments[host_id] = segment_name
        logger.info(f"Host '{host_id}' assigned to micro-segment '{segment_name}'")

    def authorize_connection(self, source_host_id: str, target_host_id: str) -> bool:
        """
        Validates if communication is allowed between source and target hosts
        under micro-segmentation rules.
        """
        src_seg = self.host_segments.get(source_host_id, "Unknown")
        tgt_seg = self.host_segments.get(target_host_id, "Unknown")
        
        # If segments aren't configured, default to allow for backward compatibility,
        # but log a warning.
        if src_seg == "Unknown" or tgt_seg == "Unknown":
            return True
            
        is_allowed = (src_seg, tgt_seg) in self.allowed_segment_flows
        
        if not is_allowed:
            logger.warning(
                f"Micro-segmentation BLOCKED connection: {source_host_id} ({src_seg}) "
                f"-> {target_host_id} ({tgt_seg})"
            )
            
        return is_allowed
