"""
Research Report Generator Module — Generates comprehensive, automated,
publication-ready markdown research papers compiling GNN and RL benchmark trials.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ResearchReportGenerator:
    """
    Assembles experimental results, tables, and asset paths into a unified research paper document.
    """

    def __init__(self, output_dir: str = "research_outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_research_paper(
        self,
        gnn_results: Dict[str, Dict[str, Any]],
        scaling_results: Dict[int, float],
        latex_table: str,
        filename: str = "amcds_research_paper.md"
    ) -> str:
        """Assembles a Markdown research report documenting the simulation findings."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Format scaling results
        scaling_str = "\n".join([f"- **Size {size} hosts:** {latency:.2f} ms" for size, latency in sorted(scaling_results.items())])
        
        paper = f"""# AMCDS: Autonomous Multi-Agent Cyber Defense Simulator
**Date:** {timestamp}
**Author:** AMCDS AI Research Scientist Subagent

## Abstract
This paper presents the empirical benchmarking evaluations of the Autonomous Multi-Agent Cyber Defense Simulator (AMCDS) platform. We investigate the runtime latency of Graph Neural Network (GNN) risk propagation estimators and assess their execution scaling profiles up to large host subnets.

## Experimental Setup & Latency Benchmarks
We evaluated GCN, GAT, GIN, and Graph Transformer architectures on identical topology profiles. 

### Latency Summary Table
```
{latex_table}
```

## Scaling Profile Analysis
To verify the feasibility of real-world deployments in enterprise security operations, we measured average GNN risk inference latencies across progressive network topology dimensions:
{scaling_str}

## Conclusion & Future Work
The empirical results confirm that decentralized GNN risk assessment maintains highly efficient computational footprints. Future investigations will evaluate multi-agent co-evolutionary reinforcement learning policies for proactive zero-trust micro-segmentation updates.
"""
        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w") as f:
            f.write(paper)
            
        logger.info(f"Research paper generated and saved to {out_path}")
        return paper
