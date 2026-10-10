"""
LaTeX Exporter — Generates publication-ready LaTeX tables
for GNN latency and scaling benchmarks.
"""

import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

class LaTeXExporter:
    """
    Translates benchmark metrics dictionary structures into formatted LaTeX table documents.
    """

    def __init__(self, output_dir: str = "research_outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def export_gnn_latency_table(self, benchmark_results: Dict[str, Dict[str, Any]], filename: str = "gnn_latency_table.tex") -> str:
        """Exports GNN latencies to a LaTeX table file."""
        table = r"""\begin{table}[h]
\centering
\caption{Inference Latency Comparison Across GNN Architectures}
\label{tab:gnn_latencies}
\begin{tabular}{lcc}
\hline
\textbf{GNN Architecture} & \textbf{Average Latency (ms)} & \textbf{Total Time (s)} \\ \hline
"""
        for model, metrics in benchmark_results.items():
            model_name = model.upper()
            latency = metrics["avg_inference_latency_ms"]
            total_time = metrics["total_inference_time_seconds"]
            table += f"{model_name} & {latency:.3f} & {total_time:.4f} \\\\\n"
            
        table += r"""\hline
\end{tabular}
\end{table}
"""
        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "w") as f:
            f.write(table)
            
        logger.info(f"LaTeX table saved to {out_path}")
        return table
