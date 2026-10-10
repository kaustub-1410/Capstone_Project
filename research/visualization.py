"""
Research Visualization Module — Generates benchmark graphs and convergence curve plots.
"""

import logging
import os
import matplotlib.pyplot as plt
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ResearchVisualizer:
    """
    Creates publication-ready visualizations of research findings.
    """

    def __init__(self, output_dir: str = "research_outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def plot_gnn_latencies(self, benchmark_results: Dict[str, Dict[str, Any]], filename: str = "gnn_latency_comparison.png"):
        """Saves a bar chart comparing GNN model inference latencies."""
        models = list(benchmark_results.keys())
        latencies = [benchmark_results[m]["avg_inference_latency_ms"] for m in models]
        
        plt.figure(figsize=(8, 5))
        bars = plt.bar(models, latencies, color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"])
        
        plt.ylabel("Inference Latency (ms)", fontsize=12)
        plt.title("GNN Architecture Latency Comparison", fontsize=14)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Add labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2.0, height, f"{height:.2f} ms", ha='center', va='bottom')
            
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        logger.info(f"GNN latency comparison plot saved to {out_path}")

    def plot_scaling_curve(self, scaling_results: Dict[int, float], filename: str = "network_scaling_curve.png"):
        """Saves a line chart showing risk assessment time vs network host size."""
        sizes = sorted(list(scaling_results.keys()))
        latencies = [scaling_results[s] for s in sizes]
        
        plt.figure(figsize=(8, 5))
        plt.plot(sizes, latencies, marker='o', linewidth=2, color='purple')
        
        plt.xlabel("Network Size (Hosts)", fontsize=12)
        plt.ylabel("Inference Latency (ms)", fontsize=12)
        plt.title("Enterprise Topology Risk Evaluation Scaling Profile", fontsize=14)
        plt.grid(True, linestyle='--', alpha=0.5)
        
        out_path = os.path.join(self.output_dir, filename)
        plt.savefig(out_path, bbox_inches='tight')
        plt.close()
        logger.info(f"Network scaling curve plot saved to {out_path}")
