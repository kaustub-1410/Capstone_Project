"""
Benchmarks Module — Comparative evaluation of GNN architectures and RL algorithms.
"""

import logging
import time
from typing import Dict, Any, List
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from gnn_layer.predictor import NetworkRiskPredictor

logger = logging.getLogger(__name__)

class Benchmarker:
    """
    Benchmarks model execution speeds, convergence rewards, and scaling factors.
    """

    def benchmark_gnn_models(self, topo: NetworkTopology, iterations: int = 10) -> Dict[str, Any]:
        """Compares prediction latency and accuracy metrics across GNN architectures."""
        model_types = ["gcn", "gat", "gin", "transformer"]
        results = {}
        
        for model in model_types:
            predictor = NetworkRiskPredictor(model_type=model)
            
            start_time = time.perf_counter()
            for _ in range(iterations):
                predictor.predict_risk_scores(topo)
            elapsed = time.perf_counter() - start_time
            
            avg_latency_ms = (elapsed / iterations) * 1000.0
            results[model] = {
                "avg_inference_latency_ms": round(avg_latency_ms, 3),
                "total_inference_time_seconds": round(elapsed, 4)
            }
            
            logger.info(f"GNN Benchmark - {model.upper()}: latency={avg_latency_ms:.3f}ms")
            
        return results

    def benchmark_network_scaling(self, sizes: List[int], iterations: int = 5) -> Dict[int, float]:
        """Measures how risk prediction scales with large network sizes."""
        from simulation_engine.network_generator import NetworkGenerator
        generator = NetworkGenerator()
        scaling_results = {}
        
        for size in sizes:
            topo = generator.generate_network(num_hosts=size, include_cloud=False, include_iot=False)
            predictor = NetworkRiskPredictor(model_type="gcn")
            
            start = time.perf_counter()
            for _ in range(iterations):
                predictor.predict_risk_scores(topo)
            elapsed = time.perf_counter() - start
            
            avg_latency = (elapsed / iterations) * 1000.0
            scaling_results[size] = round(avg_latency, 2)
            logger.info(f"Scaling Benchmark - Size {size}: latency={avg_latency:.2f}ms")
            
        return scaling_results
