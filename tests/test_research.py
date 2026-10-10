import os
import shutil
import pytest
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from research.experiment_runner import ExperimentRunner
from research.benchmarks import Benchmarker
from research.visualization import ResearchVisualizer
from research.latex_export import LaTeXExporter
from research.report_generator import ResearchReportGenerator

@pytest.fixture(scope="module")
def setup_research_topology():
    def factory():
        topo = NetworkTopology()
        topo.neo4j_enabled = False
        
        # 3 host subnet
        for i in range(1, 4):
            h = Host(id=f"H{i}", name=f"H{i}", ip=f"10.0.1.{i}", os="Linux", role="workstation")
            h.services.append(Service(name="SMB", port=445))
            topo.add_host(h)
            
        topo.add_connection("H1", "H2")
        topo.add_connection("H2", "H3")
        return topo
    return factory

def test_experiment_runner(setup_research_topology):
    output_dir = "test_research_outputs"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        
    runner = ExperimentRunner(output_dir=output_dir)
    results = runner.run_batch_simulation(
        topo_factory_fn=setup_research_topology,
        agent_type="random_attacker",
        num_trials=2,
        steps_per_trial=3
    )
    
    assert len(results) == 2
    assert results[0]["trial"] == 1
    assert "total_reward" in results[0]
    assert os.path.exists(os.path.join(output_dir, "campaign_random_attacker.json"))
    
    # Clean up
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

def test_benchmarker_visualizer_and_report(setup_research_topology):
    output_dir = "test_research_outputs_bm"
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
        
    benchmarker = Benchmarker()
    visualizer = ResearchVisualizer(output_dir=output_dir)
    exporter = LaTeXExporter(output_dir=output_dir)
    report_gen = ResearchReportGenerator(output_dir=output_dir)
    
    topo = setup_research_topology()
    
    # 1. Benchmark GNN
    gnn_results = benchmarker.benchmark_gnn_models(topo, iterations=2)
    assert "gcn" in gnn_results
    assert "avg_inference_latency_ms" in gnn_results["gcn"]
    
    # 2. Benchmark scaling
    scaling = benchmarker.benchmark_network_scaling(sizes=[5, 10], iterations=2)
    assert 5 in scaling
    
    # 3. Plot GNN latencies & scaling
    visualizer.plot_gnn_latencies(gnn_results)
    assert os.path.exists(os.path.join(output_dir, "gnn_latency_comparison.png"))
    
    visualizer.plot_scaling_curve(scaling)
    assert os.path.exists(os.path.join(output_dir, "network_scaling_curve.png"))
    
    # 4. LaTeX Export
    table = exporter.export_gnn_latency_table(gnn_results)
    assert r"\begin{tabular}" in table
    assert os.path.exists(os.path.join(output_dir, "gnn_latency_table.tex"))
    
    # 5. Report Gen
    paper = report_gen.generate_research_paper(gnn_results, scaling, table)
    assert "# AMCDS: Autonomous Multi-Agent Cyber Defense Simulator" in paper
    assert os.path.exists(os.path.join(output_dir, "amcds_research_paper.md"))
    
    # Clean up
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
