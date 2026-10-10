import os
import shutil
import pytest
import torch
from torch.utils.data import DataLoader
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from gnn_layer.datasets import CyberSecurityDataset
from gnn_layer.models import GCNModel
from gnn_layer.models_advanced import GINModel, GraphTransformerModel
from gnn_layer.training import GNNTrainer
from gnn_layer.evaluation import compute_metrics, compute_roc_curve
from gnn_layer.predictor import NetworkRiskPredictor

@pytest.fixture(scope="module")
def sample_snapshots():
    snapshots = []
    for _ in range(5):
        topo = NetworkTopology()
        topo.neo4j_enabled = False
        
        # Build a small network topology
        h1 = Host(id="H1", name="H1", ip="10.0.0.1", os="Linux", role="web_server", compromised=True)
        h2 = Host(id="H2", name="H2", ip="10.0.0.2", os="Windows", role="workstation", compromised=False)
        h3 = Host(id="H3", name="H3", ip="10.0.0.3", os="Windows", role="domain_controller", compromised=False)
        
        h1.services.append(Service(name="HTTP", port=80))
        h2.services.append(Service(name="SMB", port=445))
        h3.services.append(Service(name="LDAP", port=389))
        
        topo.add_host(h1)
        topo.add_host(h2)
        topo.add_host(h3)
        topo.add_connection("H1", "H2")
        topo.add_connection("H2", "H3")
        
        snapshots.append(topo)
    return snapshots

def test_gnn_dataset(sample_snapshots):
    dataset = CyberSecurityDataset(sample_snapshots)
    assert len(dataset) == 5
    
    item = dataset[0]
    assert "x" in item
    assert "edge_index" in item
    assert "adj" in item
    assert "y" in item
    
    # 3 nodes, 4 features
    assert item["x"].shape == (3, 4)
    # Binary classification target shape: 3 nodes, 1 label
    assert item["y"].shape == (3, 1)

def test_advanced_models():
    in_dim = 4
    hidden_dim = 8
    out_dim = 1
    N = 3
    
    X = torch.rand((N, in_dim))
    adj = torch.eye(N)
    adj[0, 1] = adj[1, 0] = 1.0
    
    gin = GINModel(in_dim, hidden_dim, out_dim)
    transformer = GraphTransformerModel(in_dim, hidden_dim, out_dim)
    
    out_gin = gin(X, adj)
    out_transformer = transformer(X, adj)
    
    assert out_gin.shape == (N, out_dim)
    assert out_transformer.shape == (N, out_dim)

def test_gnn_trainer_and_checkpointing(sample_snapshots):
    checkpoint_dir = "test_checkpoints"
    log_dir = "test_runs"
    
    # Ensure clean state
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
        
    dataset = CyberSecurityDataset(sample_snapshots)
    dataloader = DataLoader(dataset, batch_size=2, shuffle=True)
    
    model = GCNModel(in_dim=4, hidden_dim=8, out_dim=1)
    trainer = GNNTrainer(
        model=model,
        lr=0.01,
        patience=5,
        checkpoint_dir=checkpoint_dir,
        log_dir=log_dir
    )
    
    history = trainer.fit(dataloader, epochs=5)
    
    assert len(history["train_loss"]) > 0
    assert os.path.exists(os.path.join(checkpoint_dir, "best_gnn_model.pt"))
    
    # Clean up directories
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)

def test_gnn_evaluation():
    y_true = torch.tensor([[1.0], [0.0], [1.0], [0.0]])
    y_pred = torch.tensor([[0.9], [0.1], [0.8], [0.2]])
    
    metrics = compute_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["f1_score"] == 1.0
    
    fpr, tpr, auc = compute_roc_curve(y_true, y_pred)
    assert auc == 1.0
    assert len(fpr) > 0

def test_risk_predictor_advanced_and_load(sample_snapshots):
    checkpoint_dir = "test_checkpoints_pred"
    os.makedirs(checkpoint_dir, exist_ok=True)
    checkpoint_path = os.path.join(checkpoint_dir, "best_gnn_model.pt")
    
    # Train a model quickly to save weights
    model = GINModel(in_dim=4, hidden_dim=8, out_dim=1)
    torch.save(model.state_dict(), checkpoint_path)
    
    # Initialize predictor
    predictor = NetworkRiskPredictor(model_type="gin", hidden_dim=8)
    predictor.load_trained_model(checkpoint_path)
    
    topo = sample_snapshots[0]
    scores = predictor.predict_risk_scores(topo)
    
    assert "H1" in scores
    assert isinstance(scores["H1"], float)
    
    # Clean up checkpoint
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
