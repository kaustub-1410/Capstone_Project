"""
Training Module — GNN model training pipeline.
Supports model training, validation, early stopping, checkpointing, and TensorBoard metric logging.
"""

import os
import logging
from typing import Dict, Any, Optional
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
try:
    from torch.utils.tensorboard import SummaryWriter
except Exception:
    class SummaryWriter:
        def __init__(self, *args, **kwargs): pass
        def add_scalar(self, *args, **kwargs): pass
        def close(self): pass

logger = logging.getLogger(__name__)

class GNNTrainer:
    """
    Manages GNN model training, validation, early stopping, and checkpointing.
    """

    def __init__(
        self,
        model: nn.Module,
        lr: float = 0.01,
        weight_decay: float = 5e-4,
        patience: int = 10,
        checkpoint_dir: str = "checkpoints",
        log_dir: str = "runs",
        device: str = "cpu"
    ):
        self.model = model.to(device)
        self.device = device
        self.optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
        self.criterion = nn.BCELoss()
        
        self.patience = patience
        self.checkpoint_dir = checkpoint_dir
        self.log_dir = log_dir
        
        os.makedirs(checkpoint_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        
        self.writer = SummaryWriter(log_dir=log_dir)

    def train_epoch(self, dataloader: DataLoader) -> float:
        self.model.train()
        total_loss = 0.0
        for batch in dataloader:
            x = batch["x"].to(self.device)
            adj = batch["adj"].to(self.device)
            y = batch["y"].to(self.device)
            
            self.optimizer.zero_grad()
            out = self.model(x, adj)
            loss = self.criterion(out, y)
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
            
        return total_loss / len(dataloader)

    def evaluate(self, dataloader: DataLoader) -> float:
        self.model.eval()
        total_loss = 0.0
        with torch.no_grad():
            for batch in dataloader:
                x = batch["x"].to(self.device)
                adj = batch["adj"].to(self.device)
                y = batch["y"].to(self.device)
                
                out = self.model(x, adj)
                loss = self.criterion(out, y)
                total_loss += loss.item()
                
        return total_loss / len(dataloader)

    def fit(self, train_loader: DataLoader, val_loader: Optional[DataLoader] = None, epochs: int = 100) -> Dict[str, Any]:
        """
        Trains the GNN model for specified epochs with early stopping on validation loss.
        """
        best_val_loss = float("inf")
        epochs_no_improve = 0
        history = {"train_loss": [], "val_loss": []}
        
        logger.info(f"Starting GNN training for {epochs} epochs...")
        
        for epoch in range(1, epochs + 1):
            train_loss = self.train_epoch(train_loader)
            history["train_loss"].append(train_loss)
            self.writer.add_scalar("Loss/Train", train_loss, epoch)
            
            val_loss = train_loss
            if val_loader:
                val_loss = self.evaluate(val_loader)
                history["val_loss"].append(val_loss)
                self.writer.add_scalar("Loss/Val", val_loss, epoch)
                logger.info(f"Epoch {epoch:03d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")
            else:
                logger.info(f"Epoch {epoch:03d} | Train Loss: {train_loss:.4f}")
                
            # Early Stopping Check
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                epochs_no_improve = 0
                # Save best checkpoint
                checkpoint_path = os.path.join(self.checkpoint_dir, "best_gnn_model.pt")
                torch.save(self.model.state_dict(), checkpoint_path)
                logger.debug(f"Saved best model checkpoint to {checkpoint_path}")
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= self.patience:
                    logger.info(f"Early stopping triggered at epoch {epoch}.")
                    break
                    
        # Load best model weights before returning
        best_path = os.path.join(self.checkpoint_dir, "best_gnn_model.pt")
        if os.path.exists(best_path):
            self.model.load_state_dict(torch.load(best_path))
            
        self.writer.close()
        return history
