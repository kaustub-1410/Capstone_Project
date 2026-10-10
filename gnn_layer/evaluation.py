"""
Evaluation Module — Computes accuracy, precision, recall, F1, AUC-ROC, confusion matrix,
and saves plots for publication-ready reports.
Implemented in pure PyTorch/Python to avoid scikit-learn dependency.
"""

import logging
import os
from typing import Dict, List, Tuple, Any
import torch
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)

def compute_metrics(y_true: torch.Tensor, y_pred: torch.Tensor, threshold: float = 0.5) -> Dict[str, Any]:
    """
    Computes key classification metrics: accuracy, precision, recall, F1 score.
    """
    # Flatten tensors
    y_true = y_true.view(-1)
    y_pred = y_pred.view(-1)
    
    # Binary predictions
    y_pred_bin = (y_pred >= threshold).float()
    
    tp = torch.sum((y_true == 1.0) & (y_pred_bin == 1.0)).item()
    fp = torch.sum((y_true == 0.0) & (y_pred_bin == 1.0)).item()
    fn = torch.sum((y_true == 1.0) & (y_pred_bin == 0.0)).item()
    tn = torch.sum((y_true == 0.0) & (y_pred_bin == 0.0)).item()
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn
    }

def compute_roc_curve(y_true: torch.Tensor, y_pred: torch.Tensor) -> Tuple[List[float], List[float], float]:
    """
    Computes ROC curve (FPR, TPR points) and AUC score.
    """
    y_true = y_true.view(-1).tolist()
    y_pred = y_pred.view(-1).tolist()
    
    # Pair and sort by prediction score descending
    pairs = sorted(zip(y_pred, y_true), key=lambda x: x[0], reverse=True)
    
    total_pos = sum(y_true)
    total_neg = len(y_true) - total_pos
    
    if total_pos == 0 or total_neg == 0:
        return [0.0, 1.0], [0.0, 1.0], 0.5
        
    fpr = [0.0]
    tpr = [0.0]
    
    tp = 0
    fp = 0
    auc = 0.0
    prev_fpr = 0.0
    
    for _, label in pairs:
        if label == 1.0:
            tp += 1
        else:
            fp += 1
            
        cur_fpr = fp / total_neg
        cur_tpr = tp / total_pos
        
        # Area under curve trapezoidal rule
        auc += (cur_fpr - prev_fpr) * cur_tpr
        
        fpr.append(cur_fpr)
        tpr.append(cur_tpr)
        prev_fpr = cur_fpr
        
    return fpr, tpr, auc

def plot_confusion_matrix(metrics: Dict[str, Any], output_path: str):
    """
    Generates and saves a confusion matrix visualization using Matplotlib.
    """
    tp, fp, tn, fn = metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]
    
    fig, ax = plt.subplots(figsize=(5, 5))
    cm = [[tn, fp], [fn, tp]]
    
    ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.3)
    for i in range(2):
        for j in range(2):
            ax.text(x=j, y=i, s=str(cm[i][j]), va='center', ha='center', size='xx-large')
            
    ax.set_xticklabels([''] + ['Negative', 'Positive'])
    ax.set_yticklabels([''] + ['Negative', 'Positive'])
    plt.xlabel('Predictions', fontsize=14)
    plt.ylabel('Actuals', fontsize=14)
    plt.title('Confusion Matrix', fontsize=16)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
