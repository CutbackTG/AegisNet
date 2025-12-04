import torch
import numpy as np

from aegisnet.models.autoencoder import Autoencoder


class AnomalyScorer:
    """
    Wraps an Autoencoder model to compute anomaly scores for
    single flows and batches of flows.
    """

    def __init__(self, checkpoint_path: str):
        """Load model and metadata from a training checkpoint."""
        self.device = "cpu"

        # Load checkpoint (contains weights & metadata)
        checkpoint = torch.load(
            checkpoint_path,
            map_location=self.device,
            weights_only=False,  # Required for full checkpoint structures
        )

        # Extract preprocessing metadata
        self.feature_cols = checkpoint.get("feature_cols", [])
        self.mean = checkpoint.get("mean", None)
        self.std = checkpoint.get("std", None)

        # Build model using stored input dimension
        input_dim = checkpoint.get("input_dim", len(self.feature_cols))
        self.model = Autoencoder(input_dim=input_dim).to(self.device)

        # Load only the neural network weights
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()

        print(f"[Scorer Ready] Device: {self.device}, Input dim: {input_dim}")

    # ------------------------------------------------------------------
    # Internal preprocessing
    # ------------------------------------------------------------------
    def _preprocess(self, flow: dict) -> np.ndarray:
        """
        Convert a flow dictionary into a normalized feature vector.
        """
        x = np.array(
            [flow[col] for col in self.feature_cols],
            dtype=np.float32,
        )

        # Apply normalization if stats were saved
        if self.mean is not None and self.std is not None:
            x = (x - self.mean) / (self.std + 1e-8)

        return x

    # ------------------------------------------------------------------
    # Single-flow scoring API
    # ------------------------------------------------------------------
    def score(self, flow: dict) -> float:
        """
        Compute anomaly score (MSE reconstruction error) for a single flow.
        """
        x = self._preprocess(flow)
        x_tensor = torch.tensor(x, dtype=torch.float32).to(self.device)

        with torch.no_grad():
            recon = self.model(x_tensor)
            mse = torch.mean((recon - x_tensor) ** 2).item()

        return mse

    # ------------------------------------------------------------------
    # Batch scoring API
    # ------------------------------------------------------------------
    def score_batch(self, flows: list[dict]) -> list[float]:
        """
        Compute anomaly scores for a batch of flows.
        Returns a list of MSE values.
        """
        X = np.stack([self._preprocess(f) for f in flows], axis=0)
        X_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)

        with torch.no_grad():
            recon = self.model(X_tensor)
            mse = torch.mean((recon - X_tensor) ** 2, dim=1)
            mse = mse.cpu().numpy()

        return mse.tolist()
