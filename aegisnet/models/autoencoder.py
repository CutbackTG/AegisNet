# models/autoencoder.py
import torch
from torch import nn
from torch.utils.data import Dataset
import pandas as pd
import numpy as np


class FlowDataset(Dataset):
    """
    Dataset for network flow records stored in a CSV file.

    Each row should contain numeric columns listed in feature_cols.
    Example columns:
      - bytes_in, bytes_out, packets, duration, src_port, dst_port, protocol
    """

    def __init__(self, csv_path, feature_cols, normalize=True):
        df = pd.read_csv(csv_path)

        # Keep only the feature columns and convert to float32
        self.features = df[feature_cols].astype(np.float32).values

        # Simple z-score normalization
        if normalize:
            self.mean = self.features.mean(axis=0, keepdims=True)
            self.std = self.features.std(axis=0, keepdims=True) + 1e-6
            self.features = (self.features - self.mean) / self.std
        else:
            self.mean = np.zeros((1, self.features.shape[1]), dtype=np.float32)
            self.std = np.ones((1, self.features.shape[1]), dtype=np.float32)

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        x = self.features[idx]
        return torch.from_numpy(x)


class Autoencoder(nn.Module):
    """
    Basic fully-connected autoencoder for tabular features.
    """

    def __init__(self, input_dim, hidden_dims=(64, 32, 16)):
        super().__init__()

        # Encoder
        encoder_layers = []
        last_dim = input_dim
        for h in hidden_dims:
            encoder_layers.append(nn.Linear(last_dim, h))
            encoder_layers.append(nn.ReLU())
            last_dim = h
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder (mirror of encoder)
        decoder_layers = []
        hidden_dims_dec = list(hidden_dims[::-1])
        for h in hidden_dims_dec[1:]:
            decoder_layers.append(nn.Linear(last_dim, h))
            decoder_layers.append(nn.ReLU())
            last_dim = h
        decoder_layers.append(nn.Linear(last_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x):
        z = self.encoder(x)
        x_hat = self.decoder(z)
        return x_hat
