import torch
from torch import nn
from torch.utils.data import DataLoader
from aegisnet.models.autoencoder import Autoencoder, FlowDataset


def train_autoencoder(
    csv_path,
    feature_cols,
    model_save_path="autoencoder.pt",
    batch_size=256,
    num_epochs=20,
    lr=1e-3,
    device=None,
):
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    dataset = FlowDataset(csv_path, feature_cols)
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
    )

    model = Autoencoder(input_dim=len(feature_cols))
    model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()

    for epoch in range(num_epochs):
        model.train()
        total_loss = 0.0

        for batch in dataloader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = model(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.size(0)

        avg_loss = total_loss / len(dataset)
        print(f"Epoch {epoch + 1}/{num_epochs} - loss={avg_loss:.6f}")

    # Save model + normalization stats and metadata
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "input_dim": len(feature_cols),
        "feature_cols": feature_cols,
        "mean": dataset.mean,
        "std": dataset.std,
    }
    torch.save(checkpoint, model_save_path)
    print(f"[OK] Saved model to {model_save_path}")


if __name__ == "__main__":
    # TODO: update these to match your actual CSV columns
    csv_path = "data/sample_flows.csv"
    feature_cols = [
        "bytes_in",
        "bytes_out",
        "packets",
        "duration",
        "src_port",
        "dst_port",
        "protocol",
    ]
    train_autoencoder(
        csv_path=csv_path,
        feature_cols=feature_cols,
        model_save_path="autoencoder.pt",
        batch_size=256,
        num_epochs=20,
        lr=1e-3,
    )
