"""
DNA Autoencoder
===============

Autoencoder for learning compact embeddings of system behavior.

Architecture:
    Input (19 dims) → Encoder (64 hidden) → Bottleneck (64/128 dims) → Decoder (64 hidden) → Output (19 dims)

Training:
    - Trained ONLY on benign/baseline behavior
    - Reconstruction loss: MSE
    - Optimizer: Adam
    - Epochs: 50-100 (with early stopping)

Usage:
    - Encoder output = embedding for downstream tasks
    - Reconstruction error = additional anomaly signal
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import json
import os
from typing import List, Tuple, Optional
from sklearn.preprocessing import StandardScaler


class DNAAutoencoder(nn.Module):
    """Autoencoder for DNA feature embedding."""

    def __init__(self, input_dim=19, embedding_dim=64, hidden_dim=64):
        super(DNAAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, embedding_dim),
            nn.ReLU()
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(embedding_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, input_dim)
        )

    def forward(self, x):
        """Forward pass: encode then decode."""
        embedding = self.encoder(x)
        reconstruction = self.decoder(embedding)
        return reconstruction, embedding

    def encode(self, x):
        """Encode input to embedding."""
        return self.encoder(x)


class DNAEmbedder:
    """Manages DNA autoencoder training and inference."""

    def __init__(self, model_path='models/dna_autoencoder.pt', scaler_path='models/dna_scaler.json'):
        self.model_path = model_path
        self.scaler_path = scaler_path

        # Create models directory
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        self.model = DNAAutoencoder(input_dim=19, embedding_dim=64, hidden_dim=64)
        self.scaler = StandardScaler()
        self.is_trained = False

        # Try to load existing model
        self.load()

    def train(self, data: np.ndarray, epochs=100, lr=0.001, batch_size=32, early_stopping_patience=10):
        """
        Train autoencoder on benign baseline data.

        Args:
            data: np.ndarray of shape (n_samples, 19) - benign behavior samples
            epochs: Maximum training epochs
            lr: Learning rate
            batch_size: Batch size
            early_stopping_patience: Stop if no improvement for N epochs

        Returns:
            dict: Training statistics
        """
        if len(data) < 10:
            print(f"[DNAEmbedder] Warning: Only {len(data)} samples - need at least 10 for training")
            return {'status': 'insufficient_data', 'samples': len(data)}

        print(f"[DNAEmbedder] Training autoencoder on {len(data)} benign samples...")

        # Normalize data
        self.scaler.fit(data)
        data_normalized = self.scaler.transform(data)

        # Convert to torch
        X = torch.FloatTensor(data_normalized)

        # Training setup
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)

        # Early stopping
        best_loss = float('inf')
        patience_counter = 0

        losses = []

        self.model.train()
        for epoch in range(epochs):
            epoch_loss = 0.0
            num_batches = 0

            # Mini-batch training
            indices = torch.randperm(len(X))
            for i in range(0, len(X), batch_size):
                batch_indices = indices[i:i+batch_size]
                batch = X[batch_indices]

                # Forward pass
                reconstructed, _ = self.model(batch)
                loss = criterion(reconstructed, batch)

                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            avg_loss = epoch_loss / num_batches
            losses.append(avg_loss)

            # Early stopping check
            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
                # Save best model
                self.save()
            else:
                patience_counter += 1

            if epoch % 10 == 0:
                print(f"  Epoch {epoch}/{epochs}, Loss: {avg_loss:.6f}")

            if patience_counter >= early_stopping_patience:
                print(f"  Early stopping at epoch {epoch}")
                break

        self.is_trained = True
        print(f"[DNAEmbedder] Training complete. Final loss: {best_loss:.6f}")

        return {
            'status': 'success',
            'epochs_trained': epoch + 1,
            'final_loss': best_loss,
            'samples': len(data)
        }

    def embed(self, features: np.ndarray) -> np.ndarray:
        """
        Convert raw features to embeddings.

        Args:
            features: np.ndarray of shape (n_samples, 19) or (19,)

        Returns:
            np.ndarray: Embeddings of shape (n_samples, 64) or (64,)
        """
        if not self.is_trained:
            print("[DNAEmbedder] Warning: Model not trained, returning zeros")
            single_sample = features.ndim == 1
            if single_sample:
                return np.zeros(64, dtype=np.float32)
            else:
                return np.zeros((len(features), 64), dtype=np.float32)

        # Handle single sample
        single_sample = features.ndim == 1
        if single_sample:
            features = features.reshape(1, -1)

        # Normalize
        try:
            features_normalized = self.scaler.transform(features)
        except Exception as e:
            print(f"[DNAEmbedder] Scaling error: {e}")
            return np.zeros((len(features), 64), dtype=np.float32)

        # Embed
        self.model.eval()
        with torch.no_grad():
            X = torch.FloatTensor(features_normalized)
            embeddings = self.model.encode(X).numpy()

        if single_sample:
            return embeddings[0]
        return embeddings

    def reconstruction_error(self, features: np.ndarray) -> float:
        """
        Compute reconstruction error (useful as anomaly signal).

        Args:
            features: np.ndarray of shape (19,)

        Returns:
            float: MSE reconstruction error
        """
        if not self.is_trained:
            return 0.0

        # Normalize
        features_normalized = self.scaler.transform(features.reshape(1, -1))

        # Reconstruct
        self.model.eval()
        with torch.no_grad():
            X = torch.FloatTensor(features_normalized)
            reconstructed, _ = self.model(X)
            error = torch.mean((reconstructed - X) ** 2).item()

        return error

    def save(self):
        """Save model and scaler to disk."""
        try:
            # Save model
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'input_dim': self.model.input_dim,
                'embedding_dim': self.model.embedding_dim,
                'hidden_dim': self.model.hidden_dim,
                'is_trained': self.is_trained
            }, self.model_path)

            # Save scaler
            scaler_data = {
                'mean': self.scaler.mean_.tolist() if hasattr(self.scaler, 'mean_') else None,
                'scale': self.scaler.scale_.tolist() if hasattr(self.scaler, 'scale_') else None,
                'var': self.scaler.var_.tolist() if hasattr(self.scaler, 'var_') else None
            }

            with open(self.scaler_path, 'w') as f:
                json.dump(scaler_data, f)

            print(f"[DNAEmbedder] Model saved to {self.model_path}")

        except Exception as e:
            print(f"[DNAEmbedder] Save error: {e}")

    def load(self):
        """Load model and scaler from disk."""
        try:
            if not os.path.exists(self.model_path):
                print(f"[DNAEmbedder] No saved model found at {self.model_path}")
                return False

            # Load model
            checkpoint = torch.load(self.model_path, weights_only=True)
            self.model = DNAAutoencoder(
                input_dim=checkpoint['input_dim'],
                embedding_dim=checkpoint['embedding_dim'],
                hidden_dim=checkpoint['hidden_dim']
            )
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.is_trained = checkpoint.get('is_trained', True)

            # Load scaler
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'r') as f:
                    scaler_data = json.load(f)

                if scaler_data['mean'] is not None:
                    self.scaler.mean_ = np.array(scaler_data['mean'])
                    self.scaler.scale_ = np.array(scaler_data['scale'])
                    self.scaler.var_ = np.array(scaler_data['var'])
                    # Set n_samples_seen_ to make sklearn happy
                    self.scaler.n_samples_seen_ = len(scaler_data['mean'])

            print(f"[DNAEmbedder] Model loaded from {self.model_path}")
            return True

        except Exception as e:
            print(f"[DNAEmbedder] Load error: {e}")
            return False

    def is_ready(self) -> bool:
        """Check if model is trained and ready."""
        # Check if scaler has been fitted (mean_ is set after fit)
        scaler_fitted = hasattr(self.scaler, 'mean_') and self.scaler.mean_ is not None
        return self.is_trained and scaler_fitted
