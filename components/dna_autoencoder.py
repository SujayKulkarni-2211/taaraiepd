"""
DNA Autoencoder
===============

Autoencoder for learning compact behavioral DNA embeddings.

Architecture:
    Input (19) → Hidden (64) → Bottleneck (8) → Hidden (64) → Output (19)

The bottleneck (8 dims) is the behavioral DNA — a compressed latent state
that captures the essence of normal behavior. This latent vector is what
gets quantum-encoded in the SWAP test for fidelity-based anomaly detection.

Training:
    - Trained ONLY on benign/baseline behavior
    - Reconstruction loss: MSE
    - Optimizer: Adam
    - Epochs: 50-100 (with early stopping)

Usage:
    - Encoder output (8-dim) → SWAP test quantum fidelity (primary detector)
    - Reconstruction error → classical corroborating signal
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
    """Autoencoder for behavioral DNA embedding. Bottleneck = 8 dims."""

    def __init__(self, input_dim=19, embedding_dim=8, hidden_dim=64):
        super(DNAAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim

        # Encoder: 19 → 64 → 8
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, embedding_dim),
            nn.Tanh()  # Tanh bounds latent space — better for amplitude encoding
        )

        # Decoder: 8 → 64 → 19
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

        self.model = DNAAutoencoder(input_dim=19, embedding_dim=8, hidden_dim=64)
        self.scaler = StandardScaler()
        self.is_trained = False

        # Online EMA of live feature distribution — blended with pretrained scaler at inference.
        # Tracks this server's actual behavior so normalization adapts without forgetting the
        # pretrained distribution (Cowrie/benchmark). Blend: 70% pretrained + 30% live.
        self._live_mean: np.ndarray | None = None
        self._live_std:  np.ndarray | None = None
        self._live_n:    int = 0
        self._ema_alpha: float = 0.05   # EMA decay — slow drift, not noisy per-sample update

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
        if len(data) < 3:
            print(f"[DNAEmbedder] Warning: Only {len(data)} samples - need at least 3 for training")
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

    def _update_live_stats(self, vec: np.ndarray):
        """EMA update of per-server mean and std from a single observation."""
        v = np.array(vec, dtype=np.float64).flatten()[:19]
        if self._live_mean is None:
            self._live_mean = v.copy()
            self._live_std  = np.ones(len(v), dtype=np.float64)
        else:
            self._live_mean = (1 - self._ema_alpha) * self._live_mean + self._ema_alpha * v
            self._live_std  = (1 - self._ema_alpha) * self._live_std  + self._ema_alpha * np.abs(v - self._live_mean)
        self._live_n += 1

    def _blended_transform(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features using a 70/30 blend of pretrained scaler and live EMA.
        Falls back to pure pretrained scaler until we have ≥10 live observations.
        """
        pretrained_norm = self.scaler.transform(np.clip(features, -10, 10))
        if self._live_n < 10 or self._live_mean is None:
            return pretrained_norm
        live_std = np.where(self._live_std > 1e-6, self._live_std, 1.0)
        live_norm = (features - self._live_mean) / live_std
        live_norm = np.clip(live_norm, -10, 10)
        return 0.7 * pretrained_norm + 0.3 * live_norm

    def embed(self, features: np.ndarray) -> np.ndarray:
        """
        Convert raw features to embeddings.

        Args:
            features: np.ndarray of shape (n_samples, 19) or (19,)

        Returns:
            np.ndarray: Embeddings of shape (n_samples, 64) or (64,)
        """
        if not self.is_ready():
            print("[DNAEmbedder] Warning: Model not ready, returning zeros")
            single_sample = features.ndim == 1
            if single_sample:
                return np.zeros(8, dtype=np.float32)
            else:
                return np.zeros((len(features), 8), dtype=np.float32)

        # Handle single sample
        single_sample = features.ndim == 1
        if single_sample:
            features = features.reshape(1, -1)

        # Update live EMA with this observation
        self._update_live_stats(features[0] if single_sample else features.mean(axis=0))

        # Normalize — blended scaler if live stats are mature (≥10 observations)
        try:
            features_normalized = self._blended_transform(features)
        except Exception as e:
            print(f"[DNAEmbedder] Scaling error: {e}")
            return np.zeros((len(features), 8), dtype=np.float32)

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

        # Normalize — same blended transform used in embed()
        features_normalized = self._blended_transform(features.reshape(1, -1))

        # Reconstruct
        self.model.eval()
        with torch.no_grad():
            X = torch.FloatTensor(features_normalized)
            reconstructed, _ = self.model(X)
            error = torch.mean((reconstructed - X) ** 2).item()

        return error

    def save_to(self, path: str):
        """Save model checkpoint to an arbitrary path (used for per-identity copies)."""
        try:
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'input_dim': self.model.input_dim,
                'embedding_dim': self.model.embedding_dim,
                'hidden_dim': self.model.hidden_dim,
                'is_trained': True
            }, path)
            print(f"[DNAEmbedder] Model saved to {path}")
        except Exception as e:
            print(f"[DNAEmbedder] save_to error: {e}")

    def save(self):
        """Save model and scaler to disk. Never touches dna_autoencoder_pretrained.pt."""
        pretrained_backup = self.model_path.replace('dna_autoencoder.pt', 'dna_autoencoder_pretrained.pt')
        try:
            # Save model
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'input_dim': self.model.input_dim,
                'embedding_dim': self.model.embedding_dim,
                'hidden_dim': self.model.hidden_dim,
                'is_trained': True
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
        """
        Load model and scaler from disk.

        Priority order:
          1. dna_autoencoder.pt       — finetuned working copy (if it exists)
          2. dna_autoencoder_pretrained.pt — canonical pretrained base (always present
                                             after running the experiment)

        This means: replacing dna_autoencoder_pretrained.pt with a better model
        automatically becomes the new base for all future finetuning sessions,
        because the working copy is rebuilt from it on the next clean start.
        """
        pretrained_path = self.model_path.replace(
            'dna_autoencoder.pt', 'dna_autoencoder_pretrained.pt'
        )
        # Decide which file to load from
        if os.path.exists(self.model_path):
            load_path = self.model_path
        elif os.path.exists(pretrained_path):
            load_path = pretrained_path
        else:
            print(f"[DNAEmbedder] No model found at {self.model_path} or {pretrained_path}")
            return False

        try:
            checkpoint = torch.load(load_path, weights_only=True)
            self.model = DNAAutoencoder(
                input_dim=checkpoint['input_dim'],
                embedding_dim=checkpoint['embedding_dim'],
                hidden_dim=checkpoint['hidden_dim']
            )
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.is_trained = True

            # Load scaler
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'r') as f:
                    scaler_data = json.load(f)
                if scaler_data['mean'] is not None:
                    self.scaler.mean_ = np.array(scaler_data['mean'])
                    self.scaler.scale_ = np.array(scaler_data['scale'])
                    self.scaler.var_ = np.array(scaler_data['var'])
                    self.scaler.n_samples_seen_ = len(scaler_data['mean'])

            src = "pretrained" if load_path == pretrained_path else "finetuned"
            print(f"[DNAEmbedder] Loaded {src} model from {load_path} (embedding_dim={checkpoint['embedding_dim']})")
            return True

        except Exception as e:
            print(f"[DNAEmbedder] Load error: {e}")
            return False

    def finetune(self, data: np.ndarray, epochs: int = 10, lr: float = 0.0005) -> dict:
        """
        Finetune existing model weights on new live data without resetting the scaler.
        Requires the model to already be trained (loaded from disk).
        Uses a lower LR and fewer epochs — adapts the model to the current server's behavior
        without forgetting the base representation learned from the large dataset.
        """
        if not self.is_ready():
            # No pretrained model — fall back to full train
            return self.train(data, epochs=min(50, epochs * 5), lr=lr)

        if len(data) < 3:
            print(f"[DNAEmbedder] Finetune: only {len(data)} samples, skipping AE update")
            return {'status': 'skipped', 'reason': 'too_few_samples', 'samples': len(data)}

        print(f"[DNAEmbedder] Finetuning on {len(data)} live samples ({epochs} epochs, lr={lr})...")
        # Seed live stats from the baseline batch before finetuning so blended
        # normalization is consistent between finetune and subsequent inference calls.
        for vec in data:
            self._update_live_stats(vec)
        data_normalized = self._blended_transform(data)
        X = torch.FloatTensor(data_normalized)

        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        self.model.train()
        best_loss = float('inf')
        best_epoch = 0
        for epoch in range(epochs):
            reconstructed, _ = self.model(X)
            loss = criterion(reconstructed, X)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            if loss.item() < best_loss:
                best_loss = loss.item()
                best_epoch = epoch

        # No deepcopy per-epoch — finetuning with small data converges monotonically
        # so final weights are the best weights. Disk persistence is caller's job.
        self.is_trained = True
        print(f"[DNAEmbedder] Finetune complete. Final loss: {best_loss:.6f}")
        return {'status': 'success', 'epochs_trained': epochs, 'final_loss': best_loss, 'samples': len(data)}

    def load_identity(self, host: str, finetuned_dir: str = 'models/finetuned') -> bool:
        """
        Try to load a per-identity finetuned model for this host.
        Falls back to the base pretrained model if no identity checkpoint exists.
        """
        safe_host = host.replace('.', '_').replace(':', '_')
        identity_path = os.path.join(finetuned_dir, f'{safe_host}_ae.pt')
        if os.path.exists(identity_path):
            try:
                checkpoint = torch.load(identity_path, weights_only=True)
                self.model = DNAAutoencoder(
                    input_dim=checkpoint['input_dim'],
                    embedding_dim=checkpoint['embedding_dim'],
                    hidden_dim=checkpoint['hidden_dim']
                )
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.is_trained = True
                print(f"[DNAEmbedder] Loaded identity-specific model for {host}")
                return True
            except Exception as e:
                print(f"[DNAEmbedder] Identity model load error for {host}: {e}")
        return False

    def is_ready(self) -> bool:
        """Check if model is trained and ready."""
        # Check if scaler has been fitted (mean_ is set after fit)
        scaler_fitted = hasattr(self.scaler, 'mean_') and self.scaler.mean_ is not None
        return self.is_trained and scaler_fitted
