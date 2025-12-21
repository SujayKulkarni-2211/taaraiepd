"""
ML-Based Anomaly Detection & Similarity
========================================

Components:
1. Isolation Forest for anomaly detection
2. Quantum-inspired fidelity for similarity/memory
3. Persistent memory for learned patterns

NO RULES. Pure ML.
"""

import numpy as np
import json
import os
from typing import Dict, List, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.metrics.pairwise import cosine_similarity
import pickle


class MLAnomalyDetector:
    """Isolation Forest-based anomaly detector."""

    def __init__(self, model_path='models/isolation_forest.pkl'):
        self.model_path = model_path
        self.model = None
        self.is_trained = False

        # Create models directory
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        # Try to load existing model
        self.load()

    def train(self, embeddings: np.ndarray, contamination=0.2):
        """
        Train Isolation Forest on benign embeddings.

        Args:
            embeddings: np.ndarray of shape (n_samples, embedding_dim)
            contamination: Expected proportion of outliers (default: 0.2 - MORE SENSITIVE)

        Returns:
            dict: Training statistics
        """
        if len(embeddings) < 10:
            print(f"[MLAnomalyDetector] Warning: Only {len(embeddings)} samples - need at least 10")
            return {'status': 'insufficient_data', 'samples': len(embeddings)}

        print(f"[MLAnomalyDetector] Training Isolation Forest on {len(embeddings)} samples...")

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )

        self.model.fit(embeddings)
        self.is_trained = True

        # Save model
        self.save()

        print(f"[MLAnomalyDetector] Training complete")

        return {
            'status': 'success',
            'samples': len(embeddings),
            'contamination': contamination
        }

    def detect(self, embedding: np.ndarray) -> Dict[str, any]:
        """
        Detect if embedding is anomalous.

        Args:
            embedding: np.ndarray of shape (embedding_dim,) or (n_samples, embedding_dim)

        Returns:
            dict: {
                'is_anomaly': bool,
                'anomaly_score': float (negative = more anomalous),
                'confidence': float (0-1)
            }
        """
        if not self.is_trained or self.model is None:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'note': 'Model not trained - defaulting to benign'
            }

        # Handle single sample
        single_sample = embedding.ndim == 1
        if single_sample:
            embedding = embedding.reshape(1, -1)

        # Predict
        prediction = self.model.predict(embedding)  # 1 = normal, -1 = anomaly
        anomaly_score = self.model.score_samples(embedding)  # Higher = more normal

        # Convert to probabilities
        # Isolation Forest scores are typically in range [-0.5, 0.5]
        # Normalize to [0, 1] for confidence
        confidence = 1.0 / (1.0 + np.exp(-anomaly_score * 10))  # Sigmoid scaling

        result = {
            'is_anomaly': bool(prediction[0] == -1),
            'anomaly_score': float(anomaly_score[0]),
            'confidence': float(confidence[0])
        }

        if single_sample:
            return result
        else:
            return {
                'is_anomaly': [bool(p == -1) for p in prediction],
                'anomaly_score': anomaly_score.tolist(),
                'confidence': confidence.tolist()
            }

    def save(self):
        """Save model to disk."""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'is_trained': self.is_trained
                }, f)
            print(f"[MLAnomalyDetector] Model saved to {self.model_path}")
        except Exception as e:
            print(f"[MLAnomalyDetector] Save error: {e}")

    def load(self):
        """Load model from disk."""
        try:
            if not os.path.exists(self.model_path):
                print(f"[MLAnomalyDetector] No saved model found")
                return False

            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.is_trained = data['is_trained']

            print(f"[MLAnomalyDetector] Model loaded from {self.model_path}")
            return True

        except Exception as e:
            print(f"[MLAnomalyDetector] Load error: {e}")
            return False

    def is_ready(self) -> bool:
        """Check if model is trained and ready."""
        return self.is_trained and self.model is not None


class QuantumFidelity:
    """Quantum-inspired fidelity for similarity measurement."""

    @staticmethod
    def compute_fidelity(embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Compute quantum-inspired fidelity between two embeddings.

        Fidelity: F = |<ψ|φ>|² = (cosine_similarity + 1)² / 4
        This maps [-1, 1] cosine to [0, 1] fidelity.

        Args:
            embedding1: np.ndarray of shape (embedding_dim,)
            embedding2: np.ndarray of shape (embedding_dim,)

        Returns:
            float: Fidelity score in [0, 1]
        """
        # Reshape if needed
        if embedding1.ndim == 1:
            embedding1 = embedding1.reshape(1, -1)
        if embedding2.ndim == 1:
            embedding2 = embedding2.reshape(1, -1)

        # Compute cosine similarity
        cos_sim = cosine_similarity(embedding1, embedding2)[0, 0]

        # Quantum-inspired fidelity: |<ψ|φ>|²
        # Map cosine from [-1, 1] to [0, 1] then square
        fidelity = ((cos_sim + 1) / 2) ** 2

        return float(fidelity)

    @staticmethod
    def compute_distance(embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Compute distance (1 - fidelity).

        Returns:
            float: Distance in [0, 1]
        """
        return 1.0 - QuantumFidelity.compute_fidelity(embedding1, embedding2)


class BehaviorMemory:
    """
    Persistent memory for learned behavior patterns.

    Stores embeddings + labels (benign/suspicious) + admin actions.
    Used for: "Have we seen something equivalent before?"
    """

    def __init__(self, memory_path='models/behavior_memory.json'):
        self.memory_path = memory_path
        self.memory = {
            'benign': [],      # List of {embedding, timestamp, notes}
            'suspicious': [],  # List of {embedding, timestamp, action, notes}
        }

        # Create directory
        os.makedirs(os.path.dirname(memory_path), exist_ok=True)

        # Load existing memory
        self.load()

    def add_benign(self, embedding: np.ndarray, notes: str = ""):
        """Add a benign pattern to memory."""
        import time

        self.memory['benign'].append({
            'embedding': embedding.tolist(),
            'timestamp': time.time(),
            'notes': notes
        })

        self.save()

    def add_suspicious(self, embedding: np.ndarray, action: str, notes: str = ""):
        """Add a suspicious pattern with associated action to memory."""
        import time

        self.memory['suspicious'].append({
            'embedding': embedding.tolist(),
            'timestamp': time.time(),
            'action': action,
            'notes': notes
        })

        self.save()

    def find_similar(self, embedding: np.ndarray, category: str = 'all', threshold: float = 0.95) -> Optional[Dict]:
        """
        Find similar patterns in memory.

        Args:
            embedding: Query embedding
            category: 'benign', 'suspicious', or 'all'
            threshold: Fidelity threshold for similarity (default: 0.95 - STRICT)

        Returns:
            dict or None: {
                'category': 'benign' or 'suspicious',
                'fidelity': float,
                'match': dict (the memory entry),
                'action': str (if suspicious)
            }
        """
        best_match = None
        best_fidelity = 0.0

        # Search categories
        categories_to_search = []
        if category == 'all':
            categories_to_search = ['benign', 'suspicious']
        else:
            categories_to_search = [category]

        for cat in categories_to_search:
            for entry in self.memory.get(cat, []):
                stored_embedding = np.array(entry['embedding'])
                fidelity = QuantumFidelity.compute_fidelity(embedding, stored_embedding)

                if fidelity > best_fidelity and fidelity >= threshold:
                    best_fidelity = fidelity
                    best_match = {
                        'category': cat,
                        'fidelity': fidelity,
                        'match': entry,
                        'action': entry.get('action', None)
                    }

        return best_match

    def get_stats(self) -> Dict:
        """Get memory statistics."""
        return {
            'benign_count': len(self.memory['benign']),
            'suspicious_count': len(self.memory['suspicious']),
            'total': len(self.memory['benign']) + len(self.memory['suspicious'])
        }

    def save(self):
        """Save memory to disk."""
        try:
            with open(self.memory_path, 'w') as f:
                json.dump(self.memory, f, indent=2)
        except Exception as e:
            print(f"[BehaviorMemory] Save error: {e}")

    def load(self):
        """Load memory from disk."""
        try:
            if os.path.exists(self.memory_path):
                with open(self.memory_path, 'r') as f:
                    self.memory = json.load(f)
                print(f"[BehaviorMemory] Loaded memory: {self.get_stats()}")
            else:
                print(f"[BehaviorMemory] No existing memory found, starting fresh")
        except Exception as e:
            print(f"[BehaviorMemory] Load error: {e}")
            self.memory = {'benign': [], 'suspicious': []}
