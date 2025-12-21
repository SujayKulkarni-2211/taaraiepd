"""
Training Workflow Manager
==========================

Manages initial training and online learning for all ML models.

Workflow:
    1. Cold Start: Collect baseline benign data
    2. Initial Training: Train autoencoder + isolation forest
    3. Online Learning: Incremental updates from admin feedback

Safety:
    - Fallback to notify-only if models untrained
    - Graceful degradation if insufficient data
    - All training is non-blocking (VPS safe)
"""

import time
import json
import os
from typing import Dict, Any, List, Optional
import numpy as np


class TrainingManager:
    """Manages training workflows for all ML components."""

    def __init__(self, dna_collector, embedder, anomaly_detector, memory, config_path='models/training_config.json'):
        self.dna_collector = dna_collector
        self.embedder = embedder
        self.anomaly_detector = anomaly_detector
        self.memory = memory
        self.config_path = config_path

        # Training state
        self.training_state = {
            'baseline_collected': False,
            'embedder_trained': False,
            'anomaly_detector_trained': False,
            'baseline_samples': 0,
            'last_training_time': None,
            'training_history': []
        }

        # Load state
        self.load_state()

    def collect_baseline(self, ssh_manager, duration_minutes: int = 5, interval_seconds: int = 30) -> Dict[str, Any]:
        """
        Collect baseline benign behavior.

        Args:
            ssh_manager: SSH connection to VPS
            duration_minutes: How long to collect (default: 5 minutes)
            interval_seconds: Sampling interval (default: 30 seconds)

        Returns:
            dict: Collection results
        """
        print(f"[TrainingManager] Collecting baseline for {duration_minutes} minutes...")
        print(f"  Sampling every {interval_seconds} seconds")
        print("  IMPORTANT: Ensure normal operation during this time (no attacks, no unusual activity)")

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)

        baseline_data = []
        sample_count = 0

        try:
            while time.time() < end_time:
                # Collect DNA sample
                feature_vector = self.dna_collector.get_feature_vector()

                baseline_data.append(feature_vector)
                sample_count += 1

                remaining = int(end_time - time.time())
                print(f"  Collected {sample_count} samples... ({remaining}s remaining)")

                # Wait for next interval
                if time.time() < end_time:
                    time.sleep(interval_seconds)

            # Convert to numpy array
            baseline_array = np.array(baseline_data)

            print(f"[TrainingManager] Baseline collection complete: {sample_count} samples")

            # Save baseline
            os.makedirs('models', exist_ok=True)
            np.save('models/baseline_data.npy', baseline_array)

            self.training_state['baseline_collected'] = True
            self.training_state['baseline_samples'] = sample_count
            self.save_state()

            return {
                'status': 'success',
                'samples': sample_count,
                'duration': duration_minutes,
                'data_shape': baseline_array.shape,
                'message': f'Collected {sample_count} baseline samples'
            }

        except Exception as e:
            return {
                'status': 'error',
                'samples': sample_count,
                'message': f'Baseline collection failed: {str(e)}'
            }

    def train_initial_models(self) -> Dict[str, Any]:
        """
        Train autoencoder and isolation forest on baseline data.

        Returns:
            dict: Training results
        """
        print("[TrainingManager] Training initial models...")

        try:
            # Load baseline data
            if not os.path.exists('models/baseline_data.npy'):
                return {
                    'status': 'error',
                    'message': 'No baseline data found. Run collect_baseline() first.'
                }

            baseline_data = np.load('models/baseline_data.npy')

            if len(baseline_data) < 10:
                return {
                    'status': 'error',
                    'message': f'Insufficient baseline data: {len(baseline_data)} samples (need at least 10)'
                }

            print(f"  Loaded {len(baseline_data)} baseline samples")

            # Train autoencoder
            print("  Training autoencoder...")
            autoencoder_result = self.embedder.train(
                data=baseline_data,
                epochs=100,
                lr=0.001,
                batch_size=min(32, len(baseline_data)),
                early_stopping_patience=10
            )

            if autoencoder_result['status'] != 'success':
                return {
                    'status': 'error',
                    'message': f"Autoencoder training failed: {autoencoder_result}"
                }

            self.training_state['embedder_trained'] = True

            # Get embeddings
            print("  Generating embeddings...")
            embeddings = self.embedder.embed(baseline_data)

            # Train isolation forest
            print("  Training isolation forest...")
            detector_result = self.anomaly_detector.train(
                embeddings=embeddings,
                contamination=0.1
            )

            if detector_result['status'] != 'success':
                return {
                    'status': 'error',
                    'message': f"Anomaly detector training failed: {detector_result}"
                }

            self.training_state['anomaly_detector_trained'] = True
            self.training_state['last_training_time'] = time.time()

            # Add to history
            self.training_state['training_history'].append({
                'timestamp': time.time(),
                'samples': len(baseline_data),
                'autoencoder_loss': autoencoder_result.get('final_loss', 0),
                'detector_contamination': detector_result.get('contamination', 0.1)
            })

            self.save_state()

            print("[TrainingManager] Initial training complete!")

            return {
                'status': 'success',
                'baseline_samples': len(baseline_data),
                'autoencoder': autoencoder_result,
                'detector': detector_result,
                'message': 'All models trained successfully'
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Training failed: {str(e)}'
            }

    def online_update(self, new_samples: List[np.ndarray], labels: List[str]) -> Dict[str, Any]:
        """
        Incrementally update models with new labeled data.

        Args:
            new_samples: List of feature vectors
            labels: List of labels ('benign' or 'suspicious')

        Returns:
            dict: Update results
        """
        if not self.is_ready():
            return {
                'status': 'error',
                'message': 'Models not trained yet. Run train_initial_models() first.'
            }

        try:
            # Filter benign samples
            benign_samples = [s for s, l in zip(new_samples, labels) if l == 'benign']

            if not benign_samples:
                return {
                    'status': 'skipped',
                    'message': 'No benign samples to update'
                }

            # Add to baseline
            existing_baseline = np.load('models/baseline_data.npy')
            updated_baseline = np.vstack([existing_baseline, np.array(benign_samples)])

            # Re-train (incremental)
            # For simplicity, we retrain on full data (could use incremental learning later)
            print(f"[TrainingManager] Online update with {len(benign_samples)} new benign samples...")

            autoencoder_result = self.embedder.train(
                data=updated_baseline,
                epochs=20,  # Fewer epochs for incremental
                lr=0.0005,  # Lower learning rate
                batch_size=min(32, len(updated_baseline))
            )

            # Update anomaly detector
            embeddings = self.embedder.embed(updated_baseline)
            detector_result = self.anomaly_detector.train(embeddings=embeddings)

            # Save updated baseline
            np.save('models/baseline_data.npy', updated_baseline)

            self.training_state['baseline_samples'] = len(updated_baseline)
            self.training_state['last_training_time'] = time.time()
            self.save_state()

            return {
                'status': 'success',
                'new_samples': len(benign_samples),
                'total_samples': len(updated_baseline),
                'message': f'Models updated with {len(benign_samples)} new samples'
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Online update failed: {str(e)}'
            }

    def is_ready(self) -> bool:
        """Check if all models are trained and ready."""
        return (
            self.training_state['baseline_collected'] and
            self.training_state['embedder_trained'] and
            self.training_state['anomaly_detector_trained'] and
            self.embedder.is_ready() and
            self.anomaly_detector.is_ready()
        )

    def get_status(self) -> Dict[str, Any]:
        """Get current training status."""
        return {
            'ready': self.is_ready(),
            'baseline_collected': self.training_state['baseline_collected'],
            'baseline_samples': self.training_state['baseline_samples'],
            'embedder_trained': self.training_state['embedder_trained'],
            'anomaly_detector_trained': self.training_state['anomaly_detector_trained'],
            'last_training_time': self.training_state['last_training_time'],
            'training_count': len(self.training_state['training_history']),
            'memory_stats': self.memory.get_stats()
        }

    def get_fallback_mode(self) -> str:
        """Get fallback mode if models not ready."""
        if not self.is_ready():
            return 'notify_only'  # Safe default
        return 'full_agent'

    def save_state(self):
        """Save training state to disk."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.training_state, f, indent=2)
        except Exception as e:
            print(f"[TrainingManager] Save error: {e}")

    def load_state(self):
        """Load training state from disk."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.training_state = json.load(f)
                print(f"[TrainingManager] Loaded training state: {self.get_status()}")
        except Exception as e:
            print(f"[TrainingManager] Load error: {e}")

    def quick_start(self, ssh_manager, quick_mode: bool = False) -> Dict[str, Any]:
        """
        Quick start workflow: collect baseline + train models.

        Args:
            ssh_manager: SSH connection
            quick_mode: If True, use shorter collection time (2 min) for testing

        Returns:
            dict: Results
        """
        duration = 2 if quick_mode else 5
        interval = 10 if quick_mode else 30  # Faster sampling for quick mode (10s = 12 samples in 2min)

        print("[TrainingManager] Quick Start Workflow")
        print("=" * 50)

        # Step 1: Collect baseline
        baseline_result = self.collect_baseline(
            ssh_manager,
            duration_minutes=duration,
            interval_seconds=interval
        )

        if baseline_result['status'] != 'success':
            return baseline_result

        # Step 2: Train models
        training_result = self.train_initial_models()

        return training_result
