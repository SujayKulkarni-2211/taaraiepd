"""
Enhanced Training Manager
==========================

Training modes:
1. Quick Demo Training (2 minutes) - Snapshot every second, 120 samples
2. Demo Training (5 minutes) - Snapshot every 10 seconds, 30 samples
3. Standard Training (15 minutes) - 30-second intervals
4. Full Training (1 hour) - Production-grade training
5. Continuous Training - Runs until stopped (subscription tier)

Trains:
- DNA Autoencoder (behavioral embedding)
- Isolation Forest (anomaly detection)
- TAARA Memory Basis (per-identity reconstruction)
- Quantum Validator (residual direction memory)
"""

import streamlit as st
import time
import json
import os
import threading
import numpy as np
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime


TRAINING_MODES = {
    'quick_demo': {
        'name': 'Quick Training',
        'duration_minutes': 1,
        'interval_seconds': 5,
        'expected_samples': 12,
        'description': 'Fast ~1-minute finetune: collects samples from TaaraWare buffer, builds quantum subspace.'
    },
    'demo': {
        'name': 'Demo Training',
        'duration_minutes': 2,
        'interval_seconds': 10,
        'expected_samples': 12,
        'description': '2-minute training for demonstrations.'
    },
    'standard': {
        'name': 'Standard Training',
        'duration_minutes': 3,
        'interval_seconds': 15,
        'expected_samples': 12,
        'description': '~3-minute finetune: AE finetune + IsolationForest + quantum subspace. Recommended.'
    },
    'full': {
        'name': 'Full Training',
        'duration_minutes': 10,
        'interval_seconds': 30,
        'expected_samples': 20,
        'description': '10-minute comprehensive training for production environments.'
    },
    'deep': {
        'name': 'Deep Training',
        'duration_minutes': 20,
        'interval_seconds': 30,
        'expected_samples': 40,
        'description': '~20-minute deep finetune: maximum samples, 20 AE epochs, full quantum subspace rebuild.'
    },
    'continuous': {
        'name': 'Continuous Training',
        'duration_minutes': 0,
        'interval_seconds': 600,
        'expected_samples': -1,
        'description': 'Ongoing training that runs until manually stopped. For subscription tier.'
    }
}


class TrainingManager:
    """Enhanced training manager with multiple training modes."""

    def __init__(self, dna_collector=None, embedder=None, anomaly_detector=None,
                 memory=None, config_path='models/training_config.json', model_dir='models'):
        self.dna_collector = dna_collector
        self.embedder = embedder
        self.anomaly_detector = anomaly_detector
        self.memory = memory
        self.config_path = config_path
        self.model_dir = model_dir

        self.training_state = {
            'status': 'idle',
            'mode': None,
            'mode_name': None,
            'start_time': None,
            'samples_collected': 0,
            'expected_samples': 0,
            'current_phase': '',
            'progress': 0.0,
            'errors': [],
            'baseline_collected': False,
            'embedder_trained': False,
            'anomaly_detector_trained': False,
            'taara_trained': False,
            'baseline_samples': 0,
            'last_training_time': None,
            'training_history': []
        }

        self.baseline_data: List[np.ndarray] = []
        self.training_thread = None
        self.stop_flag = threading.Event()

        os.makedirs(model_dir, exist_ok=True)
        self.load_state()

    def start_training(self, mode: str, platform, embedder, detector,
                       taara_analyzer, collector_class, callback: Optional[Callable] = None) -> Dict:
        """Start training in the specified mode."""
        if self.training_state['status'] == 'running':
            return {'success': False, 'message': 'Training already in progress'}

        mode_config = TRAINING_MODES.get(mode)
        if not mode_config:
            return {'success': False, 'message': f'Unknown training mode: {mode}'}

        self.stop_flag.clear()
        self.baseline_data = []
        self.embedder = embedder
        self.anomaly_detector = detector

        self.training_state.update({
            'status': 'running',
            'mode': mode,
            'mode_name': mode_config['name'],
            'start_time': time.time(),
            'samples_collected': 0,
            'expected_samples': mode_config['expected_samples'],
            'current_phase': 'Initializing...',
            'progress': 0.0,
            'errors': [],
            'duration_minutes': mode_config['duration_minutes'],
            'interval_seconds': mode_config['interval_seconds']
        })

        self.training_thread = threading.Thread(
            target=self._training_loop,
            args=(mode, platform, embedder, detector, taara_analyzer, collector_class, callback),
            daemon=True
        )
        self.training_thread.start()

        return {'success': True, 'message': f'Started {mode_config["name"]}'}

    def _training_loop(self, mode, platform, embedder, detector,
                       taara_analyzer, collector_class, callback):
        """Main training loop running in background thread."""
        mode_config = TRAINING_MODES[mode]
        duration = mode_config['duration_minutes'] * 60
        interval = mode_config['interval_seconds']
        expected = mode_config['expected_samples']

        try:
            self.training_state['current_phase'] = 'Phase 1: Collecting behavioral baseline...'

            # If baseline_data was pre-seeded via load_from_remote_buffer(), skip live collection
            if self.baseline_data:
                self.training_state['current_phase'] = (
                    f'Phase 1: Using {len(self.baseline_data)} pre-loaded remote buffer samples...'
                )
                self.training_state['samples_collected'] = len(self.baseline_data)
                self.training_state['progress'] = 60.0
            else:
                collector = None
                if platform.platform_type == 'ssh':
                    from components.ssh_manager import SSHManager
                    ssh_mgr = SSHManager(
                        platform.config['host'],
                        platform.config['username'],
                        platform.config.get('password', '')
                    )
                    ssh_mgr.connect()
                    collector = collector_class(ssh_mgr, host=platform.config.get('host', ''))

                start = time.time()
                sample_count = 0

                while not self.stop_flag.is_set():
                    elapsed = time.time() - start

                    if mode != 'continuous' and elapsed >= duration:
                        break
                    if expected > 0 and sample_count >= expected:
                        break

                    try:
                        if collector:
                            features = collector.get_feature_vector()
                        else:
                            security_data = platform.collect_security_data()
                            feat_dict = security_data.get('features', {})
                            features = np.array([float(v) for v in feat_dict.values()], dtype=np.float32)
                            if len(features) < 19:
                                features = np.pad(features, (0, max(0, 19 - len(features))))

                        self.baseline_data.append(features)
                        sample_count += 1
                        self.training_state['samples_collected'] = sample_count

                        if expected > 0:
                            self.training_state['progress'] = min(
                                sample_count / expected * 60, 60.0
                            )
                        else:
                            self.training_state['progress'] = min(elapsed / 3600 * 100, 99.0)

                        self.training_state['current_phase'] = (
                            f'Phase 1: Collecting baseline... '
                            f'({sample_count}/{expected if expected > 0 else "continuous"} samples)'
                        )

                    except Exception as e:
                        self.training_state['errors'].append(f'Collection error: {str(e)[:100]}')

                    for _ in range(interval):
                        if self.stop_flag.is_set():
                            break
                        time.sleep(1)

                if self.stop_flag.is_set():
                    self.training_state['status'] = 'stopped'
                    self.training_state['current_phase'] = 'Training stopped by user'
                    return

            if self.stop_flag.is_set():
                self.training_state['status'] = 'stopped'
                self.training_state['current_phase'] = 'Training stopped by user'
                return

            if len(self.baseline_data) < 5:
                self.training_state['status'] = 'failed'
                self.training_state['current_phase'] = (
                    f'Insufficient data: {len(self.baseline_data)} samples (need 5+)'
                )
                return

            baseline_array = np.array(self.baseline_data)
            np.save(os.path.join(self.model_dir, 'baseline_data.npy'), baseline_array)
            self.training_state['baseline_collected'] = True
            self.training_state['baseline_samples'] = len(baseline_array)

            self.training_state['current_phase'] = 'Phase 2: Finetuning autoencoder...'
            self.training_state['progress'] = 65.0
            host = getattr(platform, 'config', {}).get('host', 'unknown')
            try:
                from components.node_identity_db import (
                    load_node_model, save_node_model, append_baseline, record_training
                )

                # Load the most adapted model for this node before finetuning.
                # load_node_model is a no-op if no node model exists yet — embedder
                # keeps the global pretrained model in that case.
                loaded = load_node_model(host, embedder)
                if loaded:
                    self.training_state['current_phase'] = (
                        f'Phase 2: Loaded node model for {host}, finetuning...'
                    )

                finetune_epochs = (
                    10 if mode in ['quick_demo', 'demo']
                    else 20 if mode == 'deep'
                    else 15
                )

                if embedder.is_ready():
                    ae_result = embedder.finetune(baseline_array, epochs=finetune_epochs, lr=0.0005)
                else:
                    # No model at all — first ever run on this machine
                    ae_result = embedder.train(
                        baseline_array,
                        epochs=50 if mode in ['quick_demo', 'demo'] else 100,
                        lr=0.001,
                        batch_size=min(32, max(4, len(baseline_array) // 4))
                    )

                if ae_result.get('status') in ('success', 'skipped'):
                    self.training_state['embedder_trained'] = True
                    # Persist updated model and baseline samples to node folder
                    save_node_model(host, embedder)
                    append_baseline(host, baseline_array)
                    record_training(host, mode, len(baseline_array), ae_result)
            except Exception as e:
                self.training_state['errors'].append(f'Autoencoder error: {str(e)[:100]}')

            self.training_state['current_phase'] = 'Phase 3: Training anomaly detector...'
            self.training_state['progress'] = 80.0
            try:
                embeddings = embedder.embed(baseline_array)
                det_result = detector.train(embeddings, contamination=0.1)
                if det_result.get('status') == 'success':
                    self.training_state['anomaly_detector_trained'] = True
                # Save mean normal latent for fidelity comparison at inference
                import json as _json
                mean_latent = embeddings.mean(axis=0).tolist()
                with open(os.path.join(self.model_dir, 'normal_latent.json'), 'w') as f:
                    _json.dump(mean_latent, f)
            except Exception as e:
                self.training_state['errors'].append(f'Detector error: {str(e)[:100]}')

            self.training_state['current_phase'] = 'Phase 4: Building TAARA memory basis...'
            self.training_state['progress'] = 90.0
            try:
                # Use the same identity key as the live monitoring path:
                # taaraware_<host> so training and monitoring share the same basis.
                host = getattr(platform, 'config', {}).get('host', platform.platform_type)
                identity_id = f'taaraware_{host}'
                for features in self.baseline_data:
                    taara_analyzer.add_training_observation(features, identity_id,
                                                             embedder=embedder)
                self.training_state['taara_trained'] = True
            except Exception as e:
                self.training_state['errors'].append(f'TAARA error: {str(e)[:100]}')

            self.training_state['status'] = 'completed'
            self.training_state['progress'] = 100.0
            self.training_state['current_phase'] = 'Training complete!'
            self.training_state['last_training_time'] = time.time()
            self.training_state['training_history'].append({
                'timestamp': time.time(),
                'mode': mode,
                'samples': len(baseline_array)
            })
            self.save_state()

        except Exception as e:
            self.training_state['status'] = 'failed'
            self.training_state['current_phase'] = f'Training failed: {str(e)[:200]}'
            self.training_state['errors'].append(str(e))

    def load_from_remote_buffer(self, host: str, buffer_data: List[Dict]) -> Dict:
        """
        Feed feature_buffer.json data fetched by collect_remote_data() into the training pipeline.
        Call this before start_training() to seed baseline_data with historical agent samples.

        buffer_data: list of dicts from feature_buffer.json, each must have a 'features' key
                     (list of floats) or be a flat list of floats.
        Returns: dict with status, vectors_loaded, message.
        """
        if not buffer_data:
            return {'status': 'error', 'message': f'No buffer data for {host}'}

        _INTERNAL_KEYS = {'timestamp', 'hostname', 'time', '_proc_pair_hashes',
                          '_bash_history_lines', '_auth_log_size'}
        vectors = []
        for entry in buffer_data:
            try:
                if isinstance(entry, dict) and 'features' in entry:
                    raw = entry['features']
                    if isinstance(raw, dict):
                        v = np.array([float(x) for k, x in raw.items()
                                      if k not in _INTERNAL_KEYS], dtype=np.float32)
                    else:
                        v = np.array(raw, dtype=np.float32)
                elif isinstance(entry, dict):
                    # Flat dict format from TaaraWare agent
                    v = np.array([float(val) for k, val in entry.items()
                                  if k not in _INTERNAL_KEYS and isinstance(val, (int, float))],
                                 dtype=np.float32)
                elif isinstance(entry, (list, tuple)):
                    v = np.array(entry, dtype=np.float32)
                else:
                    continue
                if len(v) < 19:
                    v = np.pad(v, (0, 19 - len(v)))
                vectors.append(v[:19])
            except Exception:
                continue

        if len(vectors) < 5:
            return {'status': 'error',
                    'message': f'Only {len(vectors)} valid vectors parsed (need 5+)'}

        self.baseline_data = [np.array(v) for v in vectors]
        return {
            'status': 'success',
            'vectors_loaded': len(vectors),
            'message': f'Loaded {len(vectors)} samples from {host} into baseline_data'
        }

    def stop_training(self):
        """Stop ongoing training."""
        self.stop_flag.set()
        self.training_state['status'] = 'stopping'
        self.training_state['current_phase'] = 'Stopping training...'

    def collect_baseline(self, ssh_manager, duration_minutes=5, interval_seconds=30):
        """Legacy: Collect baseline via SSH (blocking)."""
        if not self.dna_collector:
            return {'status': 'error', 'message': 'No DNA collector configured'}

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        baseline_data = []

        while time.time() < end_time:
            feature_vector = self.dna_collector.get_feature_vector()
            baseline_data.append(feature_vector)
            if time.time() < end_time:
                time.sleep(interval_seconds)

        baseline_array = np.array(baseline_data)
        np.save(os.path.join(self.model_dir, 'baseline_data.npy'), baseline_array)
        self.training_state['baseline_collected'] = True
        self.training_state['baseline_samples'] = len(baseline_array)
        self.save_state()

        return {
            'status': 'success',
            'samples': len(baseline_array),
            'data_shape': baseline_array.shape
        }

    def train_initial_models(self):
        """Legacy: Train models from saved baseline data (blocking)."""
        baseline_path = os.path.join(self.model_dir, 'baseline_data.npy')
        if not os.path.exists(baseline_path):
            return {'status': 'error', 'message': 'No baseline data found'}

        baseline_data = np.load(baseline_path)
        if len(baseline_data) < 3:
            return {'status': 'error', 'message': f'Insufficient data: {len(baseline_data)} samples (need at least 3)'}

        if self.embedder:
            ae_result = self.embedder.train(baseline_data, epochs=100, lr=0.001)
            if ae_result.get('status') == 'success':
                self.training_state['embedder_trained'] = True
                embeddings = self.embedder.embed(baseline_data)
                if self.anomaly_detector:
                    det_result = self.anomaly_detector.train(embeddings)
                    if det_result.get('status') == 'success':
                        self.training_state['anomaly_detector_trained'] = True

        self.training_state['last_training_time'] = time.time()
        self.save_state()
        return {'status': 'success', 'samples': len(baseline_data)}

    def online_update(self, new_samples, labels):
        """Incrementally update models with new labeled data."""
        if not self.is_ready():
            return {'status': 'error', 'message': 'Models not trained yet'}

        benign_samples = [s for s, l in zip(new_samples, labels) if l == 'benign']
        if not benign_samples:
            return {'status': 'skipped', 'message': 'No benign samples'}

        baseline_path = os.path.join(self.model_dir, 'baseline_data.npy')
        existing = np.load(baseline_path)
        updated = np.vstack([existing, np.array(benign_samples)])

        if self.embedder:
            self.embedder.train(updated, epochs=20, lr=0.0005)
            embeddings = self.embedder.embed(updated)
            if self.anomaly_detector:
                self.anomaly_detector.train(embeddings)

        np.save(baseline_path, updated)
        self.training_state['baseline_samples'] = len(updated)
        self.training_state['last_training_time'] = time.time()
        self.save_state()

        return {'status': 'success', 'total_samples': len(updated)}

    def is_ready(self) -> bool:
        """Check if all models are trained."""
        return (
            self.training_state.get('embedder_trained', False) and
            self.training_state.get('anomaly_detector_trained', False)
        )

    def get_status(self) -> Dict:
        return self.training_state.copy()

    def get_fallback_mode(self) -> str:
        if not self.is_ready():
            return 'notify_only'
        return 'full_agent'

    def quick_start(self, ssh_manager, quick_mode=False):
        """Legacy quick start."""
        duration = 2 if quick_mode else 5
        interval = 10 if quick_mode else 30

        result = self.collect_baseline(ssh_manager, duration, interval)
        if result['status'] != 'success':
            return result
        return self.train_initial_models()

    def save_state(self):
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            state = {k: v for k, v in self.training_state.items() if not callable(v)}
            with open(self.config_path, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"[TrainingManager] Save error: {e}")

    def load_state(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    saved = json.load(f)
                if saved.get('status') == 'running':
                    saved['status'] = 'interrupted'
                self.training_state.update(saved)
        except Exception as e:
            print(f"[TrainingManager] Load error: {e}")


def render_training_section(training_mgr, platform, embedder, detector,
                           taara_analyzer, collector_class):
    """Render the training UI section in Streamlit."""

    st.markdown("### System Training")

    status = training_mgr.get_status()
    is_running = status.get('status') == 'running'

    if is_running:
        st.markdown(f"""
        <div style="background: #1a2a1a; padding: 15px; border-radius: 10px;
                    border: 1px solid #00cc00; margin-bottom: 15px;">
            <h4 style="color: #00cc00; margin: 0;">Training in Progress</h4>
            <p style="color: #a0a0b0; margin: 5px 0;">
                {status.get('mode_name', 'Unknown')} — {status.get('current_phase', '')}
            </p>
        </div>
        """, unsafe_allow_html=True)

        progress = status.get('progress', 0)
        st.progress(min(progress / 100, 1.0), text=status.get('current_phase', ''))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Samples", status.get('samples_collected', 0))
        with col2:
            elapsed = time.time() - status.get('start_time', time.time())
            st.metric("Elapsed", f"{elapsed:.0f}s")
        with col3:
            exp = status.get('expected_samples', 0)
            st.metric("Target", exp if exp > 0 else "Continuous")

        if st.button("Stop Training", type="secondary"):
            training_mgr.stop_training()
            st.rerun()

    else:
        trained = training_mgr.is_ready()
        if trained:
            st.success("System is trained and ready for analysis")
            last = status.get('last_training_time')
            if last:
                st.caption(f"Last trained: {datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M')} | "
                          f"Samples: {status.get('baseline_samples', status.get('samples_collected', 0))}")
        elif status.get('status') == 'failed':
            st.error(f"Last training failed: {status.get('current_phase', '')}")
        elif status.get('status') == 'stopped':
            st.warning("Training was stopped before completion")

        st.markdown("#### Select Training Mode")

        modes = [
            ('quick_demo', 'Quick Demo (2 min)'),
            ('demo', 'Demo (5 min)'),
            ('standard', 'Standard (15 min)'),
            ('full', 'Full (1 hour)')
        ]

        mode_cols = st.columns(4)
        selected_mode = None
        for i, (mode_key, mode_label) in enumerate(modes):
            with mode_cols[i]:
                config = TRAINING_MODES[mode_key]
                if st.button(
                    f"{mode_label}\n{config['expected_samples']} samples",
                    use_container_width=True,
                    key=f'train_{mode_key}'
                ):
                    selected_mode = mode_key

        if selected_mode:
            config = TRAINING_MODES[selected_mode]
            st.info(f"Starting {config['name']}: {config['description']}")
            result = training_mgr.start_training(
                selected_mode, platform, embedder, detector,
                taara_analyzer, collector_class
            )
            if result['success']:
                st.success(result['message'])
                time.sleep(1)
                st.rerun()
            else:
                st.error(result['message'])

        with st.expander("Training Details"):
            if status.get('errors'):
                for err in status['errors']:
                    st.text(err)
            st.json({k: v for k, v in status.items() if k != 'errors'})
