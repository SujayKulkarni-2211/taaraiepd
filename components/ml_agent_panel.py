"""
ML Agent Panel
==============

Dashboard interface for the ML-powered agent system.

Features:
    - Training status and controls
    - Current state analysis with ML insights
    - Admin feedback buttons (mark benign/suspicious)
    - Learning statistics
    - Trained action visualization
"""

import streamlit as st
import time
from typing import Dict, Any, Optional


def render_ml_agent_panel(ml_system):
    """
    Render the ML agent panel.

    Args:
        ml_system: MLAgentSystem instance
    """
    st.title("🤖 ML-Powered Agent System")

    # Activation code check (same pattern as existing Agent panel)
    if "ml_agent_activated" not in st.session_state:
        st.session_state.ml_agent_activated = False

    if not st.session_state.ml_agent_activated:
        st.warning("⚠️ ML Agent is a powerful system that requires activation.")
        st.markdown("""
**ML Agent Capabilities:**
- Real-time behavior analysis using 19 atomic DNA features
- Machine learning-based anomaly detection (Isolation Forest + Autoencoder)
- Automated learning from admin feedback (Contextual Bandit)
- Safe action execution (enhanced monitoring only - read-only operations)

**Activation Required**: Enter the activation code to proceed.
        """)

        col1, col2 = st.columns([2, 1])
        with col1:
            activation_code = st.text_input("Enter Activation Code", type="password", key="ml_activation_input")

        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Activate ML Agent", use_container_width=True, type="primary"):
                if activation_code == "777333":  # Same code as existing agent
                    st.session_state.ml_agent_activated = True
                    st.session_state.ml_agent_start_time = time.time()
                    st.success("✅ ML Agent activated!")
                    st.rerun()
                else:
                    st.error("❌ Invalid activation code")

        return  # Don't render rest of panel until activated

    # Show activated agent interface
    # Check training status
    training_status = ml_system.get_training_status()
    is_trained = training_status['ready']

    # Show training section first if not trained
    if not is_trained:
        render_training_section(ml_system, training_status)
    else:
        # Show tabs for trained system
        tabs = st.tabs(["📊 Current Analysis", "🎓 Training & Learning", "📈 Statistics"])

        with tabs[0]:
            render_current_analysis(ml_system)

        with tabs[1]:
            render_training_section(ml_system, training_status)

        with tabs[2]:
            render_statistics(ml_system)


def render_training_section(ml_system, training_status: Dict):
    """Render training controls and status."""
    st.subheader("🎓 Training & Learning")

    # Training status
    with st.container(border=True):
        st.markdown("### Training Status")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            status_icon = "✅" if training_status['baseline_collected'] else "❌"
            st.metric("Baseline Collected", f"{status_icon} {training_status['baseline_samples']} samples")

        with col2:
            status_icon = "✅" if training_status['embedder_trained'] else "❌"
            st.metric("Autoencoder Trained", status_icon)

        with col3:
            status_icon = "✅" if training_status['anomaly_detector_trained'] else "❌"
            st.metric("Anomaly Detector Trained", status_icon)

        with col4:
            status_icon = "✅" if training_status['ready'] else "⚠️"
            st.metric("System Ready", status_icon)

        if training_status['last_training_time']:
            last_trained = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(training_status['last_training_time']))
            st.info(f"Last trained: {last_trained}")

    # Training controls
    if not training_status['ready']:
        with st.container(border=True):
            st.markdown("### Initial Training Required")

            st.warning("⚠️ **The system needs to be trained before it can analyze behavior.**")

            st.markdown("""
**Training Process:**
1. **Baseline Collection** (2-5 minutes): Collects normal system behavior samples
2. **Model Training**: Trains autoencoder and anomaly detector on baseline data

**IMPORTANT:** During baseline collection, ensure:
- ✅ Normal operation (no attacks, no unusual activity)
- ✅ VPS is running typical workload
- ✅ No deployments or maintenance happening
            """)

            col1, col2 = st.columns(2)

            with col1:
                if st.button("🚀 Quick Training (2 min)", use_container_width=True, type="primary"):
                    with st.spinner("Collecting baseline and training models..."):
                        result = ml_system.run_training(quick_mode=True)

                        if result['status'] == 'success':
                            st.success("✅ Training complete! System is now ready.")
                            st.rerun()
                        else:
                            st.error(f"❌ Training failed: {result['message']}")

            with col2:
                if st.button("⏱️ Full Training (5 min)", use_container_width=True):
                    with st.spinner("Collecting baseline and training models..."):
                        result = ml_system.run_training(quick_mode=False)

                        if result['status'] == 'success':
                            st.success("✅ Training complete! System is now ready.")
                            st.rerun()
                        else:
                            st.error(f"❌ Training failed: {result['message']}")

    else:
        # Show retrain option
        with st.expander("🔄 Retrain Models"):
            st.markdown("Retrain models with fresh baseline data.")
            if st.button("Retrain (5 min)", use_container_width=True):
                with st.spinner("Retraining..."):
                    result = ml_system.run_training(quick_mode=False)
                    if result['status'] == 'success':
                        st.success("✅ Retraining complete!")
                        st.rerun()
                    else:
                        st.error(f"❌ Retraining failed: {result['message']}")


def render_current_analysis(ml_system):
    """Render current state analysis."""
    st.subheader("📊 Current State Analysis")

    # Analyze button
    if st.button("🔍 Analyze Current State", use_container_width=True, type="primary"):
        with st.spinner("Analyzing system state..."):
            result = ml_system.analyze_current_state(safe_mode=True)

            # Store in session state
            st.session_state['ml_analysis_result'] = result

    # Show analysis if available
    if 'ml_analysis_result' in st.session_state:
        result = st.session_state['ml_analysis_result']

        # Status overview
        with st.container(border=True):
            st.markdown("### Analysis Summary")

            col1, col2, col3 = st.columns(3)

            with col1:
                anomaly_icon = "🚨" if result['is_anomaly'] else "✅"
                anomaly_text = "ANOMALY DETECTED" if result['is_anomaly'] else "Normal"
                st.metric("Status", f"{anomaly_icon} {anomaly_text}")

            with col2:
                st.metric("Anomaly Score", f"{result['anomaly_score']:.4f}")
                st.caption("Negative = more anomalous")

            with col3:
                st.metric("Confidence", f"{result['confidence']:.1%}")

        # Memory check
        if result['known_benign']:
            st.success("✅ **Known Benign Pattern** - Auto-suppressed")
        elif result['known_suspicious']:
            st.warning(f"⚠️ **Known Suspicious Pattern** - Auto-action: {result['selected_action']}")

        # Action Suggestions (only if anomaly detected and not known benign)
        if result['is_anomaly'] and not result['known_benign']:
            with st.container(border=True):
                st.markdown("### 💡 Suggested Actions")

                # Get action suggestions using the action_suggester
                if st.button("🤖 Get AI Suggestions", key="get_suggestions"):
                    with st.spinner("Querying LLM for action suggestions..."):
                        import numpy as np
                        context = {
                            'embedding': np.array(result['embedding']) if result['embedding'] else np.zeros(64),
                            'anomaly_score': result['anomaly_score'],
                            'raw_features': result['raw_features'],
                            'is_anomaly': result['is_anomaly']
                        }

                        suggestions = ml_system.action_suggester.suggest_actions(
                            context=context,
                            anomaly_detected=result['is_anomaly'],
                            known_pattern=result.get('similar_pattern')
                        )

                        st.session_state['action_suggestions'] = suggestions
                        st.rerun()

                # Display suggestions if available
                if 'action_suggestions' in st.session_state:
                    suggestions = st.session_state['action_suggestions']

                    st.info(f"**Source**: {suggestions['source'].upper()} | **Auto-Executable**: {'✅ Yes' if suggestions['auto_executable'] else '⚠️ Needs Approval'}")

                    for idx, sug in enumerate(suggestions['suggestions']):
                        with st.expander(f"**{sug['action'].upper()}** (Confidence: {sug['confidence']:.0%})", expanded=idx==0):
                            st.markdown(f"**Reason**: {sug['reason']}")
                            st.progress(sug['confidence'])

                            action_info = ml_system.action_suggester.get_action_info(sug['action'])
                            st.caption(f"ℹ️ {action_info['description']} | Risk: {action_info['risk']}")

                    # Custom action input
                    st.markdown("---")
                    st.markdown("**Or Specify Custom Action**")
                    custom_action = st.text_area("Enter custom shell command:", key="custom_action", height=100,
                                                  help="Enter a safe command to execute. This will be learned for similar future events.")

                    if custom_action and st.button("▶️ Execute Custom Action", key="execute_custom"):
                        with st.spinner("Executing custom action..."):
                            import numpy as np
                            # Execute via SSH
                            stdout, stderr, exit_code = ml_system.ssh_manager.execute_command(custom_action)

                            # Display result
                            if exit_code == 0:
                                st.success("✅ Custom action executed successfully")
                                if stdout:
                                    st.code(stdout, language="text")
                            else:
                                st.error(f"❌ Execution failed (exit code: {exit_code})")
                                if stderr:
                                    st.code(stderr, language="text")

                            # Store to memory for learning
                            if st.button("💾 Save as Learned Action", key="save_custom"):
                                context = {
                                    'embedding': np.array(result['embedding']) if result['embedding'] else np.zeros(64),
                                    'anomaly_score': result['anomaly_score'],
                                    'gemini_category': 'custom'
                                }
                                ml_system.bandit.update(context, custom_action, reward=1.0, admin_approved=True)
                                ml_system.memory.add_suspicious(
                                    embedding=np.array(result['embedding']) if result['embedding'] else np.zeros(64),
                                    action=custom_action,
                                    notes="Custom action - admin approved"
                                )
                                st.success("✅ Action saved! Similar patterns will trigger this action automatically.")
                                # Clear the suggestions
                                del st.session_state['action_suggestions']
                                st.rerun()

        # Fallback: Show recommended action (from legacy system or when no suggestions)
        elif not result['known_benign']:
            with st.container(border=True):
                st.markdown("### 🎯 Recommended Action")

                action = result['selected_action']
                rationale = result['action_rationale']

                action_icons = {
                    'ignore': '✅',
                    'notify': '🔔',
                    'enhanced_monitoring': '🔍'
                }

                st.markdown(f"### {action_icons.get(action, '•')} {action.upper().replace('_', ' ')}")
                st.markdown(f"*{rationale}*")

            # Action buttons
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                if st.button("✅ Approve & Execute", use_container_width=True, type="primary"):
                    with st.spinner("Executing..."):
                        exec_result = ml_system.approve_action(result['result_id'])

                        if exec_result['learning']['status'] == 'success':
                            st.success("✅ Action approved and executed. System learned from this decision.")
                            st.rerun()
                        else:
                            st.error("❌ Execution failed")

            with col2:
                if st.button("❌ Reject (False Positive)", use_container_width=True):
                    reject_result = ml_system.reject_action(result['result_id'])
                    if reject_result['status'] == 'success':
                        st.info("System learned to reduce false positives like this.")
                        st.rerun()

            with col3:
                if st.button("🟢 Mark Benign", use_container_width=True):
                    benign_result = ml_system.mark_as_benign(result['result_id'])
                    if benign_result['status'] == 'success':
                        st.success("Marked as benign. Future similar patterns will be auto-suppressed.")
                        st.rerun()

            with col4:
                if st.button("🔴 Mark Suspicious", use_container_width=True):
                    suspicious_result = ml_system.mark_as_suspicious(result['result_id'])
                    if suspicious_result['status'] == 'success':
                        st.warning("Marked as suspicious. Future similar patterns will trigger auto-action.")
                        st.rerun()

        # Atomic DNA features
        with st.expander("🧬 Atomic DNA Features"):
            if result['raw_features']:
                features = result['raw_features']

                st.markdown("#### Process Behavior")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Spawn Rate", f"{features.get('proc_spawn_rate', 0):.1f}/min")
                    st.metric("Short-lived Ratio", f"{features.get('proc_short_lived_ratio', 0):.2%}")
                with col2:
                    st.metric("Tree Depth", int(features.get('proc_tree_depth_max', 0)))
                    st.metric("UID Diversity", int(features.get('proc_uid_diversity', 0)))
                with col3:
                    st.metric("Root Ratio", f"{features.get('proc_root_ratio', 0):.2%}")
                    st.metric("Cmd Entropy", f"{features.get('proc_cmd_entropy', 0):.2f}")

                st.markdown("#### Network Behavior")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Outbound Conns", int(features.get('net_outbound_conn_rate', 0)))
                    st.metric("Unique Dst IPs", int(features.get('net_unique_dst_ips', 0)))
                with col2:
                    st.metric("Unique Dst Ports", int(features.get('net_unique_dst_ports', 0)))
                    st.metric("Port Entropy", f"{features.get('net_port_entropy', 0):.2f}")
                with col3:
                    st.metric("DNS Queries", f"{features.get('net_dns_query_rate', 0):.1f}/min")
                    st.metric("Failed Ratio", f"{features.get('net_failed_conn_ratio', 0):.2%}")

                st.markdown("#### Filesystem Behavior")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Sensitive Access", "Yes" if features.get('fs_sensitive_access', 0) > 0 else "No")
                    st.metric("Write Rate", f"{features.get('fs_write_rate', 0):.1f}/min")
                with col2:
                    st.metric("Exec from Tmp", "Yes" if features.get('fs_exec_from_tmp', 0) > 0 else "No")
                    st.metric("Hidden File Ratio", f"{features.get('fs_hidden_file_ratio', 0):.2%}")

                st.markdown("#### Temporal Behavior")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Time Deviation", f"{features.get('time_of_day_deviation', 0):.2f}σ")
                with col2:
                    st.metric("Burstiness", f"{features.get('burstiness_score', 0):.2f}")
                with col3:
                    st.metric("Compactness", f"{features.get('sequence_compactness', 0):.2f}")


def render_statistics(ml_system):
    """Render learning statistics."""
    st.subheader("📈 Learning Statistics")

    stats = ml_system.get_statistics()

    # Memory stats
    with st.container(border=True):
        st.markdown("### 🧠 Behavior Memory")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Benign Patterns", stats['memory']['benign_count'])

        with col2:
            st.metric("Suspicious Patterns", stats['memory']['suspicious_count'])

        with col3:
            st.metric("Total Learned", stats['memory']['total'])

    # Bandit stats
    with st.container(border=True):
        st.markdown("### 🎰 Action Learning (Contextual Bandit)")

        bandit_stats = stats['bandit']

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Approved Actions", bandit_stats['approved_actions_count'])

        with col2:
            st.metric("Exploration Rate", f"{bandit_stats['epsilon']:.1%}")

        with col3:
            total_selections = sum(bandit_stats['total_selections'].values())
            st.metric("Total Decisions", total_selections)

        # Action statistics
        st.markdown("#### Action Performance")

        for action in ['ignore', 'notify', 'enhanced_monitoring']:
            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                st.markdown(f"**{action.replace('_', ' ').title()}**")

            with col2:
                st.metric("Selected", bandit_stats['total_selections'].get(action, 0))

            with col3:
                avg_reward = bandit_stats['average_rewards'].get(action, 0.0)
                st.metric("Avg Reward", f"{avg_reward:.2f}")

    # Training stats
    with st.container(border=True):
        st.markdown("### 🎓 Training History")

        training = stats['training']

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Training Sessions", training['training_count'])

        with col2:
            st.metric("Baseline Samples", training['baseline_samples'])

        if training['last_training_time']:
            last_trained = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(training['last_training_time']))
            st.info(f"Last trained: {last_trained}")
