"""
TAARA Security Analyzer
========================

Trajectory-Aware Adaptive Residual Analysis
Quantum-Enhanced Security System for MSMEs

"Prevent Crash, Preserve Cash"

Main application entry point with:
1. Admin login
2. Platform selection (SSH, AWS, GCP, Azure, Docker, Kubernetes)
3. Navigation to all TAARA modules
"""

import streamlit as st
import os
import time
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(
    page_title="TAARA Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background-color: #0a0a1a;
    }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #e0e0e0;
    }
    div[data-testid="stMetric"] {
        background: #111122;
        padding: 10px 15px;
        border-radius: 8px;
        border: 1px solid #222244;
    }
    div[data-testid="stMetric"] label {
        color: #888 !important;
    }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #e0e0e0 !important;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background: #111122;
        border-radius: 8px;
        padding: 8px 16px;
        color: #aaa;
    }
    .stTabs [aria-selected="true"] {
        background: #1a1a3e;
        color: #e94560;
    }
    section[data-testid="stSidebar"] {
        background: #0d0d1a;
        border-right: 1px solid #1a1a3e;
    }
    .stButton > button {
        border: 1px solid #333;
        background: #1a1a2e;
        color: #e0e0e0;
    }
    .stButton > button:hover {
        border-color: #e94560;
        color: #e94560;
    }
    .stButton > button[kind="primary"] {
        background: #e94560;
        color: white;
        border: none;
    }
    .stButton > button[kind="primary"]:hover {
        background: #ff5a75;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize all session state variables."""
    defaults = {
        'authenticated': False,
        'platform_connected': False,
        'platform': None,
        'platform_type': None,
        'platform_config': {},
        'current_page': 'login',
        'active_nav': 'taara_analysis',
        'analysis_results': None,
        'nav_target': None,
        'llm_service': None,
        'taara_analyzer': None,
        'embedder': None,
        'detector': None,
        'training_mgr': None,
        'taaraware_mgr': None,
        'cloud_analyzer': None,
        'security_agent': None,
        'action_logger': None,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


def render_login():
    """Render the admin login page."""
    col_l, col_c, col_r = st.columns([1, 2, 1])

    with col_c:
        st.markdown("""
        <div style="text-align: center; padding: 40px 0 20px 0;">
            <h1 style="color: #e94560; font-size: 3.5em; margin: 0; letter-spacing: 5px;">
                TAARA
            </h1>
            <p style="color: #a0a0b0; font-size: 1.2em; margin: 5px 0;">
                Trajectory-Aware Adaptive Residual Analysis
            </p>
            <p style="color: #666; font-size: 1em; margin: 15px 0;">
                Quantum-Enhanced Security System
            </p>
            <p style="color: #e94560; font-size: 0.95em; font-style: italic;">
                Prevent Crash, Preserve Cash
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        with st.form("login_form"):
            st.markdown("### Admin Login")
            username = st.text_input("Username", placeholder="admin")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            api_key = st.text_input("Gemini API Key", type="password",
                                   value=os.getenv('GEMINI_API_KEY', ''),
                                   placeholder="Your Google Gemini API key")

            submitted = st.form_submit_button("Login to TAARA", use_container_width=True, type="primary")

            if submitted:
                if username and password:
                    st.session_state.authenticated = True
                    st.session_state.current_page = 'platform_select'

                    if api_key:
                        try:
                            from components.llm_service import LLMService
                            st.session_state.llm_service = LLMService(api_key)
                        except Exception as e:
                            st.warning(f"LLM setup notice: {e}")

                    _initialize_core_systems()
                    st.rerun()
                else:
                    st.error("Please enter username and password")


def _initialize_core_systems():
    """Initialize all core TAARA systems."""
    from components.taara_core import TAARAnalyzer
    from components.dna_autoencoder import DNAEmbedder
    from components.ml_anomaly_detector import MLAnomalyDetector, BehaviorMemory
    from components.training_manager import TrainingManager
    from components.taaraware_manager import TaaraWareManager
    from components.cloud_spending import CloudSpendingAnalyzer
    from components.security_agent import SecurityAgent
    from components.action_log import ActionLogger

    st.session_state.taara_analyzer = TAARAnalyzer(model_dir='models')
    st.session_state.embedder = DNAEmbedder(model_path='models/dna_autoencoder.pt',
                                              scaler_path='models/dna_scaler.json')
    st.session_state.detector = MLAnomalyDetector(model_path='models/isolation_forest.pkl')

    memory = BehaviorMemory(memory_path='models/behavior_memory.json')
    st.session_state.training_mgr = TrainingManager(
        dna_collector=None,
        embedder=st.session_state.embedder,
        anomaly_detector=st.session_state.detector,
        memory=memory,
        config_path='models/training_config.json'
    )

    st.session_state.taaraware_mgr = TaaraWareManager(model_dir='models')
    st.session_state.cloud_analyzer = CloudSpendingAnalyzer(model_dir='models')
    st.session_state.security_agent = SecurityAgent(model_dir='models')
    st.session_state.action_logger = ActionLogger(log_path='models/action_log.json')

    st.session_state.action_logger.log('system', 'login', 'Admin logged in', severity='info')


def render_platform_select():
    """Render the platform selection page."""
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <h1 style="color: #e94560; font-size: 2.5em;">TAARA Command Center</h1>
        <p style="color: #a0a0b0;">Select the platform to analyze</p>
    </div>
    """, unsafe_allow_html=True)

    from components.platform_manager import (
        PLATFORM_REGISTRY, PLATFORM_DISPLAY_NAMES, PLATFORM_ICONS
    )

    platforms = list(PLATFORM_REGISTRY.keys())
    cols = st.columns(3)

    for i, ptype in enumerate(platforms):
        with cols[i % 3]:
            icon = PLATFORM_ICONS.get(ptype, '🔧')
            name = PLATFORM_DISPLAY_NAMES.get(ptype, ptype)

            st.markdown(f"""
            <div style="background: #111122; padding: 20px; border-radius: 10px;
                        border: 1px solid #222244; text-align: center; margin: 5px 0;">
                <h2 style="margin: 0; font-size: 2em;">{icon}</h2>
                <h3 style="color: #e0e0e0; margin: 5px 0;">{name}</h3>
            </div>
            """, unsafe_allow_html=True)

            if st.button(f"Connect to {ptype.upper()}", key=f"platform_{ptype}", use_container_width=True):
                st.session_state.platform_type = ptype
                st.session_state.current_page = 'platform_config'
                st.rerun()


def render_platform_config():
    """Render platform-specific configuration."""
    ptype = st.session_state.platform_type

    from components.platform_manager import PLATFORM_DISPLAY_NAMES, PLATFORM_ICONS, create_platform

    st.markdown(f"""
    <div style="text-align: center; padding: 20px 0;">
        <h2 style="color: #e94560;">{PLATFORM_ICONS.get(ptype, '')} Connect to {PLATFORM_DISPLAY_NAMES.get(ptype, ptype)}</h2>
    </div>
    """, unsafe_allow_html=True)

    config = {}

    if ptype == 'ssh':
        with st.form("ssh_config"):
            config['host'] = st.text_input("Host/IP Address", placeholder="192.168.1.100")
            config['port'] = st.number_input("Port", value=22, min_value=1, max_value=65535)
            config['username'] = st.text_input("Username", placeholder="root")
            config['password'] = st.text_input("Password", type="password")
            config['key_file'] = st.text_input("SSH Key File (optional)", placeholder="/path/to/key")
            if not config['key_file']:
                config['key_file'] = None
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

    elif ptype == 'aws':
        with st.form("aws_config"):
            config['access_key'] = st.text_input("AWS Access Key ID", type="password")
            config['secret_key'] = st.text_input("AWS Secret Access Key", type="password")
            config['region'] = st.selectbox("Region", [
                'us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1',
                'ap-southeast-1', 'eu-central-1', 'us-east-2'
            ], index=3)
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

    elif ptype == 'gcp':
        with st.form("gcp_config"):
            config['project_id'] = st.text_input("GCP Project ID", placeholder="my-project-123")
            config['credentials_file'] = st.text_input("Service Account JSON Path (optional)",
                                                        placeholder="/path/to/credentials.json")
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

    elif ptype == 'azure':
        with st.form("azure_config"):
            config['subscription_id'] = st.text_input("Subscription ID")
            config['tenant_id'] = st.text_input("Tenant ID")
            config['client_id'] = st.text_input("Client ID (App Registration)")
            config['client_secret'] = st.text_input("Client Secret", type="password")
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

    elif ptype == 'docker':
        with st.form("docker_config"):
            config['base_url'] = st.text_input("Docker Host",
                                                value="unix:///var/run/docker.sock",
                                                placeholder="unix:///var/run/docker.sock or tcp://host:2375")
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)

    elif ptype == 'kubernetes':
        with st.form("k8s_config"):
            config['kubeconfig'] = st.text_input("Kubeconfig Path (optional)",
                                                  placeholder="~/.kube/config")
            config['context'] = st.text_input("Context (optional)", placeholder="default")
            submitted = st.form_submit_button("Connect", type="primary", use_container_width=True)
    else:
        st.error(f"Unknown platform: {ptype}")
        submitted = False

    if submitted:
        with st.spinner(f"Connecting to {ptype.upper()}..."):
            try:
                platform = create_platform(ptype, config)
                connected = platform.connect()

                if connected:
                    st.session_state.platform = platform
                    st.session_state.platform_config = config
                    st.session_state.platform_connected = True
                    st.session_state.current_page = 'main_app'

                    if st.session_state.action_logger:
                        st.session_state.action_logger.log(
                            'system', 'platform_connect',
                            f'Connected to {ptype.upper()}', severity='info'
                        )

                    st.success(f"Connected to {ptype.upper()} successfully!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"Connection failed: {platform.last_error}")
            except Exception as e:
                st.error(f"Connection error: {e}")

    if st.button("Back to Platform Selection"):
        st.session_state.current_page = 'platform_select'
        st.rerun()


def render_main_app():
    """Render the main application with sidebar navigation."""
    platform = st.session_state.platform
    ptype = st.session_state.platform_type

    from components.platform_manager import PLATFORM_ICONS

    with st.sidebar:
        st.markdown(f"""
        <div style="text-align: center; padding: 15px 0; border-bottom: 1px solid #222;">
            <h2 style="color: #e94560; margin: 0; letter-spacing: 3px;">TAARA</h2>
            <p style="color: #666; margin: 0; font-size: 0.8em;">Prevent Crash, Preserve Cash</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="padding: 10px 0; border-bottom: 1px solid #222;">
            <p style="color: #888; margin: 0; font-size: 0.85em;">
                {PLATFORM_ICONS.get(ptype, '')} {ptype.upper()} |
                {'🟢 Connected' if platform and platform.connected else '🔴 Disconnected'}
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("")

        nav_options = [
            ('taara_analysis', '🔍 TaaraAnalysis'),
            ('taara_words', '📄 Taara Words'),
            ('taaraware', '🛡️ TaaraWare Deploy'),
            ('command_center', '📡 Command Center'),
            ('training', '🎓 Training'),
            ('agent', '🤖 Agent'),
            ('ai_chat', '💬 AI Chat'),
            ('action_log', '📋 Action Log'),
            ('unified_dashboard', '📊 Unified Dashboard'),
        ]

        if st.session_state.nav_target:
            st.session_state.active_nav = st.session_state.nav_target
            st.session_state.nav_target = None

        for key, label in nav_options:
            is_active = st.session_state.active_nav == key
            btn_type = "primary" if is_active else "secondary"
            if st.button(label, key=f"nav_{key}", use_container_width=True,
                        type=btn_type if is_active else "secondary"):
                st.session_state.active_nav = key
                st.rerun()

        st.markdown("---")
        if st.button("🔌 Change Platform", use_container_width=True):
            if platform:
                platform.disconnect()
            st.session_state.platform_connected = False
            st.session_state.current_page = 'platform_select'
            st.rerun()

        if st.button("🚪 Logout", use_container_width=True):
            if platform:
                platform.disconnect()
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    _render_page(st.session_state.active_nav)


def _render_page(page: str):
    """Render the selected page."""
    platform = st.session_state.platform
    taara_analyzer = st.session_state.taara_analyzer
    embedder = st.session_state.embedder
    detector = st.session_state.detector
    training_mgr = st.session_state.training_mgr
    taaraware_mgr = st.session_state.taaraware_mgr
    cloud_analyzer = st.session_state.cloud_analyzer
    llm_service = st.session_state.llm_service
    security_agent = st.session_state.security_agent
    action_logger = st.session_state.action_logger

    if page == 'taara_analysis':
        from components.taara_analysis import render_taara_analysis
        render_taara_analysis(platform, taara_analyzer, cloud_analyzer, llm_service)

    elif page == 'taara_words':
        from components.taara_words import render_taara_words
        render_taara_words(st.session_state.analysis_results or {})

    elif page == 'taaraware':
        from components.taaraware_manager import render_taaraware_page
        render_taaraware_page(platform, taaraware_mgr, taara_analyzer)

    elif page == 'command_center':
        from components.command_center import render_command_center
        render_command_center(platform, taara_analyzer, training_mgr, taaraware_mgr, embedder, detector)

    elif page == 'training':
        from components.training_manager import render_training_section
        from components.atomic_dna_collector import AtomicDNACollector
        render_training_section(training_mgr, platform, embedder, detector,
                               taara_analyzer, AtomicDNACollector)

    elif page == 'agent':
        from components.security_agent import render_agent_panel
        render_agent_panel(security_agent, platform, taara_analyzer, embedder, detector)

    elif page == 'ai_chat':
        from components.ai_chat import render_ai_chat
        render_ai_chat(llm_service, platform, taara_analyzer)

    elif page == 'action_log':
        from components.action_log import render_action_log
        render_action_log(action_logger, security_agent)
        # Platform is available via st.session_state.platform for rollbacks

    elif page == 'unified_dashboard':
        from components.unified_dashboard import render_unified_dashboard
        render_unified_dashboard()


def main():
    """Main application entry point."""
    init_session_state()

    if not st.session_state.authenticated:
        render_login()
    elif st.session_state.current_page == 'platform_select':
        render_platform_select()
    elif st.session_state.current_page == 'platform_config':
        render_platform_config()
    elif st.session_state.current_page == 'main_app':
        render_main_app()
    else:
        render_login()


if __name__ == '__main__':
    main()
