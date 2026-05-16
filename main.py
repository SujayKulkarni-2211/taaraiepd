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
            api_key = st.text_input("Reasoning Engine Key", type="password",
                                   value=os.getenv('GROQ_API_KEY', ''),
                                   placeholder="Your Reasoning Engine key")

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
    """Render the top-level choice: Code Analysis or System."""
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <h1 style="color: #e94560; font-size: 2.5em;">TAARA Command Center</h1>
        <p style="color: #a0a0b0;">What would you like to do?</p>
    </div>
    """, unsafe_allow_html=True)

    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("""
        <div style="background: #111122; padding: 30px; border-radius: 12px;
                    border: 1px solid #0a3060; text-align: center; margin: 5px 0;">
            <h2 style="margin: 0; font-size: 2em;">🧬</h2>
            <h3 style="color: #4a9eff; margin: 10px 0;">Code Analysis</h3>
            <p style="color: #888; margin: 0; font-size: 0.9em;">
                Scan any GitHub repo or local path for CVEs, EOL runtimes,
                unsafe CI/CD config, and cross-file exploit chains.
                No server connection required.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Go to Code Analysis", key="goto_code", use_container_width=True, type="primary"):
            st.session_state.current_page = 'code_analysis'
            st.rerun()

    with col_r:
        st.markdown("""
        <div style="background: #111122; padding: 30px; border-radius: 12px;
                    border: 1px solid #222244; text-align: center; margin: 5px 0;">
            <h2 style="margin: 0; font-size: 2em;">🖥️</h2>
            <h3 style="color: #e0e0e0; margin: 10px 0;">System</h3>
            <p style="color: #888; margin: 0; font-size: 0.9em;">
                Connect to a server or cloud platform to run TaaraAnalysis,
                deploy TaaraWare, and monitor for behavioral anomalies.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Connect to a System", key="goto_system", use_container_width=True):
            st.session_state.current_page = 'system_select'
            st.rerun()


def render_system_select():
    """Render the system connection options: SSH, AWS, GCP, Azure."""
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <h2 style="color: #e94560;">Connect to a System</h2>
        <p style="color: #a0a0b0;">Select your platform</p>
    </div>
    """, unsafe_allow_html=True)

    platforms = [
        ('ssh',   '🖥️',  'SSH',   'Linux server via SSH — full TaaraWare support'),
        ('aws',   '☁️',  'AWS',   'Amazon Web Services'),
        ('gcp',   '🌐',  'GCP',   'Google Cloud Platform'),
        ('azure', '🔷',  'Azure', 'Microsoft Azure'),
    ]

    cols = st.columns(4)
    for i, (ptype, icon, name, desc) in enumerate(platforms):
        with cols[i]:
            st.markdown(f"""
            <div style="background: #111122; padding: 20px; border-radius: 10px;
                        border: 1px solid #222244; text-align: center; margin: 5px 0;">
                <h2 style="margin: 0; font-size: 2em;">{icon}</h2>
                <h3 style="color: #e0e0e0; margin: 5px 0;">{name}</h3>
                <p style="color: #666; margin: 0; font-size: 0.8em;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"Connect", key=f"platform_{ptype}", use_container_width=True):
                st.session_state.platform_type = ptype
                st.session_state.current_page = 'platform_config'
                st.rerun()

    if st.button("← Back", key="back_to_home"):
        st.session_state.current_page = 'platform_select'
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

    if st.button("← Back"):
        st.session_state.current_page = 'system_select'
        st.rerun()


def render_main_app():
    """Render the main application — two top-level tabs: Code Analysis and System."""
    platform = st.session_state.platform
    ptype = st.session_state.platform_type

    from components.platform_manager import PLATFORM_ICONS

    with st.sidebar:
        if st.session_state.nav_target:
            st.session_state.active_nav = st.session_state.nav_target
            st.session_state.nav_target = None

        if platform and ptype:
            st.caption(f"{PLATFORM_ICONS.get(ptype, '')} {ptype.upper()} — {'🟢 Connected' if platform.connected else '🔴 Disconnected'}")
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

    # Top-level tabs
    tab_code, tab_system = st.tabs(["🧬 Code Analysis", "🖥️ System"])

    with tab_code:
        st.session_state['top_tab'] = 'code'
        _render_code_scan()

    with tab_system:
        st.session_state['top_tab'] = 'system'
        if not platform or not platform.connected:
            st.info("No system connected.")
            if st.button("Connect to a System", type="primary", key="connect_system_tab"):
                st.session_state.current_page = 'system_select'
                st.rerun()
        elif ptype == 'ssh':
            _render_ssh_system(platform)
        elif ptype == 'aws':
            _render_aws_system(platform)
        elif ptype == 'gcp':
            _render_gcp_system(platform)
        elif ptype == 'azure':
            _render_azure_system(platform)
        else:
            _render_page(st.session_state.active_nav)


def _render_cloud_header(ptype: str, platform):
    """Shared header bar for cloud platforms."""
    icons = {'aws': '☁️', 'gcp': '🌐', 'azure': '🔷'}
    names = {'aws': 'AWS', 'gcp': 'GCP', 'azure': 'Azure'}
    cfg = platform.config if hasattr(platform, 'config') else {}
    detail = cfg.get('region') or cfg.get('project_id') or cfg.get('subscription_id', '')
    st.markdown(f"""
    <div style="background:#111122;padding:12px 20px;border-radius:8px;
                border:1px solid #222244;margin-bottom:16px;">
        <span style="color:#888;font-size:0.9em;">{icons.get(ptype,'')} {names.get(ptype,'Cloud')}</span>
        <span style="color:#e0e0e0;font-size:0.9em;margin-left:12px;">{detail}</span>
        <span style="color:#00cc44;font-size:0.9em;margin-left:12px;">🟢 Connected</span>
    </div>
    """, unsafe_allow_html=True)


def _render_cloud_setup_tab(ptype: str):
    """Setup instructions tab for cloud platforms."""
    if ptype == 'aws':
        st.markdown("### AWS CLI Setup")
        st.markdown("Follow these steps on your local machine to enable AWS analysis:")
        st.markdown("**1. Install AWS CLI**")
        st.code("pip install awscli", language="bash")
        st.markdown("**2. Configure credentials**")
        st.code("aws configure", language="bash")
        st.markdown("&nbsp;&nbsp;&nbsp;&nbsp;Enter: Access Key ID, Secret Access Key, Region (e.g. `ap-south-1`), Output format: `json`")
        st.markdown("**3. Verify**")
        st.code("aws sts get-caller-identity", language="bash")
        st.success("Once verified, switch to the TaaraAnalysis tab to run a scan.")

    elif ptype == 'gcp':
        st.markdown("### GCP CLI Setup")
        st.markdown("Follow these steps on your local machine to enable GCP analysis:")
        st.markdown("**1. Install gcloud SDK**")
        st.markdown("Download from [cloud.google.com/sdk](https://cloud.google.com/sdk) and run the installer.")
        st.markdown("**2. Authenticate**")
        st.code("gcloud auth login", language="bash")
        st.markdown("**3. Set project**")
        st.code("gcloud config set project YOUR_PROJECT_ID", language="bash")
        st.markdown("**4. Verify**")
        st.code("gcloud projects list", language="bash")
        st.success("Once verified, switch to the TaaraAnalysis tab to run a scan.")

    elif ptype == 'azure':
        st.markdown("### Azure CLI Setup")
        st.markdown("Follow these steps on your local machine to enable Azure analysis:")
        st.markdown("**1. Install Azure CLI**")
        st.markdown("Download from [docs.microsoft.com/cli/azure/install](https://docs.microsoft.com/cli/azure/install-azure-cli) and run the installer.")
        st.markdown("**2. Login**")
        st.code("az login", language="bash")
        st.markdown("**3. Set subscription**")
        st.code("az account set --subscription YOUR_SUBSCRIPTION_ID", language="bash")
        st.markdown("**4. Verify**")
        st.code("az account show", language="bash")
        st.success("Once verified, switch to the TaaraAnalysis tab to run a scan.")


def _run_cloud_commands(ptype: str, platform) -> dict:
    """Execute cloud CLI commands locally and return parsed results."""
    import subprocess
    import json as _json

    results = {}
    commands = {}
    if ptype == 'aws':
        cfg = platform.config if hasattr(platform, 'config') else {}
        region = cfg.get('region', 'us-east-1')
        commands = {
            'instances': f'aws ec2 describe-instances --region {region} --output json',
            'security_groups': f'aws ec2 describe-security-groups --region {region} --output json',
            'iam_users': 'aws iam list-users --output json',
            'cloudtrail': f'aws cloudtrail lookup-events --region {region} --max-results 10 --output json',
            's3_buckets': 'aws s3 ls',
        }
    elif ptype == 'gcp':
        cfg = platform.config if hasattr(platform, 'config') else {}
        project_id = cfg.get('project_id', '')
        commands = {
            'instances': 'gcloud compute instances list --format=json',
            'firewall_rules': 'gcloud compute firewall-rules list --format=json',
            'iam_policy': f'gcloud projects get-iam-policy {project_id} --format=json' if project_id else '',
            'logs': 'gcloud logging read "severity>=WARNING" --limit=10 --format=json',
            'billing': 'gcloud billing accounts list --format=json',
        }
        commands = {k: v for k, v in commands.items() if v}
    elif ptype == 'azure':
        commands = {
            'vms': 'az vm list --output json',
            'nsgs': 'az network nsg list --output json',
            'roles': 'az role assignment list --output json',
            'activity_log': 'az monitor activity-log list --max-events 10 --output json',
        }

    for key, cmd in commands.items():
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )
            out = proc.stdout.strip()
            try:
                results[key] = _json.loads(out) if out else {}
            except Exception:
                results[key] = {'raw': out[:2000]} if out else {'error': proc.stderr[:500]}
        except subprocess.TimeoutExpired:
            results[key] = {'error': f'Command timed out: {cmd[:60]}'}
        except Exception as e:
            results[key] = {'error': str(e)}
    return results


def _render_cloud_analysis_tab(ptype: str, platform):
    """TaaraAnalysis tab for cloud platforms — run scan, spending, TaaraWords."""
    taara_analyzer = st.session_state.taara_analyzer
    cloud_analyzer = st.session_state.cloud_analyzer
    llm_service = st.session_state.llm_service
    from components.taara_analysis import _run_analysis, _display_results

    col_scan, col_depth = st.columns([1, 2])
    with col_depth:
        scan_depth = st.selectbox("Scan Depth", ["Standard", "Deep", "Quick"], index=0,
                                  key=f"{ptype}_scan_depth")
    with col_scan:
        run_scan = st.button("▶ Run TaaraAnalysis", type="primary",
                             use_container_width=True, key=f"{ptype}_run_scan")

    if run_scan:
        with st.spinner("Collecting cloud resource data..."):
            cloud_data = _run_cloud_commands(ptype, platform)
            st.session_state[f'{ptype}_cloud_data'] = cloud_data
        _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service,
                      scan_depth, ptype, repo_target="", offline=False)

    cloud_data = st.session_state.get(f'{ptype}_cloud_data')
    if cloud_data:
        with st.expander("Raw Cloud Resource Data", expanded=False):
            for key, val in cloud_data.items():
                st.markdown(f"**{key}**")
                if isinstance(val, dict) and 'error' in val:
                    st.error(val['error'])
                elif isinstance(val, dict) and 'raw' in val:
                    st.text(val['raw'])
                else:
                    st.json(val)

    if st.session_state.get('analysis_results'):
        results = st.session_state.analysis_results

        if cloud_data:
            if 'cloud_raw' not in results:
                results['cloud_raw'] = {}
            results['cloud_raw'].update(cloud_data)

        _display_results(results, ptype)

        st.markdown("---")
        st.markdown("### Spending Analysis")
        if st.button("Run Spending Analysis", key=f"{ptype}_spending"):
            with st.spinner("Analysing resource costs..."):
                cost_result = cloud_analyzer.analyze_platform_costs(platform)
                st.session_state[f'_{ptype}_cost_result'] = cost_result

        cost_result = st.session_state.get(f'_{ptype}_cost_result')
        if cost_result:
            savings = cost_result.get('potential_monthly_savings', 0)
            recs = cost_result.get('optimization_recommendations', [])
            st.metric("Potential Monthly Savings", f"₹{savings:,.0f}" if savings else "—")
            for r in recs[:5]:
                st.markdown(f"- **{r.get('title', r.get('service',''))}**: "
                            f"{r.get('recommendation', r.get('description',''))}")

        st.markdown("---")
        st.markdown("### TaaraWords Report")
        if st.button("📄 Generate TaaraWords Report", type="primary", key=f"{ptype}_words"):
            from components.taara_words import generate_report_pdf
            with st.spinner("Generating PDF..."):
                try:
                    pdf_bytes = generate_report_pdf(results)
                    st.download_button(
                        "⬇ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"taara_report_{ptype}.pdf",
                        mime="application/pdf",
                        key=f"{ptype}_pdf_download"
                    )
                    st.success("Report ready.")
                except Exception as e:
                    st.error(f"PDF generation failed: {e}")


def _render_aws_system(platform):
    _render_cloud_header('aws', platform)
    tab_setup, tab_analysis = st.tabs(["⚙️ Setup", "🔍 TaaraAnalysis"])
    with tab_setup:
        _render_cloud_setup_tab('aws')
    with tab_analysis:
        _render_cloud_analysis_tab('aws', platform)


def _render_gcp_system(platform):
    _render_cloud_header('gcp', platform)
    tab_setup, tab_analysis = st.tabs(["⚙️ Setup", "🔍 TaaraAnalysis"])
    with tab_setup:
        _render_cloud_setup_tab('gcp')
    with tab_analysis:
        _render_cloud_analysis_tab('gcp', platform)


def _render_azure_system(platform):
    _render_cloud_header('azure', platform)
    tab_setup, tab_analysis = st.tabs(["⚙️ Setup", "🔍 TaaraAnalysis"])
    with tab_setup:
        _render_cloud_setup_tab('azure')
    with tab_analysis:
        _render_cloud_analysis_tab('azure', platform)


def _check_taaraware_deployed(platform) -> bool:
    """Check if TaaraWare agent is deployed on the remote SSH server."""
    try:
        out, _, rc = platform.execute_command(
            "test -f /opt/taaraware/taaraware_agent.py && echo YES || echo NO"
        )
        return out.strip() == 'YES'
    except Exception:
        return False


def _render_ssh_system(platform):
    """SSH connection: detect TaaraWare state, show State 1 or State 2 tabs."""
    host = platform.config.get('host', 'unknown')

    st.markdown(f"""
    <div style="background:#111122;padding:12px 20px;border-radius:8px;
                border:1px solid #222244;margin-bottom:16px;">
        <span style="color:#888;font-size:0.9em;">🖥️ SSH</span>
        <span style="color:#e0e0e0;font-size:0.9em;margin-left:12px;">{host}</span>
        <span style="color:#00cc44;font-size:0.9em;margin-left:12px;">🟢 Connected</span>
    </div>
    """, unsafe_allow_html=True)

    if 'taaraware_deployed' not in st.session_state:
        with st.spinner("Checking TaaraWare status..."):
            st.session_state['taaraware_deployed'] = _check_taaraware_deployed(platform)

    deployed = st.session_state.get('taaraware_deployed', False)

    if not deployed:
        _render_ssh_state1(platform)
    else:
        _render_ssh_state2(platform)


def _render_ssh_state1(platform):
    """State 1: TaaraWare not deployed. Show TaaraAnalysis + Deploy TaaraWare tabs."""
    taara_analyzer = st.session_state.taara_analyzer
    cloud_analyzer = st.session_state.cloud_analyzer
    llm_service = st.session_state.llm_service
    taaraware_mgr = st.session_state.taaraware_mgr

    tab_analysis, tab_deploy = st.tabs(["🔍 TaaraAnalysis", "🛡️ Deploy TaaraWare"])

    with tab_analysis:
        # Run TaaraAnalysis
        from components.taara_analysis import render_taara_analysis, _run_analysis, _display_results, build_infra_health_model
        ptype = platform.get_platform_info().get('type', 'ssh')

        col_scan, col_depth = st.columns([1, 2])
        with col_depth:
            scan_depth = st.selectbox("Scan Depth", ["Standard", "Deep", "Quick"], index=0,
                                      key="s1_scan_depth")
        with col_scan:
            run_scan = st.button("▶ Run TaaraAnalysis", type="primary",
                                 use_container_width=True, key="s1_run_scan")

        if run_scan:
            _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service,
                          scan_depth, ptype, repo_target="", offline=False)

        if st.session_state.get('analysis_results'):
            results = st.session_state.analysis_results
            _display_results(results, ptype)

            # Spending Analysis section
            st.markdown("---")
            st.markdown("### Spending Analysis")
            if st.button("Run Spending Analysis", key="s1_spending"):
                with st.spinner("Analysing resource costs..."):
                    cost_result = cloud_analyzer.analyze_platform_costs(platform)
                    st.session_state['_ssh_cost_result'] = cost_result

            cost_result = st.session_state.get('_ssh_cost_result')
            if cost_result:
                savings = cost_result.get('potential_monthly_savings', 0)
                recs = cost_result.get('optimization_recommendations', [])
                st.metric("Potential Monthly Savings", f"₹{savings:,.0f}" if savings else "—")
                if recs:
                    for r in recs[:5]:
                        st.markdown(f"- **{r.get('title', r.get('service',''))}**: "
                                    f"{r.get('recommendation', r.get('description',''))}")

            # Generate TaaraWords Report
            st.markdown("---")
            st.markdown("### TaaraWords Report")
            if st.button("📄 Generate TaaraWords Report", type="primary", key="s1_words"):
                from components.taara_words import generate_report_pdf
                with st.spinner("Generating PDF..."):
                    try:
                        pdf_bytes = generate_report_pdf(results)
                        st.download_button(
                            "⬇ Download PDF Report",
                            data=pdf_bytes,
                            file_name=f"taara_report_{platform.config.get('host','server')}.pdf",
                            mime="application/pdf",
                            key="s1_pdf_download"
                        )
                        st.success("Report ready.")
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

    with tab_deploy:
        st.markdown("### Deploy TaaraWare to this server")
        st.markdown(
            "TaaraWare is a lightweight agent that runs on your server and continuously "
            "collects behavioral signals — process trees, network patterns, filesystem changes. "
            "It sends only feature vectors to TAARA Command Center. Raw data never leaves your server."
        )

        with st.form("deploy_form"):
            cc_host = st.text_input("Command Center host IP (optional — for telemetry callbacks)",
                                     value="", placeholder="Leave blank for local-only mode")
            interval = st.number_input("Collection interval (seconds)", value=600,
                                        min_value=60, max_value=3600)
            submitted = st.form_submit_button("Deploy TaaraWare", type="primary",
                                               use_container_width=True)

        if submitted:
            progress = st.progress(0, text="Starting deployment...")
            progress.progress(20, text="Uploading agent script...")
            result = taaraware_mgr.deploy_agent(platform, {
                'command_center_host': cc_host,
                'interval': interval
            })
            progress.progress(90, text="Generating PQC key...")
            progress.progress(100, text="Done.")
            if result['success']:
                fingerprint = result.get('key_fingerprint', '')
                msg = result['message']
                if fingerprint and fingerprint != 'pqc_unavailable':
                    msg += f" | Key fingerprint: `{fingerprint}...`"
                st.success(msg)
                st.session_state['taaraware_deployed'] = True
                st.rerun()
            else:
                st.error(result['message'])


def _render_ssh_state2(platform):
    """State 2: TaaraWare deployed. Show full 7-tab management interface."""
    host = platform.config.get('host', 'unknown')
    taara_analyzer = st.session_state.taara_analyzer
    cloud_analyzer = st.session_state.cloud_analyzer
    llm_service = st.session_state.llm_service
    taaraware_mgr = st.session_state.taaraware_mgr
    security_agent = st.session_state.security_agent
    action_logger = st.session_state.action_logger
    embedder = st.session_state.embedder
    detector = st.session_state.detector

    st.markdown(f"""
    <div style="background:#0a1a0a;padding:12px 20px;border-radius:8px;
                border:1px solid #00cc44;margin-bottom:16px;">
        <span style="color:#888;font-size:0.9em;">🛡️ TaaraWare</span>
        <span style="color:#00cc44;font-size:0.9em;margin-left:12px;">● Deployed</span>
        <span style="color:#e0e0e0;font-size:0.9em;margin-left:12px;">{host}</span>
    </div>
    """, unsafe_allow_html=True)

    (tab_analysis, tab_status, tab_actions, tab_agent,
     tab_unified, tab_custom, tab_rollback,
     tab_settings, tab_revoke) = st.tabs([
        "🔍 TaaraAnalysis",
        "📊 Status Dashboard",
        "⚡ Agent & Actions",
        "🤖 Agent Panel",
        "🔒 Unified Security",
        "🛠️ Custom Actions",
        "↩️ Rollback Log",
        "⚙️ Settings",
        "🗑️ Revoke TaaraWare",
    ])

    # ── Tab 1: TaaraAnalysis (same as State 1) ──────────────────────────────
    with tab_analysis:
        from components.taara_analysis import _run_analysis, _display_results
        ptype = platform.get_platform_info().get('type', 'ssh')
        col_scan, col_depth = st.columns([1, 2])
        with col_depth:
            scan_depth = st.selectbox("Scan Depth", ["Standard", "Deep", "Quick"],
                                      index=0, key="s2_scan_depth")
        with col_scan:
            run_scan = st.button("▶ Run TaaraAnalysis", type="primary",
                                 use_container_width=True, key="s2_run_scan")
        if run_scan:
            _run_analysis(platform, taara_analyzer, cloud_analyzer, llm_service,
                          scan_depth, ptype, repo_target="", offline=False)
        if st.session_state.get('analysis_results'):
            results = st.session_state.analysis_results
            _display_results(results, ptype)
            st.markdown("---")
            st.markdown("### Spending Analysis")
            if st.button("Run Spending Analysis", key="s2_spending"):
                with st.spinner("Analysing resource costs..."):
                    cost_result = cloud_analyzer.analyze_platform_costs(platform)
                    st.session_state['_ssh_cost_result'] = cost_result
            cost_result = st.session_state.get('_ssh_cost_result')
            if cost_result:
                savings = cost_result.get('potential_monthly_savings', 0)
                recs = cost_result.get('optimization_recommendations', [])
                st.metric("Potential Monthly Savings", f"₹{savings:,.0f}" if savings else "—")
                for r in recs[:5]:
                    st.markdown(f"- **{r.get('title', r.get('service',''))}**: "
                                f"{r.get('recommendation', r.get('description',''))}")
            st.markdown("---")
            st.markdown("### TaaraWords Report")
            if st.button("📄 Generate TaaraWords Report", type="primary", key="s2_words"):
                from components.taara_words import generate_report_pdf
                with st.spinner("Generating PDF..."):
                    try:
                        pdf_bytes = generate_report_pdf(st.session_state.analysis_results)
                        st.download_button("⬇ Download PDF", data=pdf_bytes,
                                           file_name=f"taara_report_{host}.pdf",
                                           mime="application/pdf", key="s2_pdf")
                    except Exception as e:
                        st.error(f"PDF generation failed: {e}")

    # ── Tab 2: Status Dashboard ─────────────────────────────────────────────
    with tab_status:
        st.markdown("### Live Agent Status")
        col_refresh, col_auto = st.columns([1, 2])
        with col_refresh:
            if st.button("🔄 Refresh Now", key="s2_refresh_status"):
                st.session_state['_agent_status'] = None
                st.session_state['_status_last_refresh'] = time.time()
        with col_auto:
            auto_refresh = st.toggle("Auto-refresh every 30s", key="s2_auto_refresh", value=False)

        # Auto-refresh logic: rerun if toggle on and 30s elapsed since last refresh
        last_refresh = st.session_state.get('_status_last_refresh', 0)
        if auto_refresh and (time.time() - last_refresh) >= 30:
            st.session_state['_agent_status'] = None
            st.session_state['_status_last_refresh'] = time.time()

        if st.session_state.get('_agent_status') is None:
            with st.spinner("Fetching agent status..."):
                st.session_state['_agent_status'] = taaraware_mgr.check_agent_status(platform)
                st.session_state['_status_last_refresh'] = time.time()

        if auto_refresh:
            next_refresh = max(0, 30 - int(time.time() - st.session_state.get('_status_last_refresh', 0)))
            st.caption(f"Next auto-refresh in {next_refresh}s — page will refresh automatically.")

        agent_status = st.session_state.get('_agent_status', {})
        col1, col2, col3 = st.columns(3)
        with col1:
            status_val = agent_status.get('status', 'unknown')
            color = "#00cc44" if status_val == "active" else "#ff4444"
            st.markdown(f"<div style='background:#111;padding:15px;border-radius:8px;"
                        f"border:1px solid {color};text-align:center'>"
                        f"<p style='color:#888;margin:0;font-size:0.8em'>Agent Status</p>"
                        f"<p style='color:{color};margin:5px 0;font-size:1.4em;font-weight:bold'>"
                        f"{status_val.upper()}</p></div>", unsafe_allow_html=True)
        with col2:
            buf_size = agent_status.get('buffer_size', 0)
            st.metric("Buffer Size", f"{buf_size} samples")
        with col3:
            pid = agent_status.get('pid', '—')
            st.metric("PID", pid if pid else "—")

        if agent_status.get('recent_logs'):
            st.markdown("**Recent agent logs:**")
            st.code(agent_status['recent_logs'], language='text')

        st.markdown("---")
        st.markdown("### Latest Feature Vector")

        if st.button("Fetch latest feature vector", key="s2_fetch_vec"):
            with st.spinner("Reading remote buffer..."):
                data = taaraware_mgr.collect_remote_data(platform)
                st.session_state['_remote_buffer'] = data

        data = st.session_state.get('_remote_buffer', [])
        if data:
            latest = data[-1] if data else {}
            ts = latest.get('timestamp', latest.get('time', 'unknown'))
            st.caption(f"Last collection: {ts}")

            # Buffer entries are flat dicts — numeric features are top-level keys
            _INTERNAL_KEYS = {'timestamp', 'hostname', 'time', '_proc_pair_hashes',
                               '_bash_history_lines', '_auth_log_size'}
            if 'features' in latest:
                raw_feat = latest['features']
                if isinstance(raw_feat, dict):
                    features = {k: v for k, v in raw_feat.items() if k not in _INTERNAL_KEYS}
                else:
                    features = raw_feat
            else:
                # Flat dict format from TaaraWare agent
                features = {k: v for k, v in latest.items()
                            if k not in _INTERNAL_KEYS and isinstance(v, (int, float))}
            if isinstance(features, dict):
                items = list(features.items())
            elif isinstance(features, list):
                names = latest.get('feature_names', [f'feature_{i}' for i in range(len(features))])
                items = list(zip(names, features))
            else:
                items = []

            if items:
                cols = st.columns(3)
                for i, (name, val) in enumerate(items):
                    with cols[i % 3]:
                        try:
                            st.metric(str(name).replace('_', ' ').title(), f"{float(val):.3f}")
                        except Exception:
                            st.metric(str(name), str(val))

            training_mgr = st.session_state.training_mgr
            if training_mgr and training_mgr.is_ready() and embedder and embedder.is_ready():
                import numpy as np
                try:
                    if isinstance(features, dict):
                        fvec = np.array(list(features.values()), dtype=np.float32)
                    else:
                        fvec = np.array(features, dtype=np.float32)
                    fvec = fvec[:19] if len(fvec) >= 19 else np.pad(fvec, (0, 19 - len(fvec)))
                    embedding = embedder.embed(fvec)
                    detection = detector.detect(embedding) if detector and detector.is_ready() else {}
                    novelty = detection.get('anomaly_score', 0.0)
                    is_novel = detection.get('is_anomaly', False)
                    color = "#ff4444" if is_novel else "#00cc44"
                    st.markdown(f"**Novelty Score:** <span style='color:{color}'>"
                                f"{novelty:.3f} ({'NOVEL' if is_novel else 'Normal'})</span>",
                                unsafe_allow_html=True)
                except Exception:
                    pass
            else:
                st.info("Baseline building — train the model to see novelty scores.")
        else:
            st.info("No buffer data yet. Click 'Fetch latest feature vector' above.")

    # ── Tab 3: Agent & Actions ──────────────────────────────────────────────
    with tab_actions:
        from components.action_log import _generate_rollback_command
        import re as _re
        from datetime import datetime as _dt

        if 'executed_commands' not in st.session_state:
            st.session_state.executed_commands = []

        def _record_and_show(code, stdout, stderr, rc, source='manual', description=''):
            success = (rc == 0)
            entry = {
                'code': code, 'language': 'bash', 'source': source,
                'time': _dt.now().strftime('%H:%M:%S'),
                'status': 'success' if success else 'failed',
                'result': {'success': success, 'stdout': stdout, 'stderr': stderr,
                           'exit_code': rc},
            }
            st.session_state.executed_commands.append(entry)
            if success:
                st.success(f"✅ Executed: `{code[:80]}`")
                if stdout.strip():
                    st.code(stdout[:3000], language='text')
                else:
                    st.caption("(command completed with no output)")
            else:
                st.error(f"❌ Failed (rc={rc}): `{code[:80]}`")
                if stderr.strip():
                    st.code(stderr[:2000], language='text')

        # ── Pending agent proposals ────────────────────────────────────────
        st.markdown("### Pending Agent Actions")
        proposed = security_agent.proposed_actions
        if proposed:
            for i, action in enumerate(proposed):
                with st.expander(
                    f"[{action.get('time','?')}] {action.get('explanation','Action')[:80]}",
                    expanded=True
                ):
                    edited_code = st.text_area(
                        "Command (edit before approving)",
                        value=action.get('code', ''),
                        key=f"edit_action_{i}"
                    )
                    action['code'] = edited_code
                    st.caption(f"Source: {action.get('source','agent')} | Severity: {action.get('severity','?')}")
                    col_a, col_d = st.columns(2)
                    with col_a:
                        if st.button("✅ Approve & Execute", key=f"approve_action_{i}", type="primary"):
                            with st.spinner("Executing..."):
                                result = security_agent.execute_approved_action(i, platform)
                                stdout = result.get('stdout', result.get('output', ''))
                                stderr = result.get('stderr', '')
                                rc = result.get('rc', result.get('return_code', 0 if result.get('success') else 1))
                                rollback = _generate_rollback_command(edited_code)
                                action_logger.log('agent', 'action_approved', edited_code[:200],
                                                  severity='info',
                                                  metadata={'command': edited_code,
                                                            'rollback_cmd': rollback,
                                                            'stdout': stdout[:500], 'rc': rc})
                            _record_and_show(edited_code, stdout, stderr, rc, source='agent')
                            st.rerun()
                    with col_d:
                        if st.button("❌ Disapprove", key=f"disapprove_action_{i}"):
                            security_agent.proposed_actions.pop(i)
                            st.rerun()
        else:
            st.info("No pending actions. Run autonomous analysis from the Agent Panel tab to generate proposals.")

        st.markdown("---")

        # ── Manual Action ──────────────────────────────────────────────────
        st.markdown("### Manual Command")
        manual_cmd = st.text_area("Command", key="s2_manual_cmd",
                                   placeholder="e.g. ss -tlnp")
        if st.button("▶ Execute", type="primary", key="s2_exec_manual",
                     disabled=not manual_cmd.strip()):
            with st.spinner("Executing..."):
                out, err, rc = platform.execute_command(manual_cmd.strip())
                rollback = _generate_rollback_command(manual_cmd.strip())
                action_logger.log('manual', 'manual_command', manual_cmd.strip(),
                                  severity='warning',
                                  metadata={'command': manual_cmd.strip(),
                                            'rollback_cmd': rollback,
                                            'stdout': out[:500], 'rc': rc})
            _record_and_show(manual_cmd.strip(), out, err, rc, source='manual')

        st.markdown("---")

        # ── AI-Assisted Action ─────────────────────────────────────────────
        st.markdown("### AI-Assisted Command")
        ai_desc = st.text_area("Describe what you want in plain English",
                                key="s2_ai_action_desc",
                                placeholder="e.g. Disable root SSH login and restart the SSH service")
        if st.button("Generate with AI", key="s2_ai_gen",
                     disabled=not (ai_desc.strip() and llm_service)):
            with st.spinner("Asking AI..."):
                prompt = (f"Generate a single bash command or short script to: {ai_desc.strip()}\n"
                          f"Server OS: Linux. Return ONLY the command in a ```bash block. "
                          f"Include a one-line comment explaining what it does.")
                resp = llm_service.generate_response(prompt)
            commands = resp.get('commands', []) if resp.get('success') else []
            if commands:
                st.session_state['_ai_generated_cmd'] = commands[0]
            else:
                text = resp.get('explanation', resp.get('text', ''))
                m = _re.search(r'```(?:bash)?\n(.*?)```', text, _re.DOTALL)
                if m:
                    st.session_state['_ai_generated_cmd'] = {'code': m.group(1).strip(),
                                                               'language': 'bash',
                                                               'explanation': ai_desc}
                else:
                    st.warning("AI did not return a parseable command. Try rephrasing.")

        ai_cmd = st.session_state.get('_ai_generated_cmd')
        if ai_cmd:
            st.markdown("**Generated — edit if needed, then approve:**")
            edited = st.text_area("Edit command", value=ai_cmd.get('code', ''),
                                   key="s2_ai_cmd_edit")
            col_app, col_dis = st.columns(2)
            with col_app:
                if st.button("✅ Approve & Execute", type="primary", key="s2_ai_approve"):
                    with st.spinner("Executing..."):
                        out, err, rc = platform.execute_command(edited.strip())
                        rollback = _generate_rollback_command(edited.strip())
                        action_logger.log('ai_action', 'ai_assisted_command', edited.strip(),
                                          severity='warning',
                                          metadata={'command': edited.strip(),
                                                    'rollback_cmd': rollback,
                                                    'description': ai_desc,
                                                    'stdout': out[:500], 'rc': rc})
                    del st.session_state['_ai_generated_cmd']
                    _record_and_show(edited.strip(), out, err, rc, source='ai_action',
                                     description=ai_desc)
                    st.rerun()
            with col_dis:
                if st.button("❌ Disapprove", key="s2_ai_disapprove"):
                    del st.session_state['_ai_generated_cmd']
                    st.rerun()

        # ── Execution history (shared with AI Chat) ────────────────────────
        executed = st.session_state.get('executed_commands', [])
        if executed:
            st.markdown("---")
            st.markdown(f"### Execution History ({len(executed)} commands)")
            for idx, ec in enumerate(reversed(executed[-20:])):
                status = ec.get('status', 'unknown')
                icon = '✅' if status == 'success' else ('❌' if status == 'failed' else '🚫')
                with st.expander(
                    f"{icon} [{ec.get('time','')}] [{ec.get('source','')}] {ec['code'][:70]}",
                    expanded=(idx == 0)
                ):
                    st.code(ec['code'], language='bash')
                    res = ec.get('result', {})
                    if res.get('stdout', '').strip():
                        st.markdown("**Output:**")
                        st.code(res['stdout'][:3000], language='text')
                    if res.get('stderr', '').strip():
                        st.markdown("**Stderr:**")
                        st.code(res['stderr'][:1000], language='text')
                    if status == 'success':
                        st.success("Completed successfully")
                    elif status == 'failed':
                        st.error(f"Exit code: {res.get('exit_code', '?')}")
            if st.button("Clear execution history", key="s2_clear_exec_hist"):
                st.session_state.executed_commands = []
                st.rerun()

    # ── Tab 4: Agent Panel ──────────────────────────────────────────────────
    with tab_agent:
        st.markdown("### Agent Configuration")
        autonomy = st.slider("Autonomy Level", min_value=0, max_value=5,
                              value=st.session_state.get('_autonomy_level', 0),
                              key="s2_autonomy",
                              help="0 = propose only, 5 = execute within safe policy bounds automatically")
        st.session_state['_autonomy_level'] = autonomy
        st.caption({
            0: "Level 0 — Propose everything, execute nothing without approval.",
            1: "Level 1 — Auto-execute read-only commands (status checks, log reads).",
            2: "Level 2 — Auto-execute non-destructive hardening (close ports, tighten permissions).",
            3: "Level 3 — Auto-execute all policy-safe commands. Notify on execution.",
            4: "Level 4 — Auto-execute + auto-remediate repeated failures.",
            5: "Level 5 — Full autonomous mode within policy bounds. Human review of logs only.",
        }.get(autonomy, ""))

        if st.button("Run Autonomous Analysis", type="primary", key="s2_autonomous"):
            with st.spinner("Running full autonomous analysis cycle..."):
                result = security_agent.autonomous_analyze(
                    platform, taara_analyzer, llm_service, embedder, detector
                )
            if result.get('success'):
                cmds = result.get('commands', [])
                st.success(f"Analysis complete. {len(cmds)} remediation commands proposed.")
                if autonomy >= 3:
                    st.info(f"Autonomy level {autonomy} — executing safe commands automatically.")
                    for i in range(len(security_agent.proposed_actions) - 1, -1, -1):
                        security_agent.execute_approved_action(i, platform)
                    st.success("Auto-executed all proposed actions.")
            else:
                st.error(result.get('error', 'Analysis failed.'))

        st.markdown("---")
        st.markdown("### Learned Patterns")
        patterns = security_agent.learned_patterns
        if patterns:
            for key, p in list(patterns.items())[-20:]:
                col_p, col_del = st.columns([5, 1])
                with col_p:
                    st.markdown(f"**`{p.get('command_prefix','')[:70]}...`**  "
                                f"✅ {p.get('successes',0)}  ❌ {p.get('failures',0)}")
                with col_del:
                    if st.button("Remove", key=f"del_pattern_{key}"):
                        del security_agent.learned_patterns[key]
                        security_agent._save_learned_patterns()
                        st.rerun()
        else:
            st.info("No learned patterns yet. They build up as the agent executes and learns from results.")

        if st.button("Save Agent Configuration", key="s2_save_agent"):
            security_agent._save_learned_patterns()
            st.success("Configuration saved.")

    # ── Tab 5: Unified Security Dashboard ──────────────────────────────────
    with tab_unified:
        st.markdown("### Security Tools on This Server")
        if st.button("🔍 Scan for installed tools", key="s2_scan_tools"):
            st.session_state['_sec_tools'] = None

        TOOLS = [
            ('fail2ban',  'fail2ban-client status',
             'sudo apt-get install fail2ban -y'),
            ('ufw',       'ufw status verbose',
             'sudo apt-get install ufw -y && sudo ufw enable'),
            ('lynis',     'tail -20 /var/log/lynis.log 2>/dev/null || echo "NOT_FOUND"',
             'sudo apt-get install lynis -y'),
            ('rkhunter',  'tail -20 /var/log/rkhunter.log 2>/dev/null || echo "NOT_FOUND"',
             'sudo apt-get install rkhunter -y'),
            ('netstat',   'ss -tulnp 2>/dev/null | head -30',
             'sudo apt-get install iproute2 -y'),
            ('auth.log',  'tail -20 /var/log/auth.log 2>/dev/null || echo "NOT_FOUND"',
             'N/A — system log'),
            ('cron',      'crontab -l 2>/dev/null || echo "NO_CRONTAB"',
             'N/A — built-in'),
        ]

        if st.session_state.get('_sec_tools') is None:
            with st.spinner("Checking tools..."):
                results_tools = {}
                for name, cmd, install_hint in TOOLS:
                    out, err, rc = platform.execute_command(cmd)
                    output = (out or err or '').strip()
                    installed = 'NOT_FOUND' not in output and 'NO_CRONTAB' not in output and output
                    results_tools[name] = {
                        'installed': bool(installed),
                        'output': output[:500],
                        'install_hint': install_hint,
                    }
                st.session_state['_sec_tools'] = results_tools

        tools_data = st.session_state.get('_sec_tools', {})
        for name, data in tools_data.items():
            installed = data.get('installed', False)
            icon = "🟢" if installed else "🔴"
            with st.expander(f"{icon} {name.upper()} — {'Installed' if installed else 'Not installed'}"):
                if installed:
                    output = data.get('output', '')
                    if output:
                        st.code(output, language='text')
                    else:
                        st.caption("No output returned.")
                else:
                    st.warning(f"Not installed. Install with: `{data.get('install_hint','')}`")

        st.markdown("---")
        st.markdown("### Last 20 Failed Login Attempts")
        if st.button("Fetch failed logins", key="s2_failed_logins"):
            out, _, _ = platform.execute_command(
                "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20"
            )
            st.session_state['_failed_logins'] = out.strip()
        logins = st.session_state.get('_failed_logins', '')
        if logins:
            st.code(logins, language='text')
        elif logins == '':
            st.info("No failed login attempts found in auth.log.")

    # ── Tab 6: Custom Actions ───────────────────────────────────────────────
    with tab_custom:
        import re as _re2
        from components.action_log import _generate_rollback_command as _grc
        from datetime import datetime as _dt2

        if 'executed_commands' not in st.session_state:
            st.session_state.executed_commands = []

        def _custom_record_and_show(code, stdout, stderr, rc, source='custom'):
            success = (rc == 0)
            st.session_state.executed_commands.append({
                'code': code, 'language': 'bash', 'source': source,
                'time': _dt2.now().strftime('%H:%M:%S'),
                'status': 'success' if success else 'failed',
                'result': {'success': success, 'stdout': stdout, 'stderr': stderr,
                           'exit_code': rc},
            })
            if success:
                st.success(f"✅ Done: `{code[:80]}`")
                if stdout.strip():
                    st.code(stdout[:3000], language='text')
                else:
                    st.caption("(completed with no output)")
            else:
                st.error(f"❌ Failed (rc={rc}): `{code[:80]}`")
                if stderr.strip():
                    st.code(stderr[:2000], language='text')

        st.markdown("### Custom Actions")
        mode = st.radio("Mode", ["Manual", "AI-Assisted"], key="s2_custom_mode", horizontal=True)

        if mode == "Manual":
            cmd_input = st.text_area("Command", key="s2_custom_manual",
                                      placeholder="Enter any bash command")
            st.caption("Executes on the connected server as the configured SSH user.")
            confirm = st.checkbox("I confirm I want to run this on the remote server",
                                   key="s2_custom_confirm")
            if st.button("▶ Execute", type="primary", key="s2_custom_exec_manual",
                         disabled=not (cmd_input.strip() and confirm)):
                with st.spinner("Executing..."):
                    out, err, rc = platform.execute_command(cmd_input.strip())
                    rollback = _grc(cmd_input.strip())
                    action_logger.log('custom', 'custom_command', cmd_input.strip(),
                                      severity='warning',
                                      metadata={'command': cmd_input.strip(),
                                                'rollback_cmd': rollback,
                                                'stdout': out[:500], 'rc': rc})
                _custom_record_and_show(cmd_input.strip(), out, err, rc, source='custom_manual')
        else:
            desc = st.text_area("Describe what you want",
                                 key="s2_custom_ai_desc",
                                 placeholder="e.g. List all open ports and their associated processes")
            if st.button("Generate with AI", key="s2_custom_ai_gen",
                         disabled=not (desc.strip() and llm_service)):
                with st.spinner("Generating..."):
                    prompt = (f"Generate a bash command or short script to: {desc.strip()}\n"
                              f"Linux server. Return ONLY the command in a ```bash block.")
                    resp = llm_service.generate_response(prompt)
                commands = resp.get('commands', []) if resp.get('success') else []
                if commands:
                    st.session_state['_custom_ai_cmd'] = commands[0].get('code', '')
                else:
                    text = resp.get('explanation', resp.get('text', ''))
                    m = _re2.search(r'```(?:bash)?\n(.*?)```', text, _re2.DOTALL)
                    st.session_state['_custom_ai_cmd'] = m.group(1).strip() if m else ''
                    if not st.session_state['_custom_ai_cmd']:
                        st.warning("AI did not return a parseable command. Try rephrasing.")

            ai_cmd = st.session_state.get('_custom_ai_cmd', '')
            if ai_cmd:
                edited = st.text_area("Edit if needed", value=ai_cmd,
                                       key="s2_custom_ai_edit")
                col_a, col_d = st.columns(2)
                with col_a:
                    if st.button("✅ Approve & Execute", type="primary",
                                 key="s2_custom_ai_approve"):
                        with st.spinner("Executing..."):
                            out, err, rc = platform.execute_command(edited.strip())
                            rollback = _grc(edited.strip())
                            action_logger.log('custom_ai', 'ai_custom_command', edited.strip(),
                                              severity='warning',
                                              metadata={'command': edited.strip(),
                                                        'rollback_cmd': rollback,
                                                        'description': desc,
                                                        'stdout': out[:500], 'rc': rc})
                        del st.session_state['_custom_ai_cmd']
                        _custom_record_and_show(edited.strip(), out, err, rc, source='custom_ai')
                        st.rerun()
                with col_d:
                    if st.button("❌ Disapprove", key="s2_custom_ai_dis"):
                        st.session_state['_custom_ai_cmd'] = ''
                        st.rerun()

        # ── Execution history ──────────────────────────────────────────────
        executed = st.session_state.get('executed_commands', [])
        if executed:
            st.markdown("---")
            st.markdown(f"### Execution History ({len(executed)} commands)")
            for idx, ec in enumerate(reversed(executed[-20:])):
                status = ec.get('status', 'unknown')
                icon = '✅' if status == 'success' else ('❌' if status == 'failed' else '🚫')
                with st.expander(
                    f"{icon} [{ec.get('time','')}] [{ec.get('source','')}] {ec['code'][:70]}",
                    expanded=(idx == 0)
                ):
                    st.code(ec['code'], language='bash')
                    res = ec.get('result', {})
                    if res.get('stdout', '').strip():
                        st.markdown("**Output:**")
                        st.code(res['stdout'][:3000], language='text')
                    if res.get('stderr', '').strip():
                        st.markdown("**Stderr:**")
                        st.code(res['stderr'][:1000], language='text')
                    if status == 'success':
                        st.success("Completed successfully")
                    elif status == 'failed':
                        st.error(f"Exit code: {res.get('exit_code', '?')}")
            if st.button("Clear history", key="s2_custom_clear_hist"):
                st.session_state.executed_commands = []
                st.rerun()

    # ── Tab 7: Rollback Log ─────────────────────────────────────────────────
    with tab_rollback:
        from components.action_log import render_action_log
        render_action_log(action_logger, security_agent)

    # ── Tab 8: Settings ─────────────────────────────────────────────────────
    with tab_settings:
        st.markdown("### Settings")

        with st.expander("Profile", expanded=True):
            firm_name = st.text_input("Firm name (shown on TaaraWords PDF)",
                                       value=st.session_state.get('_firm_name', ''),
                                       key="s2_firm_name")
            if st.button("Save profile", key="s2_save_profile"):
                st.session_state['_firm_name'] = firm_name
                st.success("Saved.")

        with st.expander("Autonomy"):
            st.info("Set the global autonomy level in the Agent Panel tab.")

        with st.expander("Notifications"):
            webhook = st.text_input("Webhook URL (POST on alert)",
                                     value=st.session_state.get('_webhook_url', ''),
                                     key="s2_webhook")
            email = st.text_input("Alert email",
                                   value=st.session_state.get('_alert_email', ''),
                                   key="s2_email")
            if st.button("Save notifications", key="s2_save_notif"):
                st.session_state['_webhook_url'] = webhook
                st.session_state['_alert_email'] = email
                st.success("Saved.")

        with st.expander("Key Management"):
            import json as _json
            keys_path = 'models/client_keys.json'
            keys = {}
            if os.path.exists(keys_path):
                try:
                    with open(keys_path) as kf:
                        keys = _json.load(kf)
                except Exception:
                    pass
            key_entry = keys.get(host)
            if key_entry and isinstance(key_entry, dict):
                fingerprint = key_entry.get('fingerprint', key_entry.get('public_key', '')[:8])
                algo = key_entry.get('algorithm', 'Kyber768')
                st.markdown(f"**Algorithm:** `{algo}` (NIST FIPS 203 — lattice-based, quantum-hard)")
                st.markdown(f"**Key fingerprint:** `{fingerprint}...`")
                st.caption("Full key never displayed. Shared secret exists in session memory only.")
                col_rev, col_reg = st.columns(2)
                with col_rev:
                    if st.button("Revoke key", key="s2_revoke_key"):
                        keys.pop(host, None)
                        with open(keys_path, 'w') as kf:
                            _json.dump(keys, kf)
                        st.session_state.get('client_shared_secrets', {}).pop(host, None)
                        st.success("Key revoked. Baseline reset required.")
                        st.rerun()
                with col_reg:
                    if st.button("Regenerate key", key="s2_regen_key"):
                        try:
                            import oqs
                            kem = oqs.KeyEncapsulation('Kyber768')
                            pub = kem.generate_keypair()
                            ct, ss = kem.encap_secret(pub)
                            keys[host] = {
                                'public_key': pub.hex(),
                                'ciphertext': ct.hex(),
                                'fingerprint': pub.hex()[:8],
                                'algorithm': 'Kyber768',
                                'generated_at': time.time(),
                            }
                            with open(keys_path, 'w') as kf:
                                _json.dump(keys, kf)
                            if 'client_shared_secrets' not in st.session_state:
                                st.session_state['client_shared_secrets'] = {}
                            st.session_state['client_shared_secrets'][host] = ss.hex()
                            st.success("New Kyber768 key generated. Baseline reset required.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Key regeneration failed: {e}")
            else:
                st.info("No PQC key on file for this host. Deploy TaaraWare to generate one.")
                st.caption("Key is generated automatically at deployment using Kyber768 (ML-KEM).")

        with st.expander("Appearance"):
            theme = st.selectbox("Theme", ["Dark", "Cyberpunk", "Midnight", "Terminal", "Light"],
                                  key="s2_theme")
            THEMES = {
                "Dark":      ".stApp { background-color: #0a0a1a; } * { color: #e0e0e0; }",
                "Cyberpunk": ".stApp { background-color: #0d001a; } h1,h2,h3 { color: #ff00ff; }",
                "Midnight":  ".stApp { background-color: #000011; } h1,h2,h3 { color: #4444ff; }",
                "Terminal":  ".stApp { background-color: #000000; } * { color: #00ff00; font-family: monospace; }",
                "Light":     ".stApp { background-color: #f5f5f5; } * { color: #111; }",
            }
            if st.button("Apply theme", key="s2_apply_theme"):
                st.session_state['_theme_css'] = THEMES.get(theme, '')
                st.rerun()

        theme_css = st.session_state.get('_theme_css', '')
        if theme_css:
            st.markdown(f"<style>{theme_css}</style>", unsafe_allow_html=True)

    # ── Tab 9: Revoke TaaraWare ─────────────────────────────────────────────
    with tab_revoke:
        st.markdown("### Revoke TaaraWare")
        st.warning("This will stop and remove the TaaraWare agent from the remote server. "
                   "All buffered feature data on the remote server will be deleted.")

        backup_col, _ = st.columns([2, 1])
        with backup_col:
            backup_buffer = st.checkbox("Download feature buffer before removing",
                                         key="s2_backup_before_revoke", value=True)

        confirm_revoke = st.checkbox("I understand — stop and remove TaaraWare from this server",
                                      key="s2_confirm_revoke")
        if st.button("Revoke TaaraWare", type="primary", key="s2_revoke",
                     disabled=not confirm_revoke):
            progress = st.progress(0, text="Starting revoke...")

            # Step 1: Optionally download buffer
            if backup_buffer:
                progress.progress(10, text="Downloading feature buffer...")
                try:
                    buffer_data = taaraware_mgr.collect_remote_data(platform)
                    if buffer_data:
                        import json as _rjson
                        buf_bytes = _rjson.dumps(buffer_data).encode()
                        st.download_button(
                            "⬇ Download Buffer Backup",
                            data=buf_bytes,
                            file_name=f"taaraware_buffer_{host}.json",
                            mime="application/json",
                            key="s2_revoke_backup_dl"
                        )
                except Exception as e:
                    st.warning(f"Buffer download failed: {e}")

            # Step 2: Stop and disable service
            progress.progress(30, text="Stopping TaaraWare service...")
            _, _, _ = platform.execute_command("sudo systemctl stop taaraware 2>/dev/null || true")
            _, _, _ = platform.execute_command("sudo systemctl disable taaraware 2>/dev/null || true")

            # Step 3: Remove service file and reload systemd
            progress.progress(60, text="Removing service files...")
            _, _, _ = platform.execute_command("sudo rm -f /etc/systemd/system/taaraware.service")
            _, _, _ = platform.execute_command("sudo systemctl daemon-reload 2>/dev/null || true")

            # Step 4: Remove agent files
            progress.progress(80, text="Removing agent files...")
            _, err, rc = platform.execute_command("sudo rm -rf /opt/taaraware")

            # Step 5: Clean up local state
            progress.progress(95, text="Cleaning up local state...")
            taaraware_mgr.deployed_agents.pop(host, None)
            taaraware_mgr._save_state()

            # Remove PQC key for this host
            import json as _rjson
            keys_path = 'models/client_keys.json'
            if os.path.exists(keys_path):
                try:
                    with open(keys_path) as kf:
                        keys = _rjson.load(kf)
                    keys.pop(host, None)
                    with open(keys_path, 'w') as kf:
                        _rjson.dump(keys, kf)
                except Exception:
                    pass
            if 'client_shared_secrets' in st.session_state:
                st.session_state['client_shared_secrets'].pop(host, None)

            action_logger.log('taaraware', 'revoke', f'TaaraWare revoked from {host}',
                              severity='warning')

            progress.progress(100, text="Done.")
            st.session_state['taaraware_deployed'] = False
            st.session_state['_agent_status'] = None
            st.session_state['_sec_tools'] = None

            if rc != 0 and err.strip() and 'No such file' not in err:
                st.warning(f"Completed with note: {err.strip()[:120]}")
            else:
                st.success(f"TaaraWare fully removed from {host}. PQC key revoked.")
            st.rerun()


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

    elif page == 'code_scan':
        _render_code_scan()

    elif page == 'taaraware_actions':
        _render_taaraware_actions(platform, taaraware_mgr)

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


def _render_code_scan():
    """Standalone Code / Repo Scan — no platform connection required."""
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #0a1a2e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #0a3060;">
        <h1 style="color: #4a9eff; margin: 0; font-size: 2.2em;">Code Scan</h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Scan any GitHub repo or local path for CVEs, EOL images,
            unsafe CI/CD, and cross-file failure chains.
            No platform connection required.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input(
            "Repository URL or local path",
            placeholder="https://github.com/org/repo  or  /path/to/local/repo",
            key="code_scan_target"
        )
    with col2:
        offline = st.checkbox("Offline mode", value=False,
                              help="Skip OSV.dev + endoflife.date API calls. "
                                   "Lockfile parsing + static checks still run.")

    if st.button("Run Code Scan", type="primary", use_container_width=True,
                 disabled=not target):
        if not target.strip():
            st.warning("Enter a repo URL or local path.")
            return

        # Clear previous scan PDF when starting a new scan
        st.session_state.pop("code_scan_pdf", None)

        progress = st.progress(0, text="Starting scan...")
        status_box = st.empty()

        try:
            from research.scan_repo import scan_repo
            progress.progress(20, text="Resolving repository...")
            status_box.info(f"Scanning: `{target.strip()}`")

            result = scan_repo(target.strip(), offline=offline)
            progress.progress(100, text="Scan complete.")
            status_box.empty()

            if result.get("error"):
                st.error(f"Scan error: {result['error']}")
                return

            # Store result in session state — everything renders from here on re-runs
            if "analysis_results" not in st.session_state or not st.session_state.analysis_results:
                st.session_state.analysis_results = {}
            st.session_state.analysis_results["repo_results"] = result
            st.session_state["code_scan_result"] = result

        except Exception as e:
            progress.progress(100)
            st.error(f"Scan failed: {e}")
            return

    # ── Results — rendered from session state so they survive any re-render ──
    result = st.session_state.get("code_scan_result")
    if not result:
        return

    findings = result.get("findings", [])
    chains = result.get("cross_file_chains", [])
    skipped = result.get("offline_skipped", [])

    # Summary metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Findings", len(findings))
    with c2:
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        st.metric("Critical / High", f"{critical} / {high}")
    with c3:
        structural_chain_count = sum(1 for c in chains if c.get("chain_id") != "graphrag:llm_dependency_analysis")
        st.metric("Cross-file Chains", structural_chain_count)
    with c4:
        st.metric("Packages Scanned", result.get("packages_resolved", 0))

    if skipped:
        st.info(f"Offline mode — skipped: {', '.join(skipped)}")

    rq = result.get("repo_quantum_fidelity")
    if rq:
        fval = rq.get("fidelity", 0)
        color = "#ff2222" if fval < 0.5 else "#ffcc00" if fval < 0.7 else "#44ff88"
        st.markdown(
            f"<div style='background:#0d0d1a;padding:12px 16px;border-radius:8px;"
            f"border-left:4px solid {color};margin:8px 0'>"
            f"<b style='color:{color}'>Repo Posture Fidelity F={fval:.3f}</b>"
            f"<span style='color:#a0a0b0;margin-left:12px'>{rq.get('interpretation','')}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

    # GraphRAG LLM analysis
    graphrag_chain = next(
        (c for c in chains if c.get("chain_id") == "graphrag:llm_dependency_analysis"), None
    )
    if graphrag_chain:
        st.markdown("### TAARA Dependency Risk Analysis")
        st.markdown(
            f"<div style='background:#0a1a2e;padding:16px;border-radius:8px;"
            f"border-left:4px solid #4a9eff;color:#e0e0f0;line-height:1.7'>"
            f"{graphrag_chain.get('detail','')}</div>",
            unsafe_allow_html=True
        )
        laf = graphrag_chain.get("llm_answer_fidelity")
        if laf:
            st.caption(f"Answer fidelity F={laf['fidelity']:.3f} — {laf['interpretation']}")
        if graphrag_chain.get("remediation"):
            st.info(graphrag_chain["remediation"])

    # Cross-file chains
    structural_chains = [c for c in chains if c.get("chain_id") != "graphrag:llm_dependency_analysis"]
    if structural_chains:
        st.markdown("### Cross-file Failure Chains")
        st.caption("Multi-file risk paths — the danger is in the connection, not any single file.")
        for c in structural_chains:
            with st.expander(f"[{c.get('severity','?').upper()}] {c.get('title', 'Unknown')}"):
                files = c.get("files", c.get("files_involved", []))
                if files:
                    st.markdown(f"**Files involved:** {' → '.join(str(x) for x in files)}")
                st.markdown(f"**Attack path:** {c.get('attack_path', c.get('detail', ''))}")
                st.markdown(f"**Remediation:** {c.get('remediation', '')}")
                if c.get("why_tests_miss_this"):
                    st.caption(f"Why tests miss this: {c['why_tests_miss_this']}")
                if c.get("real_incident"):
                    st.caption(f"Real incident: {c['real_incident']}")

    # Findings by severity
    if findings:
        st.markdown("### Findings")
        for sev, color in [("critical","#ff2222"), ("high","#ff8800"),
                           ("medium","#ffcc00"), ("low","#88ff88")]:
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if not sev_findings:
                continue
            st.markdown(
                f"<span style='color:{color}'>**{sev.upper()}** ({len(sev_findings)})</span>",
                unsafe_allow_html=True
            )
            for f in sev_findings:
                with st.expander(f.get("title", "Finding")):
                    st.markdown(f.get("detail", ""))
                    if f.get("remediation"):
                        st.info(f.get("remediation"))
                    cols = st.columns(2)
                    if f.get("osv_id"):
                        cols[0].caption(f"OSV: {f['osv_id']}")
                        if f.get("fix_versions"):
                            cols[0].caption(f"Fix: {f['fix_versions'][0]}")
                    if f.get("quantum_fidelity"):
                        qf = f["quantum_fidelity"]
                        F = qf.get("fidelity", 0)
                        cols[1].caption(
                            f"Quantum F={F:.3f} — {qf.get('interpretation','')[:70]}"
                        )

    # Download report
    st.markdown("---")
    st.markdown("### Download Report")
    client_name = st.text_input(
        "Client name (optional)", placeholder="Enter client org name", key="code_scan_client"
    )
    if st.button("Generate PDF Report", key="code_scan_pdf_btn", use_container_width=True):
        with st.spinner("Building report..."):
            try:
                from components.taara_words import generate_report_pdf
                pdf_bytes = generate_report_pdf(
                    st.session_state.analysis_results, {"client_name": client_name}
                )
                st.session_state["code_scan_pdf"] = pdf_bytes
                st.success("Report ready.")
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

    if st.session_state.get("code_scan_pdf"):
        st.download_button(
            label="Download TAARA Code Scan Report (PDF)",
            data=st.session_state["code_scan_pdf"],
            file_name=f"TAARA_CodeScan_{result.get('repo','repo')}_{result.get('scanned_at','')[:10]}.pdf",
            mime="application/pdf",
            use_container_width=True,
            type="primary",
        )


def _render_taaraware_actions(platform, taaraware_mgr):
    """TaaraWare autonomous actions log — CIA triad demo panel."""
    import json
    from pathlib import Path

    st.markdown("""
    <div style="background: linear-gradient(135deg, #0a2e0a 0%, #1a1a2e 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #00cc44;">
        <h1 style="color: #00cc44; margin: 0; font-size: 2.2em;">TaaraWare Actions</h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Autonomous actions taken by deployed agents. Policy-bounded.
            High-impact actions require human approval.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Load real action log if it exists
    log_path = Path("models/agent_log.json")
    actions = []
    if log_path.exists():
        try:
            with open(log_path) as f:
                actions = json.load(f)
        except Exception:
            pass

    # Always show demo actions for the CIA triad story
    demo_actions = [
        {
            "timestamp": "2026-05-16T02:14:33Z",
            "agent": "taaraware@10.147.20.101",
            "action_type": "autonomous_block",
            "pillar": "Availability",
            "trigger": "847 failed SSH attempts in 90 seconds from 185.220.101.42",
            "action_taken": "iptables -I INPUT -s 185.220.101.42 -j DROP",
            "human_approval_required": False,
            "reason": "Within policy bounds: >200 failed attempts/minute. Traditional IDS logged only.",
            "taara_advantage": "Standard fail2ban default threshold: 5 failures. Attack was slow-ramping to stay under threshold. TAARA's reconstruction novelty caught behavioral direction shift at attempt 23.",
            "severity": "critical",
            "status": "executed",
        },
        {
            "timestamp": "2026-05-15T22:01:55Z",
            "agent": "taaraware@10.147.20.101",
            "action_type": "integrity_alert",
            "pillar": "Integrity",
            "trigger": "sshd_config modified — PermitRootLogin changed from 'no' to 'yes'",
            "action_taken": "Alert sent to Command Center. Config snapshot taken. Human approval requested to revert.",
            "human_approval_required": True,
            "reason": "Config revert is high-impact — requires operator confirmation.",
            "taara_advantage": "No standard monitoring tool flagged this. File integrity monitoring (AIDE/Tripwire) not installed. TAARA's config drift detection caught it in 38 seconds.",
            "severity": "critical",
            "status": "pending_approval",
        },
        {
            "timestamp": "2026-05-16T03:55:12Z",
            "agent": "taaraware@10.147.20.101",
            "action_type": "confidentiality_flag",
            "pillar": "Confidentiality",
            "trigger": "developer_temp_key accessed ec2:DescribeInstances from eu-north-1 (baseline: ap-south-1 only)",
            "action_taken": "Behavioral novelty flagged. Quantum fidelity F=0.18 (threshold 0.5). Alert queued.",
            "human_approval_required": False,
            "reason": "Read-only action, no data exfiltration confirmed. Flag + alert, no block.",
            "taara_advantage": "SIEM rule-based tools would not flag this — it is a valid API call. TAARA flagged it because the direction is new for this identity. F=0.18 means the behavioral state is 82% orthogonal to all prior observations.",
            "severity": "high",
            "status": "flagged",
        },
    ]

    all_actions = demo_actions + actions

    # CIA Triad summary
    st.markdown("### CIA Triad Coverage")
    c1, c2, c3 = st.columns(3)
    with c1:
        conf = [a for a in all_actions if a.get("pillar") == "Confidentiality"]
        color = "#ff4444" if conf else "#444"
        st.markdown(f"<div style='background:#111;border:1px solid {color};border-radius:8px;padding:15px;text-align:center'>"
                    f"<h3 style='color:{color};margin:0'>Confidentiality</h3>"
                    f"<p style='color:#aaa;margin:5px 0'>{len(conf)} events</p></div>",
                    unsafe_allow_html=True)
    with c2:
        integ = [a for a in all_actions if a.get("pillar") == "Integrity"]
        color = "#ffaa00" if integ else "#444"
        st.markdown(f"<div style='background:#111;border:1px solid {color};border-radius:8px;padding:15px;text-align:center'>"
                    f"<h3 style='color:{color};margin:0'>Integrity</h3>"
                    f"<p style='color:#aaa;margin:5px 0'>{len(integ)} events</p></div>",
                    unsafe_allow_html=True)
    with c3:
        avail = [a for a in all_actions if a.get("pillar") == "Availability"]
        color = "#00cc44" if avail else "#444"
        st.markdown(f"<div style='background:#111;border:1px solid {color};border-radius:8px;padding:15px;text-align:center'>"
                    f"<h3 style='color:{color};margin:0'>Availability</h3>"
                    f"<p style='color:#aaa;margin:5px 0'>{len(avail)} events</p></div>",
                    unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Action Log")

    status_colors = {"executed": "#00cc44", "pending_approval": "#ffaa00",
                     "flagged": "#4a9eff", "failed": "#ff2222"}
    pillar_colors = {"Confidentiality": "#ff4444", "Integrity": "#ffaa00", "Availability": "#00cc44"}

    for action in all_actions:
        sev_color = {"critical": "#ff2222", "high": "#ff8800", "medium": "#ffcc00"}.get(
            action.get("severity", "medium"), "#aaa")
        pil_color = pillar_colors.get(action.get("pillar", ""), "#aaa")
        stat_color = status_colors.get(action.get("status", ""), "#aaa")

        with st.expander(
            f"[{action.get('timestamp','')[:19]}]  "
            f"{action.get('pillar','')} — {action.get('action_type','').replace('_',' ').title()}  "
            f"[{action.get('status','').upper()}]"
        ):
            col_a, col_b = st.columns([2, 1])
            with col_a:
                st.markdown(f"**Agent:** `{action.get('agent','')}`")
                st.markdown(f"**Trigger:** {action.get('trigger','')}")
                st.markdown(f"**Action taken:** `{action.get('action_taken','')}`")
                st.markdown(f"**Reason:** {action.get('reason','')}")
            with col_b:
                st.markdown(f"<span style='color:{pil_color}'>**{action.get('pillar','')}**</span>",
                            unsafe_allow_html=True)
                st.markdown(f"<span style='color:{sev_color}'>Severity: {action.get('severity','').upper()}</span>",
                            unsafe_allow_html=True)
                st.markdown(f"<span style='color:{stat_color}'>Status: {action.get('status','').upper()}</span>",
                            unsafe_allow_html=True)
                approval = action.get("human_approval_required", False)
                st.markdown(f"Human approval: {'**Required**' if approval else 'Not required'}")

            if action.get("taara_advantage"):
                st.markdown("---")
                st.markdown(f"**Why standard tools missed this:**")
                st.info(action["taara_advantage"])

            # Approve button for pending actions
            if action.get("status") == "pending_approval" and platform and platform.connected:
                if st.button(f"Approve: Revert config on {platform.config.get('host','target')}",
                             key=f"approve_{action.get('timestamp','')}",
                             type="primary"):
                    if platform.platform_type == 'ssh':
                        out, err, rc = platform.execute_command(
                            "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config "
                            "&& systemctl reload ssh 2>/dev/null || service ssh reload 2>/dev/null"
                        )
                        if rc == 0:
                            st.success("Config reverted. SSH reloaded.")
                        else:
                            st.error(f"Revert failed: {err}")
                    else:
                        st.info("Config revert executed in simulation.")


def main():
    """Main application entry point."""
    init_session_state()

    if not st.session_state.authenticated:
        render_login()
    elif st.session_state.current_page == 'platform_select':
        render_platform_select()
    elif st.session_state.current_page == 'system_select':
        render_system_select()
    elif st.session_state.current_page == 'code_analysis':
        # Code Analysis standalone — no platform needed
        with st.sidebar:
            st.markdown("""
            <div style="text-align: center; padding: 15px 0; border-bottom: 1px solid #222;">
                <h2 style="color: #e94560; margin: 0; letter-spacing: 3px;">TAARA</h2>
                <p style="color: #666; margin: 0; font-size: 0.8em;">Prevent Crash, Preserve Cash</p>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("")
            if st.button("← Back to Home", use_container_width=True):
                st.session_state.current_page = 'platform_select'
                st.rerun()
            if st.button("🚪 Logout", use_container_width=True):
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
        _render_code_scan()
    elif st.session_state.current_page == 'platform_config':
        render_platform_config()
    elif st.session_state.current_page == 'main_app':
        render_main_app()
    else:
        render_login()


if __name__ == '__main__':
    main()
