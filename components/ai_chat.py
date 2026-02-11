"""
AI Chat Interface
==================

AI-powered chat for security analysis with executable command support.
Uses Gemini LLM with TAARA context awareness.

Features:
- Security Q&A with TAARA context
- Generates executable commands (shell, AWS CLI, etc.)
- Sidebar shows pending/executed commands
- Approval flow: AI suggests -> user approves -> execute -> show result
- On failure: result sent back to AI for troubleshooting
"""

import streamlit as st
import time
import re
from typing import Dict, List, Optional
from datetime import datetime


def render_ai_chat(llm_service, platform=None, taara_analyzer=None):
    """Render the AI Chat interface with command execution support."""

    st.markdown("""
    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #1a2e1a 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 20px;
                border: 1px solid #44aa44;">
        <h1 style="color: #44aa44; margin: 0; font-size: 2.2em;">
            TAARA AI Assistant
        </h1>
        <p style="color: #a0a0b0; margin: 5px 0 0 0; font-size: 1.1em;">
            Quantum-Enhanced Security Intelligence — With Command Execution
        </p>
    </div>
    """, unsafe_allow_html=True)

    if not llm_service:
        st.warning("LLM service not configured. Please set your API key at login.")
        return

    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'pending_commands' not in st.session_state:
        st.session_state.pending_commands = []
    if 'executed_commands' not in st.session_state:
        st.session_state.executed_commands = []

    # --- Sidebar: Command Queue ---
    with st.sidebar:
        st.markdown("---")
        st.markdown("### Command Queue")

        pending = st.session_state.pending_commands
        executed = st.session_state.executed_commands

        if pending:
            st.markdown(f"**Pending Approval:** {len(pending)}")
            for i, cmd in enumerate(pending):
                with st.expander(f"{'[' + cmd.get('language', 'shell') + ']'} {cmd['code'][:50]}...", expanded=False):
                    st.code(cmd['code'], language=cmd.get('language', 'bash'))
                    st.caption(f"Source: AI suggestion at {cmd.get('time', '')}")
                    col_a, col_r = st.columns(2)
                    with col_a:
                        if st.button("Approve", key=f"approve_cmd_{i}", type="primary", use_container_width=True):
                            result = _execute_command(cmd, platform)
                            cmd['status'] = 'success' if result['success'] else 'failed'
                            cmd['result'] = result
                            st.session_state.executed_commands.append(cmd)
                            st.session_state.pending_commands.pop(i)

                            if not result['success']:
                                _send_failure_to_ai(cmd, result, llm_service, platform, taara_analyzer)

                            st.rerun()
                    with col_r:
                        if st.button("Reject", key=f"reject_cmd_{i}", use_container_width=True):
                            cmd['status'] = 'rejected'
                            st.session_state.executed_commands.append(cmd)
                            st.session_state.pending_commands.pop(i)
                            st.rerun()
        else:
            st.caption("No pending commands")

        if executed:
            st.markdown(f"**Executed:** {len(executed)}")
            for i, cmd in enumerate(executed[-10:][::-1]):
                status = cmd.get('status', 'unknown')
                if status == 'success':
                    icon = '✅'
                elif status == 'failed':
                    icon = '❌'
                elif status == 'rejected':
                    icon = '🚫'
                else:
                    icon = '⏳'

                with st.expander(f"{icon} {cmd['code'][:40]}...", expanded=False):
                    st.code(cmd['code'], language=cmd.get('language', 'bash'))
                    if cmd.get('result'):
                        res = cmd['result']
                        if res.get('stdout'):
                            st.text_area("Output", res['stdout'][:2000], height=100,
                                        key=f"exec_out_{i}_{cmd.get('time', i)}")
                        if res.get('stderr'):
                            st.text_area("Errors", res['stderr'][:2000], height=80,
                                        key=f"exec_err_{i}_{cmd.get('time', i)}")
                        if res.get('success'):
                            st.success("Executed successfully")
                        else:
                            st.error(f"Failed: {res.get('error', 'Unknown error')}")

        if st.button("Clear Command History", key="clear_cmd_hist"):
            st.session_state.pending_commands = []
            st.session_state.executed_commands = []
            st.rerun()

        if st.button("Clear Chat", key="clear_chat"):
            st.session_state.chat_history = []
            st.rerun()

        st.markdown("---")
        st.markdown("**Quick Questions:**")
        quick_qs = [
            "Scan for vulnerabilities and suggest fixes",
            "What security issues should I fix first?",
            "How can I harden SSH on this server?",
            "Show me commands to check for rootkits",
        ]
        for q in quick_qs:
            if st.button(q, key=f"qq_{hash(q)}"):
                st.session_state.chat_history.append({'role': 'user', 'content': q})
                st.rerun()

    # --- Main Chat Area ---
    for msg in st.session_state.chat_history:
        role = msg['role']
        with st.chat_message(role):
            st.markdown(msg['content'])

            if role == 'assistant' and msg.get('commands'):
                for j, cmd in enumerate(msg['commands']):
                    with st.expander(f"Command: {cmd['code'][:60]}...", expanded=True):
                        st.code(cmd['code'], language=cmd.get('language', 'bash'))
                        if st.button(f"Add to Queue", key=f"queue_{msg.get('ts', 0)}_{j}",
                                    use_container_width=True):
                            cmd['time'] = datetime.now().strftime('%H:%M:%S')
                            cmd['source'] = 'ai_chat'
                            st.session_state.pending_commands.append(cmd)
                            st.rerun()

    user_input = st.chat_input("Ask TAARA about security, or request commands for your systems...")

    if user_input:
        st.session_state.chat_history.append({'role': 'user', 'content': user_input})
        with st.chat_message('user'):
            st.markdown(user_input)

        context = _build_context(platform, taara_analyzer)
        recent_executed = st.session_state.executed_commands[-5:] if st.session_state.executed_commands else []
        exec_context = ""
        if recent_executed:
            exec_context = "\n\nRecently executed commands and their results:\n"
            for ec in recent_executed:
                status = ec.get('status', 'unknown')
                output = ec.get('result', {}).get('stdout', '')[:500]
                errors = ec.get('result', {}).get('stderr', '')[:300]
                exec_context += f"  Command: {ec['code'][:100]}\n  Status: {status}\n"
                if output:
                    exec_context += f"  Output: {output}\n"
                if errors:
                    exec_context += f"  Errors: {errors}\n"
                exec_context += "\n"

        platform_type = platform.platform_type if platform else 'unknown'

        system_prompt = f"""You are TAARA AI Assistant — a quantum-enhanced security analysis system.

You help admins secure their infrastructure by:
1. Explaining security findings and vulnerabilities
2. Generating EXECUTABLE commands to fix issues or gather more info
3. Recommending remediation steps with actual implementation commands
4. Explaining TAARA's quantum validation methodology
5. Helping with cloud cost optimization (Preserve Cash)

IMPORTANT: When the user asks for fixes, scans, hardening, or any actionable security task:
- Provide commands in markdown code blocks with the language specified
- For shell commands: ```bash
- For AWS CLI: ```bash
- For Python scripts: ```python
- For kubectl: ```bash
- The commands will be extracted and shown to the user for approval before execution

Currently connected platform: {platform_type}
{context}
{exec_context}

Tagline: "Prevent Crash, Preserve Cash"

Be concise, actionable, and security-focused. When giving commands, make them safe and
idempotent where possible. Always explain what each command does.

If a command previously failed, analyze the error and suggest corrective commands.
"""

        full_prompt = f"{system_prompt}\n\nUser: {user_input}"

        with st.chat_message('assistant'):
            with st.spinner("Analyzing..."):
                response = llm_service.generate_response(full_prompt)
                if response.get('success'):
                    answer = response.get('explanation', 'I could not generate a response.')
                    commands = response.get('commands', [])
                else:
                    answer = f"Error: {response.get('error', 'Unknown error')}"
                    commands = []

                st.markdown(answer)

                if commands:
                    st.markdown("---")
                    st.markdown("**Suggested Commands:**")
                    for j, cmd in enumerate(commands):
                        with st.expander(f"Command: {cmd['code'][:60]}...", expanded=True):
                            st.code(cmd['code'], language=cmd.get('language', 'bash'))
                            if st.button(f"Add to Approval Queue", key=f"new_queue_{time.time()}_{j}",
                                        use_container_width=True):
                                cmd['time'] = datetime.now().strftime('%H:%M:%S')
                                cmd['source'] = 'ai_chat'
                                st.session_state.pending_commands.append(cmd)
                                st.rerun()

                ts = time.time()
                st.session_state.chat_history.append({
                    'role': 'assistant',
                    'content': answer,
                    'commands': commands,
                    'ts': ts
                })


def _execute_command(cmd: Dict, platform) -> Dict:
    """Execute a command on the connected platform."""
    result = {'success': False, 'stdout': '', 'stderr': '', 'error': ''}

    code = cmd.get('code', '')
    language = cmd.get('language', 'shell')

    if not platform or not platform.connected:
        result['error'] = 'No platform connected'
        return result

    try:
        if platform.platform_type == 'ssh':
            if language in ['bash', 'shell', 'sh']:
                stdout, stderr, exit_code = platform.execute_command(code)
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['exit_code'] = exit_code
                result['success'] = (exit_code == 0)
                if exit_code != 0 and not result['error']:
                    result['error'] = f'Exit code: {exit_code}'
            elif language == 'python':
                escaped = code.replace("'", "'\\''")
                stdout, stderr, exit_code = platform.execute_command(
                    f"python3 -c '{escaped}'"
                )
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['exit_code'] = exit_code
                result['success'] = (exit_code == 0)
            else:
                stdout, stderr, exit_code = platform.execute_command(code)
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['exit_code'] = exit_code
                result['success'] = (exit_code == 0)

        elif platform.platform_type in ['aws', 'gcp', 'azure']:
            result['error'] = (
                f'Direct command execution on {platform.platform_type} requires CLI. '
                f'Commands are shown for manual execution or SSH into instances.'
            )
            result['stdout'] = f'[{platform.platform_type.upper()}] Command staged for reference:\n{code}'
            result['success'] = True

        elif platform.platform_type == 'docker':
            result['error'] = 'Docker command execution: use docker exec on specific containers'
            result['stdout'] = f'[Docker] Command staged:\n{code}'
            result['success'] = True

        elif platform.platform_type == 'kubernetes':
            result['error'] = 'Kubernetes commands: use kubectl from your terminal'
            result['stdout'] = f'[K8s] Command staged:\n{code}'
            result['success'] = True

    except Exception as e:
        result['error'] = str(e)

    if st.session_state.get('action_logger'):
        st.session_state.action_logger.log(
            'ai_chat', 'command_execute',
            f'{"Success" if result["success"] else "Failed"}: {code[:100]}',
            severity='info' if result['success'] else 'warning',
            metadata={'command': code[:500], 'result': result.get('stdout', '')[:500]}
        )

    return result


def _send_failure_to_ai(cmd: Dict, result: Dict, llm_service, platform, taara_analyzer):
    """Send failed command result back to AI for troubleshooting."""
    failure_msg = (
        f"The following command failed:\n```{cmd.get('language', 'bash')}\n{cmd['code']}\n```\n\n"
        f"Exit code: {result.get('exit_code', 'N/A')}\n"
        f"Stdout: {result.get('stdout', '')[:1000]}\n"
        f"Stderr: {result.get('stderr', '')[:1000]}\n"
        f"Error: {result.get('error', '')}\n\n"
        f"Please analyze the error and suggest corrective commands."
    )

    st.session_state.chat_history.append({'role': 'user', 'content': failure_msg})

    context = _build_context(platform, taara_analyzer)
    platform_type = platform.platform_type if platform else 'unknown'

    prompt = f"""You are TAARA AI Assistant. A command that was executed on {platform_type} has failed.
Analyze the error and provide corrective commands.

{context}

{failure_msg}

Provide:
1. Analysis of what went wrong
2. Corrective commands in code blocks
3. Any preventive measures
"""

    response = llm_service.generate_response(prompt)
    if response.get('success'):
        answer = response.get('explanation', 'Could not analyze the failure.')
        commands = response.get('commands', [])
    else:
        answer = f"Could not analyze failure: {response.get('error', '')}"
        commands = []

    st.session_state.chat_history.append({
        'role': 'assistant',
        'content': answer,
        'commands': commands,
        'ts': time.time()
    })


def _build_context(platform, taara_analyzer) -> str:
    """Build context string from current system state."""
    parts = []

    if platform and platform.connected:
        info = platform.get_platform_info()
        parts.append(f"Connected platform: {info.get('type', 'unknown').upper()}")
        if 'host' in info:
            parts.append(f"Host: {info['host']}")

    if taara_analyzer:
        summary = taara_analyzer.get_detection_summary()
        parts.append(f"Total analyses: {summary.get('total_windows', 0)}")
        parts.append(f"Novelties detected: {summary.get('taara_novelty', 0)}")
        parts.append(f"Quantum confirmed: {summary.get('quantum_confirmed', 0)}")
        parts.append(f"Identities tracked: {summary.get('identities_tracked', 0)}")

    return "\n".join(parts) if parts else "No active analysis session."
