import google.generativeai as genai
import re
from typing import Dict, List, Any, Optional

class LLMService:
    """
    Unified LLM service using Gemini API.
    Abstracted from frontend to hide implementation details.
    """
    
    def __init__(self, api_key: str):
        """Initialize with API key stored securely."""
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        self.conversation_history = []
    
    def parse_markdown_code(self, markdown_text: str) -> List[Dict[str, str]]:
        """
        Extract executable code from markdown responses.
        Handles markdown code blocks: ```language ... ```
        """
        code_blocks = []
        pattern = r'```(\w+)?\n(.*?)```'
        matches = re.finditer(pattern, markdown_text, re.DOTALL)
        
        for match in matches:
            language = match.group(1) or 'shell'
            code = match.group(2).strip()
            code_blocks.append({
                'language': language,
                'code': code
            })
        
        # Also extract plain bash commands (lines starting with $)
        bash_pattern = r'^\$\s+(.+)$'
        bash_matches = re.finditer(bash_pattern, markdown_text, re.MULTILINE)
        
        for match in bash_matches:
            bash_code = match.group(1)
            if bash_code not in [b['code'] for b in code_blocks]:
                code_blocks.append({
                    'language': 'shell',
                    'code': bash_code
                })
        
        return code_blocks
    
    def generate_response(self, prompt: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate reasoning about threat, actions, or deployments.
        Automatically extracts executable commands from response.
        """
        try:
            # Add context if available
            full_prompt = prompt
            if context:
                if context.get('dna_drift'):
                    full_prompt += f"\n\nSystem DNA Drift: {context['dna_drift']}"
                if context.get('alerts'):
                    full_prompt += f"\n\nActive Alerts: {context['alerts']}"
                if context.get('server_metrics'):
                    full_prompt += f"\n\nServer Metrics: {context['server_metrics']}"

            # Call Gemini API with chat context
            chat = self.model.start_chat(history=[
                {"role": msg["role"], "parts": [msg["content"]]}
                for msg in self.conversation_history
            ])

            response = chat.send_message(full_prompt)
            response_text = response.text

            # Add to conversation history
            self.conversation_history.append({"role": "user", "content": full_prompt})
            self.conversation_history.append({"role": "model", "content": response_text})

            # Extract executable code
            code_blocks = self.parse_markdown_code(response_text)

            # Extract explanation (text before first code block)
            explanation = response_text
            for block in code_blocks:
                pattern = re.escape(f"```{block.get('language', '')}") + r"\n.*?```"
                explanation = re.sub(pattern, "", explanation, flags=re.DOTALL)
            explanation = explanation.strip()

            return {
                "success": True,
                "explanation": explanation,
                "commands": code_blocks,
                "raw_response": response_text
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "explanation": f"Service temporarily unavailable: {str(e)}",
                "commands": []
            }
    
    def analyze_threat(self, dna_drift: Dict, alerts: List[Dict], metrics: Dict) -> Dict[str, Any]:
        """Analyze threat using all available signals."""
        context = {
            'dna_drift': dna_drift,
            'alerts': alerts,
            'server_metrics': metrics
        }
        
        prompt = f"""
        Analyze this security incident:
        - System DNA drift: {dna_drift.get('drift_magnitude', 0)*100:.1f}% change
        - Similarity score: {dna_drift.get('similarity_score', 0)*100:.1f}%
        - Active alerts: {len(alerts)} detected
        
        Provide:
        1. Likely root causes (ranked by probability)
        2. Immediate recommended actions
        3. Investigation commands
        4. Prevention steps
        """
        
        return self.generate_response(prompt, context)
    
    def propose_deployment(self, service: str, current_version: str, new_version: str, 
                          deployment_type: str = "rolling") -> Dict[str, Any]:
        """Propose deployment commands with rollback."""
        prompt = f"""
        Propose a {deployment_type} deployment:
        - Service: {service}
        - Current version: {current_version}
        - Target version: {new_version}
        
        Provide:
        1. Pre-deployment checks
        2. Deployment commands
        3. Health check commands
        4. Rollback commands (if needed)
        5. Estimated risk level
        """
        
        return self.generate_response(prompt)
    
    def propose_security_action(self, action_type: str, target: str, severity: str) -> Dict[str, Any]:
        """Propose security remediation actions."""
        prompt = f"""
        Propose immediate action:
        - Action: {action_type}
        - Target: {target}
        - Severity: {severity}
        
        Provide:
        1. Isolation commands (if applicable)
        2. Investigation commands
        3. Remediation steps
        4. Recovery commands
        5. Risk assessment
        """
        
        return self.generate_response(prompt)
    
    def chat_query(self, user_query: str) -> Dict[str, Any]:
        """Handle general chat queries."""
        return self.generate_response(user_query)
