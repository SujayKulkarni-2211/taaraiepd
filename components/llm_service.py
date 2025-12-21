import re
from typing import Dict, List, Any, Optional
from google import genai


class LLMService:
    """
    Unified LLM service using Google GenAI SDK.
    Uses ONLY models confirmed via list_models().
    """

    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)

        # ✅ THIS IS THE KEY FIX
        self.model = "models/gemini-3-flash-preview"

    def parse_markdown_code(self, text: str):
        blocks = []
        for m in re.finditer(r"```(\w+)?\n(.*?)```", text, re.DOTALL):
            blocks.append({
                "language": m.group(1) or "shell",
                "code": m.group(2).strip()
            })
        return blocks

    def generate_response(self, prompt: str, context: Optional[Dict] = None):
        try:
            if context:
                prompt += f"\n\nContext:\n{context}"

            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )

            text = response.text.strip()

            return {
                "success": True,
                "explanation": text,
                "commands": self.parse_markdown_code(text),
                "raw_response": text
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "explanation": "LLM unavailable",
                "commands": []
            }

    def chat_query(self, user_query: str):
        return self.generate_response(user_query)
