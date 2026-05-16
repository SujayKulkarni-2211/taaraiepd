import re
from typing import Dict, List, Any, Optional
from groq import Groq


class LLMService:
    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"

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

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024,
            )

            text = response.choices[0].message.content.strip()

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
