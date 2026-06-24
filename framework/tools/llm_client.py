import os
import json
from typing import Optional
from openai import OpenAI


class LLMClient:
    def __init__(
        self,
        model: str = "gpt-4o",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is not set. "
                "Create a .env file or set it in your shell."
            )
        self.client = OpenAI(api_key=api_key, timeout=timeout)
        self.model = os.getenv("OPENAI_MODEL", model)
        self.temperature = temperature
        self.max_tokens = max_tokens

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        output_json: bool = False,
    ) -> str:
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if output_json:
            kwargs["response_format"] = {"type": "json_object"}

        resp = self.client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = self.chat(system_prompt, user_prompt, output_json=True)
        return json.loads(raw)
