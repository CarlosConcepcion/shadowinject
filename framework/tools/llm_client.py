import os
import json
from typing import Optional


class LLMClient:
    def __init__(
        self,
        provider: str = "gemini",
        model: str = "gemini-2.5-flash",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

        if self.provider == "openai":
            self._init_openai()
        elif self.provider == "gemini":
            self._init_gemini()
        else:
            raise ValueError(f"Unsupported provider: {provider}. Use 'openai' or 'gemini'.")

    def _init_openai(self):
        from openai import OpenAI
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not set. Add to .env file."
            )
        self._client = OpenAI(api_key=api_key, timeout=self.timeout)

    def _init_gemini(self):
        from google import genai
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not set. Add to .env file.\n"
                "Get a free key at: https://aistudio.google.com/apikey"
            )
        self._client = genai.Client(api_key=api_key)

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        output_json: bool = False,
    ) -> str:
        if self.provider == "openai":
            return self._chat_openai(system_prompt, user_prompt, output_json)
        return self._chat_gemini(system_prompt, user_prompt, output_json)

    def _chat_openai(self, system_prompt: str, user_prompt: str, output_json: bool) -> str:
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
        resp = self._client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    def _chat_gemini(self, system_prompt: str, user_prompt: str, output_json: bool) -> str:
        contents = f"{system_prompt}\n\n{user_prompt}"
        if output_json:
            contents += "\n\nRespond with valid JSON only."
        try:
            resp = self._client.models.generate_content(
                model=self.model,
                contents=contents,
            )
            return resp.text or ""
        except Exception as e:
            err = str(e)
            if "limit: 0" in err or "RESOURCE_EXHAUSTED" in err:
                raise RuntimeError(
                    f"Gemini API quota exhausted (model: {self.model}).\n"
                    "Fix: enable billing at https://aistudio.google.com or try a different model.\n"
                    "Edit config.yaml → llm.model"
                ) from e
            if "not found" in err.lower() or "not supported" in err.lower() or "deprecated" in err.lower():
                raise RuntimeError(
                    f"Model '{self.model}' may be deprecated or unavailable.\n"
                    "Try: gemini-2.5-flash, gemini-2.5-pro, or edit config.yaml"
                ) from e
            raise

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = self.chat(system_prompt, user_prompt, output_json=True)
        return json.loads(raw)
