import os
import json


class LLMClient:
    def __init__(
        self,
        provider: str = "groq",
        model: str = "llama-3.3-70b-versatile",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

        init_map = {
            "openai": self._init_openai,
            "groq": self._init_groq,
            "gemini": self._init_gemini,
        }
        init_fn = init_map.get(self.provider)
        if not init_fn:
            raise ValueError(
                f"Unsupported provider: {provider}. Options: openai, groq, gemini"
            )
        init_fn()

    def _init_openai(self):
        from openai import OpenAI
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set in .env file.")
        self._client = OpenAI(api_key=api_key, timeout=self.timeout)

    def _init_groq(self):
        from openai import OpenAI
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError(
                "GROQ_API_KEY not set in .env file.\n"
                "Get a free key at: https://console.groq.com (no credit card needed)"
            )
        self._client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=self.timeout,
        )

    def _init_gemini(self):
        from google import genai
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not set in .env file.\n"
                "Get a free key at: https://aistudio.google.com/apikey"
            )
        self._client = genai.Client(api_key=api_key)

    def chat(self, system_prompt: str, user_prompt: str, output_json: bool = False) -> str:
        chat_map = {
            "openai": self._chat_openai,
            "groq": self._chat_openai,
        }
        fn = chat_map.get(self.provider, self._chat_gemini)
        return fn(system_prompt, user_prompt, output_json)

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
        try:
            resp = self._client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content or ""
        except Exception as e:
            if output_json and ("json_validate_failed" in str(e) or "json" in str(e).lower()):
                kwargs.pop("response_format", None)
                kwargs["max_tokens"] = min(self.max_tokens * 2, 8192)
                resp = self._client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""
            raise

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
                    "Fix: enable billing at https://aistudio.google.com or switch to groq.\n"
                    "Edit config.yaml → llm.provider = groq"
                ) from e
            if any(x in err.lower() for x in ("not found", "not supported", "deprecated")):
                raise RuntimeError(
                    f"Model '{self.model}' may be deprecated or unavailable.\n"
                    "Try: gemini-2.5-flash, gemini-2.5-pro, or edit config.yaml"
                ) from e
            raise

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = self.chat(system_prompt, user_prompt, output_json=True)
        return json.loads(raw)
