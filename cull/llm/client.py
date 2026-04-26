from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .prompts import SYSTEM_PROMPT
from .schema import Verdict, validate_verdict


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class OpenAICompatClient:
    def __init__(self, *, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def classify(self, user_prompt: str) -> tuple[Verdict, Usage]:
        last_error: Exception | None = None
        prompt = user_prompt

        for attempt in range(5):
            try:
                data = self._post(prompt)
                verdict = validate_verdict(_message_json(data))
                return verdict, _usage(data)
            except ValueError as error:
                last_error = error
                if attempt >= 1:
                    break
                prompt = f"{user_prompt}\n\nYour previous response was invalid: {error}. Return only the JSON object."
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in {429, 500, 502, 503, 504} or attempt == 4:
                    break
                time.sleep(2**attempt)
            except (OSError, json.JSONDecodeError) as error:
                last_error = error
                if attempt == 4:
                    break
                time.sleep(2**attempt)

        raise RuntimeError(str(last_error or "LLM request failed"))

    def _post(self, user_prompt: str) -> dict[str, object]:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("LLM response was not an object")
        return data


def _message_json(data: dict[str, object]) -> object:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM response missing choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError("LLM choice was not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM choice missing message")
    content = message.get("content")
    if not isinstance(content, str):
        raise ValueError("LLM message content was not text")
    return json.loads(content)


def _usage(data: dict[str, object]) -> Usage:
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return Usage(0, 0)

    prompt = _int(usage.get("prompt_tokens") or usage.get("input_tokens"))
    completion = _int(usage.get("completion_tokens") or usage.get("output_tokens"))
    cache_read = _int(usage.get("cache_read_input_tokens") or usage.get("cached_tokens"))
    cache_write = _int(usage.get("cache_creation_input_tokens"))
    return Usage(prompt, completion, cache_read, cache_write)


def _int(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) else 0
