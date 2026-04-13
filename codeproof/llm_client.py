"""
Codeproof LLM Client — standalone version.

Thin LLM routing layer: Anthropic API (direct) → OpenAI API (direct)
→ OpenRouter (fallback).  Uses direct API keys when available (cheaper,
no markup); falls back to OpenRouter for models not supported natively.

Requirements
------------
    pip install openai>=1 anthropic>=0.30  # anthropic optional but recommended

Environment variables
---------------------
    OPENROUTER_API_KEY   — required for OpenRouter fallback
    ANTHROPIC_API_KEY    — optional; enables direct Anthropic routing
    OPENAI_API_KEY       — optional; enables direct OpenAI routing

Public API
----------
    LLMClient.chat(messages, model, tools, reasoning_effort, max_tokens) -> (msg, usage)
    LLMClient.vision_query(prompt, images, model, max_tokens, reasoning_effort) -> (text, usage)
    LLMClient.default_model() -> str
    add_usage(total, usage) -> None
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

DEFAULT_MODEL = "anthropic/claude-sonnet-4-6"
DEFAULT_LIGHT_MODEL = "openai/gpt-4o-mini"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_reasoning_effort(value: str, default: str = "medium") -> str:
    allowed = {"none", "minimal", "low", "medium", "high", "xhigh"}
    v = str(value or "").strip().lower()
    return v if v in allowed else default


def add_usage(total: Dict[str, Any], usage: Dict[str, Any]) -> None:
    """Accumulate token/cost usage from one LLM call into a running total."""
    for k in (
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_tokens",
        "cache_write_tokens",
    ):
        total[k] = int(total.get(k) or 0) + int(usage.get(k) or 0)
    if usage.get("cost"):
        total["cost"] = float(total.get("cost") or 0) + float(usage["cost"])


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------


_anthropic_sdk_available: Optional[bool] = None
_anthropic_sdk_warned: bool = False


def _check_anthropic_sdk() -> bool:
    global _anthropic_sdk_available, _anthropic_sdk_warned
    if _anthropic_sdk_available is None:
        try:
            import anthropic  # noqa: F401
            _anthropic_sdk_available = True
        except ImportError:
            _anthropic_sdk_available = False
    if not _anthropic_sdk_available and not _anthropic_sdk_warned:
        log.warning(
            "anthropic SDK not installed — falling back to OpenRouter for "
            "anthropic/ models. Install with: pip install anthropic"
        )
        _anthropic_sdk_warned = True
    return bool(_anthropic_sdk_available)


class LLMClient:
    """
    Multi-provider LLM client.

    Routing priority:
      1. anthropic/* + ANTHROPIC_API_KEY → direct Anthropic SDK
      2. openai/*   + OPENAI_API_KEY     → direct OpenAI SDK
      3. anything else                   → OpenRouter (requires OPENROUTER_API_KEY)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://openrouter.ai/api/v1",
    ):
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._base_url = base_url
        self._client = None
        self._anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self._openai_key = os.environ.get("OPENAI_API_KEY", "")

    # ------------------------------------------------------------------
    # Internal: OpenRouter client
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self._base_url,
                api_key=self._api_key or "no-key",
            )
        return self._client

    # ------------------------------------------------------------------
    # Internal: Anthropic direct
    # ------------------------------------------------------------------

    def _chat_anthropic_direct(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: int = 16384,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        import anthropic

        raw_model = model[len("anthropic/"):]  # strip "anthropic/" prefix

        client = anthropic.Anthropic(api_key=self._anthropic_key)

        # Separate system message
        system_text = ""
        filtered: List[Dict[str, Any]] = []
        for m in messages:
            if m.get("role") == "system":
                system_text += (m.get("content") or "") + "\n"
            else:
                filtered.append(m)

        kwargs: Dict[str, Any] = {
            "model": raw_model,
            "max_tokens": max_tokens,
            "messages": filtered,
        }
        if system_text:
            kwargs["system"] = system_text.strip()
        if tools:
            anthropic_tools = []
            for t in tools:
                if t.get("type") == "function":
                    fn = t.get("function") or {}
                    anthropic_tools.append({
                        "name": fn.get("name", ""),
                        "description": fn.get("description", ""),
                        "input_schema": fn.get("parameters") or {},
                    })
            if anthropic_tools:
                kwargs["tools"] = anthropic_tools

        resp = client.messages.create(**kwargs)

        # Build OpenAI-compatible message dict
        tool_calls = []
        text_content = ""
        for block in resp.content:
            if block.type == "text":
                text_content += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "type": "function",
                    "function": {
                        "name": block.name,
                        "arguments": json.dumps(block.input),
                    },
                })

        msg: Dict[str, Any] = {
            "role": "assistant",
            "content": text_content or None,
        }
        if tool_calls:
            msg["tool_calls"] = tool_calls

        usage = {
            "prompt_tokens": resp.usage.input_tokens,
            "completion_tokens": resp.usage.output_tokens,
            "total_tokens": resp.usage.input_tokens + resp.usage.output_tokens,
            "cached_tokens": getattr(resp.usage, "cache_read_input_tokens", 0) or 0,
            "cache_write_tokens": getattr(resp.usage, "cache_creation_input_tokens", 0) or 0,
        }
        return msg, usage

    # ------------------------------------------------------------------
    # Internal: OpenAI direct
    # ------------------------------------------------------------------

    def _chat_openai_direct(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: int = 16384,
        reasoning_effort: str = "medium",
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        from openai import OpenAI

        raw_model = model[len("openai/"):]

        client = OpenAI(api_key=self._openai_key)

        kwargs: Dict[str, Any] = {
            "model": raw_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        is_reasoning = any(raw_model.startswith(p) for p in ("o1", "o3", "o4"))
        if is_reasoning:
            effort = normalize_reasoning_effort(reasoning_effort)
            if effort != "none":
                effort_map = {
                    "minimal": "low", "low": "low",
                    "medium": "medium",
                    "high": "high", "xhigh": "high",
                }
                kwargs["reasoning_effort"] = effort_map.get(effort, "medium")

        resp = client.chat.completions.create(**kwargs)
        resp_dict = resp.model_dump()

        usage = resp_dict.get("usage") or {}
        choices = resp_dict.get("choices") or [{}]
        msg = (choices[0] if choices else {}).get("message") or {}

        # Extract cached_tokens if available
        if not usage.get("cached_tokens"):
            prompt_details = usage.get("prompt_tokens_details") or {}
            if isinstance(prompt_details, dict) and prompt_details.get("cached_tokens"):
                usage["cached_tokens"] = int(prompt_details["cached_tokens"])

        return msg, usage

    # ------------------------------------------------------------------
    # Internal: cost fetch
    # ------------------------------------------------------------------

    def _fetch_generation_cost(self, gen_id: str) -> Optional[float]:
        """Try to fetch cost for a generation from OpenRouter's /generation endpoint."""
        try:
            import requests
            url = f"https://openrouter.ai/api/v1/generation?id={gen_id}"
            headers = {"Authorization": f"Bearer {self._api_key}"}
            r = requests.get(url, headers=headers, timeout=5)
            if r.ok:
                data = r.json()
                return data.get("data", {}).get("total_cost")
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: List[Dict[str, Any]],
        model: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        reasoning_effort: str = "medium",
        max_tokens: int = 16384,
        tool_choice: str = "auto",
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Send a single LLM request.

        Args:
            messages:         OpenAI-format message list.
            model:            Model ID e.g. "anthropic/claude-sonnet-4-6".
            tools:            OpenAI-format tool definitions (optional).
            reasoning_effort: "none" | "low" | "medium" | "high" | "xhigh".
            max_tokens:       Max response tokens.
            tool_choice:      "auto" | "required" | "none".

        Returns:
            (message_dict, usage_dict)
            message_dict — OpenAI-style: {"role": "assistant", "content": ...,
                                          "tool_calls": [...]}
            usage_dict   — token counts + optional "cost" in USD.
        """
        direct_forbidden = False

        # 1. Try Anthropic direct
        if model.startswith("anthropic/") and self._anthropic_key and _check_anthropic_sdk():
            try:
                return self._chat_anthropic_direct(
                    messages=messages,
                    model=model,
                    tools=tools,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                log.warning("Anthropic direct call failed, falling back to OpenRouter: %s", exc)
                err_str = str(exc)
                if "403" in err_str or "forbidden" in err_str.lower():
                    direct_forbidden = True

        # 2. Try OpenAI direct
        if model.startswith("openai/") and self._openai_key:
            try:
                return self._chat_openai_direct(
                    messages=messages,
                    model=model,
                    tools=tools,
                    max_tokens=max_tokens,
                    reasoning_effort=reasoning_effort,
                )
            except Exception as exc:
                log.warning("OpenAI direct call failed, falling back to OpenRouter: %s", exc)

        # 3. OpenRouter
        client = self._get_client()
        effort = normalize_reasoning_effort(reasoning_effort)

        extra_body: Dict[str, Any] = {}
        if not model.startswith("google/"):
            extra_body["reasoning"] = {"effort": effort, "exclude": True}

        if model.startswith("anthropic/") and not direct_forbidden:
            extra_body["provider"] = {
                "order": ["Anthropic"],
                "allow_fallbacks": False,
                "require_parameters": True,
            }

        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "extra_body": extra_body,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        resp = client.chat.completions.create(**kwargs)
        resp_dict = resp.model_dump()
        usage = resp_dict.get("usage") or {}
        choices = resp_dict.get("choices") or [{}]
        msg = (choices[0] if choices else {}).get("message") or {}

        # Extract cached/write tokens
        if not usage.get("cached_tokens"):
            pd = usage.get("prompt_tokens_details") or {}
            if isinstance(pd, dict) and pd.get("cached_tokens"):
                usage["cached_tokens"] = int(pd["cached_tokens"])

        if not usage.get("cache_write_tokens"):
            pd = usage.get("prompt_tokens_details") or {}
            if isinstance(pd, dict):
                cw = (
                    pd.get("cache_write_tokens")
                    or pd.get("cache_creation_tokens")
                    or pd.get("cache_creation_input_tokens")
                )
                if cw:
                    usage["cache_write_tokens"] = int(cw)

        if not usage.get("cost"):
            gen_id = resp_dict.get("id") or ""
            if gen_id:
                cost = self._fetch_generation_cost(gen_id)
                if cost is not None:
                    usage["cost"] = cost

        return msg, usage

    def vision_query(
        self,
        prompt: str,
        images: List[Dict[str, Any]],
        model: str = "anthropic/claude-sonnet-4-6",
        max_tokens: int = 1024,
        reasoning_effort: str = "low",
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Send a vision query to a multimodal LLM.

        Args:
            prompt:  Text instruction.
            images:  List of image dicts:
                       {"url": "https://..."}
                       {"base64": "<b64>", "mime": "image/png"}
            model:   VLM-capable model ID.

        Returns:
            (text_response, usage_dict)
        """
        content: List[Dict[str, Any]] = [{"type": "text", "text": prompt}]
        for img in images:
            if "url" in img:
                content.append({"type": "image_url", "image_url": {"url": img["url"]}})
            elif "base64" in img:
                mime = img.get("mime", "image/png")
                content.append({
                    "type": "image_url",
                    "image_url": {"url": f"data:{mime};base64,{img['base64']}"},
                })

        messages = [{"role": "user", "content": content}]
        response_msg, usage = self.chat(
            messages=messages,
            model=model,
            tools=None,
            reasoning_effort=reasoning_effort,
            max_tokens=max_tokens,
        )
        return response_msg.get("content") or "", usage

    def default_model(self) -> str:
        """Return the default model ID (from env or hardcoded fallback)."""
        return os.environ.get("CODEPROOF_MODEL", DEFAULT_MODEL)
