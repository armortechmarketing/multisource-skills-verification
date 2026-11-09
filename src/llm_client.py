import os
import json
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Tuple


def call_llm_json_with_meta(
    prompt: str = "",
    system_prompt: Optional[str] = None,
    model: str = "",
    timeout: int = 40,
    temperature: float = 0.0,
    api_key: Optional[str] = None,
    user_prompt: str = "",
    **kwargs: Any,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Unified LLM caller supporting both Google Gemini (GEMINI_API_KEY) and OpenAI (OPENAI_API_KEY).
    Returns (parsed_json_dict_or_None, telemetry_meta).
    telemetry_meta schema:
    {
        "mode": "llm" | "deterministic" | "llm_failed_fallback",
        "model": str or None,
        "latency_ms": int,
        "input_tokens": int or None,
        "output_tokens": int or None,
        "fallback_reason": str or None,
    }
    """
    effective_prompt = prompt or user_prompt or ""
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    openai_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip()

    target_model = model or "gpt-4o-mini"

    if not gemini_key and not openai_key:
        return None, {
            "mode": "deterministic",
            "model": None,
            "latency_ms": 0,
            "input_tokens": None,
            "output_tokens": None,
            "fallback_reason": "No API key configured (neither OPENAI_API_KEY nor GEMINI_API_KEY)",
        }

    t0 = time.perf_counter()

    # Priority 1: OpenAI if openai_key is present
    if openai_key:
        target_model = model if model else "gpt-4o-mini"
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json",
            }
            sys_content = system_prompt if system_prompt else "You are a helpful assistant."
            if "json" not in sys_content.lower() and "json" not in effective_prompt.lower():
                sys_content += " You must respond with valid JSON."
            messages = [
                {"role": "system", "content": sys_content},
                {"role": "user", "content": effective_prompt},
            ]
            payload = {
                "model": target_model,
                "messages": messages,
                "response_format": {"type": "json_object"},
                "temperature": float(temperature),
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8"))
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)

                t1 = time.perf_counter()
                latency_ms = int((t1 - t0) * 1000)

                usage = data.get("usage") or {}
                in_tok = usage.get("prompt_tokens")
                out_tok = usage.get("completion_tokens")

                return parsed, {
                    "mode": "llm",
                    "model": target_model,
                    "latency_ms": latency_ms,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "fallback_reason": None,
                }
        except Exception as exc:
            t1 = time.perf_counter()
            latency_ms = int((t1 - t0) * 1000)
            err_msg = str(exc)
            if hasattr(exc, "read"):
                try:
                    err_msg += f" - {exc.read().decode('utf-8', errors='replace')}"
                except Exception:
                    pass
            return None, {
                "mode": "llm_failed_fallback",
                "model": target_model,
                "latency_ms": latency_ms,
                "input_tokens": None,
                "output_tokens": None,
                "fallback_reason": f"OpenAI API request failed: {err_msg}",
            }

    # Priority 2: Gemini
    if gemini_key:
        target_model = model if model else "gemini-flash-latest"
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={gemini_key}"
            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": effective_prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": float(temperature),
                },
            }
            if system_prompt:
                payload["systemInstruction"] = {
                    "parts": [{"text": system_prompt}]
                }

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)

                t1 = time.perf_counter()
                latency_ms = int((t1 - t0) * 1000)

                usage = data.get("usageMetadata") or {}
                in_tok = usage.get("promptTokenCount")
                out_tok = usage.get("candidatesTokenCount")

                return parsed, {
                    "mode": "llm",
                    "model": target_model,
                    "latency_ms": latency_ms,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "fallback_reason": None,
                }
        except Exception as exc:
            t1 = time.perf_counter()
            latency_ms = int((t1 - t0) * 1000)
            return None, {
                "mode": "llm_failed_fallback",
                "model": target_model,
                "latency_ms": latency_ms,
                "input_tokens": None,
                "output_tokens": None,
                "fallback_reason": f"Gemini API request failed: {exc}",
            }

    return None, {
        "mode": "deterministic",
        "model": None,
        "latency_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "fallback_reason": "No usable API key found",
    }


def call_llm_json(
    prompt: str = "",
    system_prompt: Optional[str] = None,
    model: str = "",
    timeout: int = 40,
    temperature: float = 0.0,
    api_key: Optional[str] = None,
    user_prompt: str = "",
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """
    Unified LLM caller returning parsed JSON dict or None on failure.
    Maintains backward compatibility with all caller signatures.
    """
    res, _ = call_llm_json_with_meta(
        prompt=prompt,
        system_prompt=system_prompt,
        model=model,
        timeout=timeout,
        temperature=temperature,
        api_key=api_key,
        user_prompt=user_prompt,
        **kwargs,
    )
    return res
