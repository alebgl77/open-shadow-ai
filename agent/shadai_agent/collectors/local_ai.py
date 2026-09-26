"""Local AI runtime detector."""

from __future__ import annotations

from pathlib import Path

KNOWN_AI_PROCESSES = {
    "ollama",
    "ollama-runner",
    "llama-server",
    "llama-cli",
    "llama.cpp",
    "lm-studio",
    "lms",
    "jan",
    "gpt4all",
    "localai",
    "local-ai",
    "vllm",
    "koboldcpp",
    "llamafile",
    "text-generation",
    "anything-llm",
    "tgi",
}

KNOWN_AI_PORTS = {11434, 8080, 5000, 1234, 8000, 5001, 7860, 3001, 1337}

MODEL_EXTENSIONS = {".gguf", ".ggml", ".safetensors"}

MODEL_SEARCH_PATHS = [
    "~/.ollama/models",
    "~/lm-studio/models",
    "~/.cache/gpt4all",
    "~/.cache/huggingface/hub",
    "~/jan/models",
]


def detect_local_ai(processes: list[dict]) -> list[dict]:
    """Check running processes against known AI tools."""
    hits = []
    for proc in processes:
        name = (proc.get("name") or "").lower().removesuffix(".exe")
        port = proc.get("listening_port", 0)

        matched = False
        reason = ""

        if name in KNOWN_AI_PROCESSES:
            matched = True
            reason = f"Known AI process: {name}"

        if port in KNOWN_AI_PORTS and not matched:
            matched = True
            reason = f"Known AI port: {port}"

        if matched:
            hits.append(
                {
                    "process_name": proc.get("name", ""),
                    "port": port,
                    "tool_name": name,
                    "reason": reason,
                    "pid": proc.get("pid", 0),
                    "username": proc.get("username", ""),
                }
            )
    return hits


def detect_model_files() -> list[dict]:
    """Scan common paths for AI model files."""
    files = []
    for search_path in MODEL_SEARCH_PATHS:
        path = Path(search_path).expanduser()
        if not path.exists():
            continue
        try:
            for f in path.rglob("*"):
                if f.suffix in MODEL_EXTENSIONS and f.is_file():
                    files.append(
                        {
                            "path": str(f),
                            "size_mb": round(f.stat().st_size / 1_048_576, 1),
                            "name": f.name,
                        }
                    )
        except PermissionError:
            continue
    return files
