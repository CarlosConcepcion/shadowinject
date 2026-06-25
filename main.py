#!/usr/bin/env python3
"""
ShadowInject - Exploit Generation Framework

Usage:
    python main.py --target 192.168.1.50
    python main.py --target 192.168.1.50 --config config/custom.yaml --verbose
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
    from dotenv import load_dotenv
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)


def load_config(path: str = "config/config.yaml") -> dict:
    path = Path(path).resolve()
    if not path.exists():
        print(f"[ERROR] Config file not found: {path}")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="ShadowInject - Exploit Generation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target 192.168.1.50\n"
            "  python main.py --target 10.0.0.5 --config config/custom.yaml --verbose\n"
        ),
    )
    parser.add_argument(
        "--target",
        help="Target IP address (e.g. 192.168.1.50)",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output for debugging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ShadowInject 1.0.0",
    )
    parser.add_argument(
        "--list-payloads",
        action="store_true",
        help="List available payload reference categories from PayloadsAllTheThings",
    )

    args = parser.parse_args()

    if args.list_payloads:
        from framework.tools.payload_reference import reference
        if not reference.is_available():
            print("[ERROR] PayloadsAllTheThings not found (cloned to payloads_reference/).")
            sys.exit(1)
        cats = reference.list_categories()
        print(f"Available payload categories ({len(cats)}):\n")
        for c in cats:
            print(f"  - {c}")
        sys.exit(0)

    if not args.target:
        parser.error("--target is required (use --list-payloads to see available payloads)")

    config = load_config(args.config)
    config.setdefault("agents", {})

    provider = config.get("llm", {}).get("provider", "groq")
    key_var = {"openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY"}
    var_name = key_var.get(provider)
    if var_name and not os.getenv(var_name):
        urls = {
            "openai": "https://platform.openai.com/api-keys",
            "groq": "https://console.groq.com (no credit card needed)",
            "gemini": "https://aistudio.google.com/apikey",
        }
        print(f"[ERROR] {var_name} not set. Add to .env file.")
        print(f"Get a free key at: {urls.get(provider, 'N/A')}")
        sys.exit(1)

    from framework.agents.orchestrator import PentestFramework

    framework = PentestFramework(
        target=args.target,
        config=config,
        verbose=args.verbose,
    )
    framework.run()


if __name__ == "__main__":
    main()
