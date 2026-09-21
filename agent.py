#!/usr/bin/env python3
"""
SOC triage-to-case-report agent.

Feeds a JSON log file to Claude with two tools (IOC lookup, MITRE ATT&CK
mapping) and lets it investigate and write a structured case report.

Usage:
    python agent.py data/sample_logs/suspicious_login_lateral_movement.json

Requires:
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=sk-ant-...   (or put it in a .env file, see .env.example)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from anthropic import Anthropic

from tools.tool_definitions import TOOLS, DISPATCH

MODEL = os.environ.get("SOC_AGENT_MODEL", "claude-sonnet-4-5")
MAX_TURNS = 8  # safety cap on the tool-use loop


def load_system_prompt() -> str:
    path = Path(__file__).parent / "prompts" / "system_prompt.md"
    return path.read_text()


def load_log(log_path: str) -> dict:
    with open(log_path) as f:
        return json.load(f)


def run_agent(log_data: dict, verbose: bool = True) -> str:
    """Run the tool-use loop until Claude returns a final text-only report."""
    client = Anthropic()  # reads ANTHROPIC_API_KEY from env
    system_prompt = load_system_prompt()

    messages = [
        {
            "role": "user",
            "content": (
                "Here is a batch of Windows Security and Sysmon log events "
                "for a single host. Investigate and produce a case report "
                "following the format in your instructions.\n\n"
                f"```json\n{json.dumps(log_data, indent=2)}\n```"
            ),
        }
    ]

    for turn in range(MAX_TURNS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        # Collect any tool calls in this turn's response.
        tool_uses = [block for block in response.content if block.type == "tool_use"]

        if response.stop_reason != "tool_use" or not tool_uses:
            # Claude is done investigating — this is the final report.
            text_blocks = [block.text for block in response.content if block.type == "text"]
            return "\n".join(text_blocks)

        # Echo the assistant turn (including tool_use blocks) back into history.
        messages.append({"role": "assistant", "content": response.content})

        # Run each requested tool and feed results back.
        tool_results = []
        for tool_use in tool_uses:
            fn = DISPATCH.get(tool_use.name)
            if verbose:
                print(f"  [turn {turn + 1}] agent called {tool_use.name}({tool_use.input})")
            try:
                result = fn(tool_use.input) if fn else {"error": f"unknown tool {tool_use.name}"}
            except Exception as exc:  # keep the loop alive even if a tool errors
                result = {"error": str(exc)}
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": json.dumps(result),
                }
            )

        messages.append({"role": "user", "content": tool_results})

    raise RuntimeError(
        f"Agent didn't converge on a final report within {MAX_TURNS} turns — "
        "check for a tool-calling loop, or raise MAX_TURNS."
    )


def main():
    parser = argparse.ArgumentParser(description="Run the SOC triage-to-report agent on a log file.")
    parser.add_argument("log_file", help="Path to a JSON log file, e.g. data/sample_logs/*.json")
    parser.add_argument("--quiet", action="store_true", help="Suppress tool-call progress output.")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit(
            "ANTHROPIC_API_KEY is not set. Run:\n"
            "    export ANTHROPIC_API_KEY=sk-ant-...\n"
            "or copy .env.example to .env, fill it in, and `pip install python-dotenv` "
            "then add `from dotenv import load_dotenv; load_dotenv()` at the top of agent.py."
        )

    log_data = load_log(args.log_file)
    print(f"Investigating {args.log_file} (case_id: {log_data.get('case_id', 'n/a')})...\n")

    report = run_agent(log_data, verbose=not args.quiet)

    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    out_name = f"{Path(args.log_file).stem}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    out_path = reports_dir / out_name
    out_path.write_text(report)

    print("\n" + "=" * 70)
    print(report)
    print("=" * 70)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
