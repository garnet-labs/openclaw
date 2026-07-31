#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["anthropic==0.80.0"]
# ///
"""Two-pass, read-only PR review using ClawSweeper-shaped verdicts."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_MARKER = "<!-- garnet-runtime-review -->"
POLICY_HEADING = "## ClawSweeper Review Policy"


def gh(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path, "--paginate"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}


def policy() -> str:
    source = (ROOT / "AGENTS.md").read_text()
    start = source.index(POLICY_HEADING)
    remainder = source[start + len(POLICY_HEADING) :]
    next_heading = re.search(r"^## (?!#)", remainder, re.MULTILINE)
    return (POLICY_HEADING + remainder[: next_heading.start() if next_heading else None]).strip()


def pr_context(repo: str, number: int) -> dict[str, Any]:
    pr = gh(f"repos/{repo}/pulls/{number}")
    files = gh(f"repos/{repo}/pulls/{number}/files")
    if isinstance(files, dict):
        files = [files]
    return {
        "number": number,
        "repo": repo,
        "title": pr.get("title", ""),
        "body": pr.get("body", ""),
        "head_sha": (pr.get("head") or {}).get("sha", ""),
        "base_sha": (pr.get("base") or {}).get("sha", ""),
        "files": [
            {
                "path": item.get("filename", ""),
                "status": item.get("status", ""),
                "additions": item.get("additions", 0),
                "deletions": item.get("deletions", 0),
                "patch": item.get("patch", ""),
            }
            for item in files
        ],
    }


def runtime_evidence(repo: str, number: int, head_sha: str) -> dict[str, Any]:
    comments = gh(f"repos/{repo}/issues/{number}/comments")
    if isinstance(comments, dict):
        comments = [comments]
    candidates = [
        item
        for item in comments
        if RUNTIME_MARKER in (item.get("body") or "")
        and re.search(rf"<!-- garnet:commit {re.escape(head_sha)} -->", item.get("body") or "")
    ]
    if not candidates:
        return {"present": False, "reason": "No head-pinned Garnet Runtime Review comment was found."}
    body = candidates[-1]["body"]
    urls = re.findall(r"https?://[^\s)<>]+", body)
    profile_url = next(
        (html.unescape(url.rstrip('",.')) for url in urls if "app.garnet.ai/public/runs/" in url),
        "",
    )
    profile: dict[str, Any] = {}
    if profile_url:
        try:
            api_url = profile_url.replace(
                "https://app.garnet.ai/public/runs/",
                "https://app.garnet.ai/api/public/runs/",
                1,
            )
            with urllib.request.urlopen(api_url, timeout=20) as response:
                profile = json.load(response)
            profile["_source_url"] = profile_url
        except (OSError, ValueError) as exc:
            profile = {"url": profile_url, "fetch_error": str(exc)}
    plain = html.unescape(re.sub(r"<[^>]+>", " ", body))
    destinations = sorted(set(re.findall(r"→\s*([A-Za-z0-9_.:-]+)", plain)))
    processes = sorted(
        set(
            re.findall(
                r"\b(?:bash|sh|node|pnpm|npm|git|docker|dockerd|curl|Runner\.Worker)\b",
                plain,
                re.IGNORECASE,
            )
        )
    )
    return {
        "present": True,
        "commit": head_sha,
        "comment_url": candidates[-1].get("html_url", ""),
        "markers": re.findall(r"<!--\s*(garnet[^>]+)-->", body),
        "profile": profile,
        "destinations": destinations,
        "processes": processes,
    }


def prompt(context: dict[str, Any], evidence: dict[str, Any] | None) -> str:
    files = "\n\n".join(
        f"### {item['path']} ({item['status']})\n{item['patch'] or '(binary or patch unavailable)'}"
        for item in context["files"]
    )
    evidence_block = "No runtime evidence was supplied."
    if evidence:
        evidence_block = json.dumps(evidence, indent=2)
    return f"""Review this pull request conservatively.

Repository policy:
{policy()}

PR metadata:
{json.dumps({k: v for k, v in context.items() if k != "files"}, indent=2)}

Diff:
{files}

Runtime evidence (only available in evidence-grounded mode):
{evidence_block}

Return only JSON matching this shape:
{{
  "verdict": "pass|needs-human|needs-changes",
  "risks": ["..."],
  "reviewMetrics": [{{"label":"...","value":"...","reason":"..."}}],
  "mergeRiskLabels": [],
  "bestSolution": "...",
  "labelJustifications": [],
  "rankUpMoves": ["..."],
  "reviewFindings": [{{"priority":1,"title":"...","body":"...","file":"...","lineStart":1,"lineEnd":1}}],
  "evidence": ["..."],
  "behaviorVsBaseline": "Explicitly compare observed behavior with baseline, or state that no comparison is possible.",
  "overallCorrectness": "patch is correct|patch is incorrect",
  "overallConfidenceScore": 0.0
}}

Use empty arrays when no concrete risk or finding is supported. Do not invent
runtime behavior. In evidence-grounded mode, cite the Runtime Review markers,
profile, recorded processes, and destinations, and explicitly explain behavior
versus the baseline CI lane.
"""


def call_anthropic(instruction: str) -> dict[str, Any]:
    from anthropic import Anthropic

    response = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"]).messages.create(
        model=os.environ.get("GARNET_REVIEW_MODEL", "claude-sonnet-4-5"),
        max_tokens=5000,
        temperature=0,
        system="You are a careful maintainer review worker. Return valid JSON only.",
        messages=[{"role": "user", "content": instruction}],
    )
    text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise RuntimeError("Anthropic returned no JSON verdict.")
    result = json.loads(match.group(0))
    result["llm"] = {"provider": "anthropic", "model": response.model}
    return result


def render_markdown(context: dict[str, Any], diff: dict[str, Any], evidence: dict[str, Any]) -> str:
    def compact(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ").strip()

    def list_value(value: dict[str, Any], key: str) -> str:
        item = value.get(key) or []
        if isinstance(item, list):
            return "<br>".join(compact(json.dumps(entry) if isinstance(entry, dict) else entry) for entry in item) or "—"
        return compact(item) or "—"

    return "\n".join(
        [
            "<!-- garnet-review-sticky -->",
            f"# Garnet review: PR {context['number']}",
            "",
            "This review compares a diff-only pass with a Runtime Review evidence-grounded pass.",
            "",
            "| Review pass | Verdict | Risks | Best solution | Rank-up moves |",
            "| --- | --- | --- | --- | --- |",
            f"| Diff-only | `{compact(diff.get('verdict', 'unknown'))}` | {list_value(diff, 'risks')} | {compact(diff.get('bestSolution', '—'))} | {list_value(diff, 'rankUpMoves')} |",
            f"| Evidence-grounded | `{compact(evidence.get('verdict', 'unknown'))}` | {list_value(evidence, 'risks')} | {compact(evidence.get('bestSolution', '—'))} | {list_value(evidence, 'rankUpMoves')} |",
            "",
            "## Evidence-grounded citations",
            "",
            *[f"- {compact(item)}" for item in evidence.get("evidence", [])],
            f"- Behavior versus baseline: {compact(evidence.get('behaviorVsBaseline', 'No comparison supplied.'))}",
            "",
            "## Runtime evidence",
            "",
            f"- Head commit: `{evidence.get('runtime', {}).get('commit', context['head_sha'])}`",
            f"- Runtime Review comment: {evidence.get('runtime', {}).get('comment_url', 'not found')}",
            f"- Public profile: {evidence.get('runtime', {}).get('profile', {}).get('_source_url', 'not found')}",
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pr_number", type=int)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        raise SystemExit("ANTHROPIC_API_KEY is required; refusing to run without an LLM credential.")
    context = pr_context(args.repo, args.pr_number)
    runtime = runtime_evidence(args.repo, args.pr_number, context["head_sha"])
    diff_verdict = call_anthropic(prompt(context, None))
    evidence_verdict = call_anthropic(prompt(context, runtime))
    result = {
        "pr": context,
        "diff_only": diff_verdict,
        "evidence_grounded": evidence_verdict,
        "runtime": runtime,
        "review_body": render_markdown(context, diff_verdict, {"runtime": runtime, **evidence_verdict}),
        "final_verdict": evidence_verdict.get("verdict", "needs-human"),
    }
    Path(args.output_json).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"final_verdict": result["final_verdict"], "output": args.output_json}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
