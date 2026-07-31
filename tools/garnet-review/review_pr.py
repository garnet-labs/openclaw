#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Deterministic two-view PR gate.

View A rolls up GitHub check runs for the PR head. View B compares the
head-pinned Garnet Runtime Review profiles with a baseline supplied as a PR
number or ``run_id:profile_id``. The workflow passes ``GARNET_BASELINE_PR``
through ``--baseline``; without it, missing baseline evidence is needs-human.
"""

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
PATCH_CHAR_CAP = 4_000
DIFF_CHAR_CAP = 60_000
PROFILE_CHAR_CAP = 20_000
PUBLIC_PROFILE_RE = re.compile(
    r"https://app\.garnet\.ai/public/runs/(?P<run_id>\d+)"
    r"\?profile=(?P<profile_id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=$|[\s)<>",.]|&amp;)'
)


def gh(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path, "--paginate"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else {}


def gh_once(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path],
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


def parse_public_profile_url(body: str) -> tuple[str, str, str] | None:
    match = PUBLIC_PROFILE_RE.search(body)
    if not match:
        return None
    run_id = match.group("run_id")
    profile_id = match.group("profile_id").lower()
    canonical_url = f"https://app.garnet.ai/public/runs/{run_id}?profile={profile_id}"
    return run_id, profile_id, canonical_url


def parse_public_profile_urls(body: str) -> list[tuple[str, str, str]]:
    return [
        (match.group("run_id"), match.group("profile_id").lower(),
         f"https://app.garnet.ai/public/runs/{match.group('run_id')}?profile={match.group('profile_id').lower()}")
        for match in PUBLIC_PROFILE_RE.finditer(body)
    ]


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
    parsed_profiles = parse_public_profile_urls(body)
    profiles: list[dict[str, Any]] = []
    for run_id, profile_id, profile_url in parsed_profiles:
        try:
            api_url = f"https://app.garnet.ai/api/public/runs/{run_id}?profile={profile_id}"
            with urllib.request.urlopen(api_url, timeout=20) as response:
                profile = json.load(response)
            profile["_source_url"] = profile_url
            profiles.append({"run_id": run_id, "profile_id": profile_id, "url": profile_url, "data": profile})
        except (OSError, ValueError) as exc:
            profiles.append({"url": profile_url, "fetch_error": str(exc)})
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
        "profile": profiles[0]["data"] if profiles and "data" in profiles[0] else {},
        "profiles": profiles,
        "destinations": destinations,
        "processes": processes,
    }


def bounded_diff(context: dict[str, Any]) -> tuple[str, int]:
    chunks: list[str] = []
    total = 0
    omitted = 0
    for item in context["files"]:
        patch = item["patch"] or "(binary or patch unavailable)"
        if len(patch) > PATCH_CHAR_CAP:
            patch = patch[:PATCH_CHAR_CAP] + "\n[patch truncated]"
        chunk = f"### {item['path']} ({item['status']})\n{patch}"
        if total + len(chunk) > DIFF_CHAR_CAP:
            omitted += 1
            continue
        chunks.append(chunk)
        total += len(chunk)
    if omitted:
        chunks.append(f"[{omitted} file(s) omitted after the {DIFF_CHAR_CAP}-character diff cap]")
    return "\n\n".join(chunks), omitted


def bounded_json(value: Any, cap: int) -> str:
    serialized = json.dumps(value, indent=2, sort_keys=True)
    if len(serialized) <= cap:
        return serialized
    return serialized[:cap] + f"\n[JSON truncated at {cap} characters]"


def check_rollup(repo: str, sha: str) -> dict[str, Any]:
    payload = gh_once(f"repos/{repo}/commits/{sha}/check-runs")
    runs = payload.get("check_runs", []) if isinstance(payload, dict) else []
    green = sum(item.get("conclusion") == "success" for item in runs)
    red = sum(item.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required"} for item in runs)
    pending = len(runs) - green - red
    verdict = "PASS" if red == 0 else "FLAG"
    return {
        "verdict": verdict,
        "green": green,
        "red": red,
        "pending": pending,
        "checks": [{"name": item.get("name", ""), "conclusion": item.get("conclusion")} for item in runs],
    }


def profile_sets(evidence: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    jobs: dict[str, dict[str, set[str]]] = {}
    for entry in evidence.get("profiles", []):
        data = entry.get("data", {})
        documents = data.get("profiles", []) if isinstance(data, dict) else []
        if not documents and isinstance(data, dict) and data.get("profile"):
            documents = [data["profile"]]
        for document in documents:
            run = document.get("run", {}) if isinstance(document, dict) else {}
            job = run.get("job", "unknown")
            bucket = jobs.setdefault(job, {"processes": set(), "destinations": set()})
            for association in document.get("associations", []):
                ancestry = association.get("ancestry") or []
                process = association.get("process")
                if process:
                    bucket["processes"].add(" > ".join([*ancestry, process]) if ancestry else process)
                names = association.get("remote_names") or []
                if names:
                    bucket["destinations"].update(names)
                elif association.get("remote_address"):
                    bucket["destinations"].add(association["remote_address"])
    return jobs


def baseline_evidence(repo: str, value: str) -> dict[str, Any]:
    if not value:
        return {"present": False, "reason": "No --baseline PR or run/profile identifier was supplied."}
    if value.isdigit():
        context = pr_context(repo, int(value))
        return runtime_evidence(repo, int(value), context["head_sha"])
    match = re.fullmatch(r"(\d+):([0-9a-fA-F-]{36})", value)
    if match:
        run_id, profile_id = match.groups()
        url = f"https://app.garnet.ai/public/runs/{run_id}?profile={profile_id.lower()}"
        api_url = f"https://app.garnet.ai/api/public/runs/{run_id}?profile={profile_id.lower()}"
        try:
            with urllib.request.urlopen(api_url, timeout=20) as response:
                data = json.load(response)
            return {"present": True, "profile": data, "profiles": [{"url": url, "data": data}]}
        except (OSError, ValueError) as exc:
            return {"present": False, "reason": f"Baseline profile fetch failed: {exc}", "profile_url": url}
    parsed = parse_public_profile_url(value)
    if parsed:
        return baseline_evidence(repo, f"{parsed[0]}:{parsed[1]}")
    return {"present": False, "reason": "Baseline must be a PR number or run_id:profile_id."}


def configured_baseline(explicit: str) -> str:
    if explicit:
        return explicit
    config_path = ROOT / "tools/garnet-review/baseline.json"
    try:
        config = json.loads(config_path.read_text())
    except (OSError, ValueError):
        return ""
    return str(config.get("baseline", "")).strip()


def behavior_view(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    if not current.get("present") or not baseline.get("present"):
        return {
            "verdict": "needs-human",
            "risks": [current.get("reason", "Current evidence missing."), baseline.get("reason", "Baseline evidence missing.")],
            "evidence": [current.get("comment_url", ""), baseline.get("comment_url", "")],
            "behaviorVsBaseline": "Unable to compare because one or both Runtime Review profiles are missing.",
            "deltas": [],
        }
    current_jobs = profile_sets(current)
    baseline_jobs = profile_sets(baseline)
    deltas: list[dict[str, Any]] = []
    for job, observed in current_jobs.items():
        base = baseline_jobs.get(job, {"processes": set(), "destinations": set()})
        processes = sorted(observed["processes"] - base["processes"])
        destinations = sorted(observed["destinations"] - base["destinations"])
        if processes or destinations:
            deltas.append({"job": job, "newProcesses": processes, "newDestinations": destinations})
    verdict = "PASS" if not deltas else "FLAG"
    return {
        "verdict": verdict,
        "risks": [f"{item['job']}: new processes={item['newProcesses']}, new destinations={item['newDestinations']}" for item in deltas],
        "evidence": [current.get("comment_url", ""), baseline.get("comment_url", "")],
        "behaviorVsBaseline": "No new processes or destinations versus baseline." if not deltas else "Observed runtime deltas versus baseline are listed explicitly.",
        "deltas": deltas,
    }


def render_markdown(
    context: dict[str, Any],
    correctness: dict[str, Any],
    behavior: dict[str, Any],
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> str:
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
            "This deterministic gate compares GitHub correctness signals with Runtime Review behavior deltas.",
            "",
            "| View | Verdict | Signals |",
            "| --- | --- | --- |",
            f"| Correctness (check-run rollup) | `{compact(correctness.get('verdict', 'unknown'))}` | green={correctness.get('green', 0)}, red={correctness.get('red', 0)}, pending={correctness.get('pending', 0)} |",
            f"| Behavior (Garnet vs baseline) | `{compact(behavior.get('verdict', 'unknown'))}` | {list_value(behavior, 'risks')} |",
            "",
            "## Behavior deltas",
            "",
            *[f"- `{item['job']}`: new processes={item['newProcesses']}; new destinations={item['newDestinations']}" for item in behavior.get("deltas", [])],
            f"- {compact(behavior.get('behaviorVsBaseline', 'No comparison supplied.'))}",
            "",
            "## Runtime profile citations",
            "",
            f"- Current Runtime Review comment: {current.get('comment_url', 'not found')}",
            f"- Current public profile: {current.get('profiles', [{}])[0].get('url', 'not found')}",
            f"- Baseline Runtime Review comment: {baseline.get('comment_url', 'not found')}",
            f"- Baseline public profile: {baseline.get('profiles', [{}])[0].get('url', 'not found')}",
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pr_number", type=int)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--baseline", default=os.environ.get("GARNET_BASELINE_PR", ""))
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()
    context = pr_context(args.repo, args.pr_number)
    runtime = runtime_evidence(args.repo, args.pr_number, context["head_sha"])
    baseline = baseline_evidence(args.repo, configured_baseline(args.baseline))
    correctness = check_rollup(args.repo, context["head_sha"])
    behavior = behavior_view(runtime, baseline)
    result = {
        "pr": context,
        "correctness_view": correctness,
        "behavior_view": behavior,
        "runtime": runtime,
        "baseline": baseline,
        "review_body": render_markdown(context, correctness, behavior, runtime, baseline),
        "final_verdict": "FLAG" if "FLAG" in {correctness["verdict"], behavior["verdict"]} else (
            "needs-human" if "needs-human" in {correctness["verdict"], behavior["verdict"]} else "PASS"
        ),
    }
    Path(args.output_json).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"final_verdict": result["final_verdict"], "output": args.output_json}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
