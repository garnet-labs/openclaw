#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Deterministic two-view PR gate.

View A rolls up GitHub check runs for the PR head. View B compares the
head-pinned Garnet Runtime Review profiles with a baseline supplied as a PR
number or ``run_id:profile_id``. The workflow passes ``GARNET_BASELINE_PR``
through ``--baseline``; without it, missing baseline evidence is needs-human.

Runtime deltas are classified rather than discarded. Process lineages under
``Runner.Worker > bash``/``sh`` are workload; hosted-compute, provjobd,
Runner.Listener, terminal Runner.Worker, and systemd-network lineages are
runner infrastructure. Destinations in GitHub/Actions artifact ranges are
runner infrastructure unless profile associations link them to a workload
process. Flat destination sets without that linkage use the destination-only
classification and are identified as such in the rendered fold.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_MARKER = "<!-- garnet-runtime-review -->"
POLICY_HEADING = "## ClawSweeper Review Policy"
PATCH_CHAR_CAP = 4_000
DIFF_CHAR_CAP = 60_000
PROFILE_CHAR_CAP = 20_000
RUNNER_INFRA_PROCESS_MARKERS = (
    "hosted-compute",
    "provjobd",
    "Runner.Listener",
    "systemd-network",
)
RUNNER_INFRA_DESTINATION_SUFFIXES = (
    ".blob.core.windows.net",
    ".actions.githubusercontent.com",
)
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


def _profile_evidence_from_comment(
    body: str,
    comment: dict[str, Any],
    pinned_commit: str,
) -> dict[str, Any]:
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
        "commit": pinned_commit,
        "comment_url": comment.get("html_url", ""),
        "markers": re.findall(r"<!--\s*(garnet[^>]+)-->", body),
        "profile": profiles[0]["data"] if profiles and "data" in profiles[0] else {},
        "profiles": profiles,
        "destinations": destinations,
        "processes": processes,
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
    body = candidates[-1].get("body") or ""
    return _profile_evidence_from_comment(body, candidates[-1], head_sha)


def latest_runtime_evidence(repo: str, number: int) -> dict[str, Any]:
    """Read the latest baseline review, even if the PR moved afterward."""
    comments = gh(f"repos/{repo}/issues/{number}/comments")
    if isinstance(comments, dict):
        comments = [comments]
    candidates: list[tuple[dict[str, Any], str]] = []
    for comment in comments:
        body = comment.get("body") or ""
        if RUNTIME_MARKER not in body:
            continue
        match = re.search(r"<!-- garnet:commit ([0-9a-fA-F]{40}) -->", body)
        if match:
            candidates.append((comment, match.group(1)))
    if not candidates:
        return {"present": False, "reason": "No Garnet Runtime Review comment was found on the baseline PR."}
    comment, pinned_commit = candidates[-1]
    return _profile_evidence_from_comment(comment.get("body") or "", comment, pinned_commit)


def wait_for_runtime_evidence(
    repo: str,
    number: int,
    head_sha: str,
    *,
    timeout_seconds: int = 15 * 60,
    interval_seconds: int = 30,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    evidence = runtime_evidence(repo, number, head_sha)
    while (
        (not evidence.get("present") or not profile_sets(evidence))
        and time.monotonic() < deadline
    ):
        time.sleep(min(interval_seconds, max(0, deadline - time.monotonic())))
        evidence = runtime_evidence(repo, number, head_sha)
    return evidence


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
    verdict = "FLAG" if red else ("pending" if pending else "PASS")
    return {
        "verdict": verdict,
        "green": green,
        "red": red,
        "pending": pending,
        "checks": [{"name": item.get("name", ""), "conclusion": item.get("conclusion")} for item in runs],
    }


def is_workload_process(lineage: str) -> bool:
    return bool(re.search(r"Runner\.Worker > (?:bash|sh)(?: >|$)", lineage))


def is_runner_infra_process(lineage: str) -> bool:
    if is_workload_process(lineage):
        return False
    if any(marker.lower() in lineage.lower() for marker in RUNNER_INFRA_PROCESS_MARKERS):
        return True
    # A process outside the Runner.Worker job-step shell chain is not
    # attributable to workload execution from this profile shape.
    return True


def is_runner_infra_destination(destination: str) -> bool:
    normalized = destination.lower().rstrip(".")
    if normalized == "ip6-allrouters" or normalized.startswith(("169.254.", "fe80:")):
        return True
    if normalized.endswith(RUNNER_INFRA_DESTINATION_SUFFIXES):
        return True
    match = re.fullmatch(r"140\.82\.(?:\d{1,3})\.(?:\d{1,3})", normalized)
    return bool(match)


def profile_sets(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    jobs: dict[str, dict[str, Any]] = {}
    for entry in evidence.get("profiles", []):
        data = entry.get("data", {})
        documents = data.get("profiles", []) if isinstance(data, dict) else []
        if not documents and isinstance(data, dict) and data.get("profile"):
            documents = [data["profile"]]
        for document in documents:
            run = document.get("run", {}) if isinstance(document, dict) else {}
            job = run.get("job", "unknown")
            bucket = jobs.setdefault(
                job,
                {
                    "processes": set(),
                    "destinations": set(),
                    "destination_processes": {},
                },
            )
            for association in document.get("associations", []):
                ancestry = association.get("ancestry") or []
                process = association.get("process")
                lineage = ""
                if process:
                    lineage = " > ".join([*ancestry, process]) if ancestry else process
                    bucket["processes"].add(lineage)
                names = association.get("remote_names") or []
                destinations = names or (
                    [association["remote_address"]]
                    if association.get("remote_address")
                    else []
                )
                for destination in destinations:
                    bucket["destinations"].add(destination)
                    if lineage:
                        bucket["destination_processes"].setdefault(destination, set()).add(lineage)
    return jobs


def baseline_evidence(repo: str, value: str) -> dict[str, Any]:
    if not value:
        return {"present": False, "reason": "No --baseline PR or run/profile identifier was supplied."}
    if value.isdigit():
        return latest_runtime_evidence(repo, int(value))
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
    reasons = []
    if not current.get("present"):
        reasons.append(current.get("reason", "Current evidence missing."))
    if not baseline.get("present"):
        reasons.append(baseline.get("reason", "Baseline evidence missing."))
    current_jobs = profile_sets(current) if current.get("present") else {}
    baseline_jobs = profile_sets(baseline) if baseline.get("present") else {}
    if current.get("present") and not current_jobs:
        reasons.append("Current Runtime Review has no resolved public profile evidence.")
    if baseline.get("present") and not baseline_jobs:
        reasons.append("Baseline Runtime Review has no resolved public profile evidence.")
    if reasons:
        return {
            "verdict": "needs-human",
            "risks": reasons,
            "evidence": [current.get("comment_url", ""), baseline.get("comment_url", "")],
            "behaviorVsBaseline": "Unable to compare because one or both Runtime Review profiles are missing.",
            "deltas": [],
        }
    deltas: list[dict[str, Any]] = []
    for job, observed in current_jobs.items():
        base = baseline_jobs.get(
            job,
            {"processes": set(), "destinations": set(), "destination_processes": {}},
        )
        processes = sorted(observed["processes"] - base["processes"])
        destinations = sorted(observed["destinations"] - base["destinations"])
        workload_processes = sorted(filter(is_workload_process, processes))
        runner_infra_processes = sorted(
            process for process in processes if is_runner_infra_process(process)
        )
        workload_destinations: list[str] = []
        runner_infra_destinations: list[str] = []
        flat_destination_classification = False
        for destination in destinations:
            linked_processes = observed["destination_processes"].get(destination, set())
            if linked_processes:
                if any(is_workload_process(process) for process in linked_processes):
                    workload_destinations.append(destination)
                else:
                    runner_infra_destinations.append(destination)
            elif is_runner_infra_destination(destination):
                runner_infra_destinations.append(destination)
                flat_destination_classification = True
            else:
                workload_destinations.append(destination)
                flat_destination_classification = True
        if processes or destinations:
            deltas.append(
                {
                    "job": job,
                    "workload": {
                        "newProcesses": workload_processes,
                        "newDestinations": sorted(workload_destinations),
                    },
                    "runnerInfra": {
                        "newProcesses": runner_infra_processes,
                        "newDestinations": sorted(runner_infra_destinations),
                    },
                    "destinationClassification": (
                        "association-linked where available; flat destination "
                        "sets use destination-only rules"
                        if flat_destination_classification
                        else "association-linked"
                    ),
                }
            )
    workload_deltas = [
        item
        for item in deltas
        if item["workload"]["newProcesses"] or item["workload"]["newDestinations"]
    ]
    verdict = "PASS" if not workload_deltas else "FLAG"
    return {
        "verdict": verdict,
        "risks": [
            f"{item['job']}: workload processes={item['workload']['newProcesses']}, "
            f"workload destinations={item['workload']['newDestinations']}"
            for item in workload_deltas
        ],
        "evidence": [current.get("comment_url", ""), baseline.get("comment_url", "")],
        "behaviorVsBaseline": (
            "No new workload processes or destinations versus baseline."
            if not workload_deltas
            else "Observed workload deltas versus baseline are listed explicitly."
        ),
        "deltas": deltas,
    }


def overall_verdict(correctness: dict[str, Any], behavior: dict[str, Any]) -> str:
    verdicts = {correctness.get("verdict"), behavior.get("verdict")}
    if "FLAG" in verdicts:
        return "FLAG"
    if "needs-human" in verdicts or "pending" in verdicts:
        return "needs-human"
    return "PASS"


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

    def first_profile_url(evidence: dict[str, Any]) -> str:
        profiles = evidence.get("profiles") or []
        if not profiles:
            return "not found"
        return str(profiles[0].get("url") or "not found")

    return "\n".join(
        [
            "<!-- garnet-review-sticky -->",
            f"# Garnet review: PR {context['number']}",
            "",
            f"**Final verdict: {overall_verdict(correctness, behavior)}** "
            f"(correctness {correctness.get('verdict', 'unknown')} · behavior {behavior.get('verdict', 'unknown')})",
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
            *[
                f"- `{item['job']}`: workload processes={item['workload']['newProcesses']}; "
                f"workload destinations={item['workload']['newDestinations']}"
                for item in behavior.get("deltas", [])
                if item["workload"]["newProcesses"] or item["workload"]["newDestinations"]
            ],
            f"- {compact(behavior.get('behaviorVsBaseline', 'No comparison supplied.'))}",
            "",
            "<details>",
            "<summary>Runner infrastructure deltas (classified, not hidden)</summary>",
            "",
            "Runner infrastructure includes hosted-compute/provjobd/Runner.Listener/terminal Runner.Worker/systemd-network lineages and GitHub/Actions artifact destinations. Destination-only classification is used when profile associations do not link a destination to a process.",
            "",
            *[
                f"- `{item['job']}`: processes={item['runnerInfra']['newProcesses']}; "
                f"destinations={item['runnerInfra']['newDestinations']} "
                f"({item['destinationClassification']})"
                for item in behavior.get("deltas", [])
                if item["runnerInfra"]["newProcesses"] or item["runnerInfra"]["newDestinations"]
            ],
            "",
            "</details>",
            "",
            "## Runtime profile citations",
            "",
            f"- Current Runtime Review comment: {current.get('comment_url', 'not found')}",
            f"- Current public profile: {first_profile_url(current)}",
            f"- Baseline Runtime Review comment: {baseline.get('comment_url', 'not found')}",
            f"- Baseline commit: {baseline.get('commit', 'not found')} (from Runtime Review pin)",
            f"- Baseline public profile: {first_profile_url(baseline)}",
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
    runtime = wait_for_runtime_evidence(args.repo, args.pr_number, context["head_sha"])
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
        "final_verdict": overall_verdict(correctness, behavior),
    }
    Path(args.output_json).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"final_verdict": result["final_verdict"], "output": args.output_json}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
