#!/usr/bin/env python3
"""Clone an OSS repo into the streetrace-dev-eval-code-review org for code review evaluation.

Preserves the N latest merged PRs (with passing checks), their discussions,
review comments, and linked issues. Content is sanitized to look native.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

import requests

ORG = "streetrace-dev-eval-code-review"
API = "https://api.github.com"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

class GitHub:
    """Thin wrapper around the GitHub REST API with rate-limit handling."""

    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _request(self, method: str, url: str, **kwargs):
        if not url.startswith("http"):
            url = f"{API}{url}"
        resp = getattr(self.session, method)(url, **kwargs)

        # Handle rate limiting
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), 1) + 1
            log.warning("Rate limited, sleeping %ds", wait)
            time.sleep(wait)
            resp = getattr(self.session, method)(url, **kwargs)

        return resp

    def get(self, url: str, **kwargs):
        return self._request("get", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("post", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self._request("patch", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._request("delete", url, **kwargs)

    def get_paginated(self, url: str, params: dict | None = None, max_pages: int = 50):
        """Yield items from a paginated GitHub API endpoint."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        for _ in range(max_pages):
            resp = self.get(url, params=params)
            resp.raise_for_status()
            items = resp.json()
            if not items:
                break
            yield from items
            if "next" not in resp.links:
                break
            url = resp.links["next"]["url"]
            params = {}  # params are baked into the next URL


# ---------------------------------------------------------------------------
# Content sanitization
# ---------------------------------------------------------------------------

def sanitize_body(text: str, source_owner: str, source_repo: str) -> str:
    """Remove references to the source repo, authors, and cross-repo links."""
    if not text:
        return ""

    # Remove full GitHub URLs pointing to the source repo
    # e.g. https://github.com/keycloak/keycloak/pull/123 → #123
    text = re.sub(
        rf"https?://github\.com/{re.escape(source_owner)}/{re.escape(source_repo)}/(?:pull|issues)/(\d+)",
        r"#\1",
        text,
    )

    # Remove other github.com URLs to the source repo (commits, blobs, etc.)
    text = re.sub(
        rf"https?://github\.com/{re.escape(source_owner)}/{re.escape(source_repo)}[^\s)]*",
        "",
        text,
    )

    # Remove @username mentions (replace with plain text)
    text = re.sub(r"@([a-zA-Z0-9_-]+)", r"\1", text)

    # Remove "Co-authored-by:" trailers
    text = re.sub(r"Co-authored-by:.*$", "", text, flags=re.MULTILINE)

    # Remove "Signed-off-by:" trailers
    text = re.sub(r"Signed-off-by:.*$", "", text, flags=re.MULTILINE)

    # Clean up excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def remap_issue_refs(text: str, issue_map: dict[int, int]) -> str:
    """Replace #old_number references with #new_number based on the issue map."""
    if not text or not issue_map:
        return text or ""

    def replace_ref(m):
        old_num = int(m.group(1))
        if old_num in issue_map:
            return f"#{issue_map[old_num]}"
        return m.group(0)

    return re.sub(r"#(\d+)", replace_ref, text)


# ---------------------------------------------------------------------------
# PR discovery
# ---------------------------------------------------------------------------

def find_eligible_prs(gh: GitHub, owner: str, repo: str, count: int) -> list[dict]:
    """Find the N most recently merged PRs where all check-runs passed."""
    eligible = []
    log.info("Searching for %d eligible merged PRs in %s/%s...", count, owner, repo)

    for pr in gh.get_paginated(
        f"/repos/{owner}/{repo}/pulls",
        params={"state": "closed", "sort": "updated", "direction": "desc"},
    ):
        if len(eligible) >= count:
            break

        if not pr.get("merged_at"):
            continue

        head_sha = pr["head"]["sha"]
        pr_number = pr["number"]

        # Check check-runs for the head SHA
        resp = gh.get(f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs",
                      params={"per_page": 100})
        if resp.status_code != 200:
            log.warning("Could not fetch check-runs for PR #%d (SHA %s): %s",
                        pr_number, head_sha[:8], resp.status_code)
            continue

        check_data = resp.json()
        runs = check_data.get("check_runs", [])

        if not runs:
            # No check-runs at all — treat as eligible (some repos don't use checks)
            log.info("PR #%d has no check-runs, treating as eligible", pr_number)
            eligible.append(pr)
            continue

        # All runs must have conclusion in {success, skipped, neutral}
        passed = all(
            r.get("conclusion") in ("success", "skipped", "neutral")
            for r in runs
        )

        if passed:
            log.info("PR #%d ✓ all %d checks passed", pr_number, len(runs))
            eligible.append(pr)
        else:
            failed = [r["name"] for r in runs
                      if r.get("conclusion") not in ("success", "skipped", "neutral")]
            log.debug("PR #%d ✗ failed checks: %s", pr_number, ", ".join(failed[:5]))

    if len(eligible) < count:
        log.warning("Only found %d eligible PRs (wanted %d)", len(eligible), count)

    return eligible


# ---------------------------------------------------------------------------
# Issue extraction and copying
# ---------------------------------------------------------------------------

def extract_issue_refs(text: str, source_owner: str, source_repo: str) -> set[int]:
    """Extract issue numbers referenced in PR body text."""
    refs = set()
    if not text:
        return refs

    # Match #N references
    refs.update(int(m) for m in re.findall(r"#(\d+)", text))

    # Match full URLs like github.com/owner/repo/issues/N
    refs.update(
        int(m)
        for m in re.findall(
            rf"https?://github\.com/{re.escape(source_owner)}/{re.escape(source_repo)}/issues/(\d+)",
            text,
        )
    )

    return refs


def copy_issues(
    gh: GitHub,
    source_owner: str,
    source_repo: str,
    target_repo_full: str,
    issue_numbers: set[int],
) -> dict[int, int]:
    """Copy issues from source to target repo. Returns old→new number map."""
    issue_map = {}

    for num in sorted(issue_numbers):
        resp = gh.get(f"/repos/{source_owner}/{source_repo}/issues/{num}")
        if resp.status_code != 200:
            log.warning("Could not fetch issue #%d: %s", num, resp.status_code)
            continue

        issue = resp.json()
        # Skip pull requests (GitHub treats PRs as issues too)
        if issue.get("pull_request"):
            continue

        body = sanitize_body(issue.get("body", ""), source_owner, source_repo)

        create_resp = gh.post(
            f"/repos/{target_repo_full}/issues",
            json={
                "title": issue["title"],
                "body": body,
                "labels": [l["name"] for l in issue.get("labels", [])],
            },
        )

        if create_resp.status_code == 201:
            new_num = create_resp.json()["number"]
            issue_map[num] = new_num
            log.info("Copied issue #%d → #%d", num, new_num)
        else:
            log.warning("Failed to create issue #%d: %s %s",
                        num, create_resp.status_code, create_resp.text[:200])

    return issue_map


# ---------------------------------------------------------------------------
# Comment copying
# ---------------------------------------------------------------------------

def copy_issue_comments(
    gh: GitHub,
    source_owner: str,
    source_repo: str,
    source_pr_number: int,
    target_repo_full: str,
    target_pr_number: int,
    issue_map: dict[int, int],
):
    """Copy timeline/issue comments from a source PR to the target PR."""
    for comment in gh.get_paginated(
        f"/repos/{source_owner}/{source_repo}/issues/{source_pr_number}/comments"
    ):
        body = sanitize_body(comment.get("body", ""), source_owner, source_repo)
        body = remap_issue_refs(body, issue_map)

        if not body.strip():
            continue

        resp = gh.post(
            f"/repos/{target_repo_full}/issues/{target_pr_number}/comments",
            json={"body": body},
        )
        if resp.status_code != 201:
            log.warning("Failed to copy comment: %s", resp.status_code)


def copy_review_comments(
    gh: GitHub,
    source_owner: str,
    source_repo: str,
    source_pr_number: int,
    target_repo_full: str,
    target_pr_number: int,
    issue_map: dict[int, int],
):
    """Copy review comments (inline code comments) preserving file/line positions."""
    for comment in gh.get_paginated(
        f"/repos/{source_owner}/{source_repo}/pulls/{source_pr_number}/comments"
    ):
        body = sanitize_body(comment.get("body", ""), source_owner, source_repo)
        body = remap_issue_refs(body, issue_map)

        if not body.strip():
            continue

        payload = {
            "body": body,
            "commit_id": comment["commit_id"],
            "path": comment["path"],
        }

        # Use the newer subject_type + line/side API if available
        if comment.get("subject_type"):
            payload["subject_type"] = comment["subject_type"]

        if comment.get("line") is not None:
            payload["line"] = comment["line"]
            payload["side"] = comment.get("side", "RIGHT")
            if comment.get("start_line") is not None:
                payload["start_line"] = comment["start_line"]
                payload["start_side"] = comment.get("start_side", "RIGHT")
        elif comment.get("position") is not None:
            payload["position"] = comment["position"]
        else:
            # Cannot place this comment — skip
            log.debug("Skipping review comment without position on %s", comment["path"])
            continue

        resp = gh.post(
            f"/repos/{target_repo_full}/pulls/{target_pr_number}/comments",
            json=payload,
        )
        if resp.status_code not in (201, 422):
            log.warning("Failed to copy review comment on %s: %s %s",
                        comment["path"], resp.status_code, resp.text[:200])


def copy_reviews(
    gh: GitHub,
    source_owner: str,
    source_repo: str,
    source_pr_number: int,
    target_repo_full: str,
    target_pr_number: int,
    issue_map: dict[int, int],
):
    """Copy review bodies (approve/request changes/comment) to the target PR."""
    for review in gh.get_paginated(
        f"/repos/{source_owner}/{source_repo}/pulls/{source_pr_number}/reviews"
    ):
        body = sanitize_body(review.get("body", ""), source_owner, source_repo)
        body = remap_issue_refs(body, issue_map)

        # Skip empty reviews with no body (these are just containers for inline comments)
        if not body.strip():
            continue

        state = review.get("state", "COMMENTED")
        # We can only submit COMMENT or APPROVE events via the API
        # (REQUEST_CHANGES requires being a reviewer)
        event = "COMMENT"

        resp = gh.post(
            f"/repos/{target_repo_full}/pulls/{target_pr_number}/reviews",
            json={"body": body, "event": event},
        )
        if resp.status_code != 200:
            log.warning("Failed to copy review: %s %s",
                        resp.status_code, resp.text[:200])


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------

def clone_and_push(
    source_url: str,
    target_repo_full: str,
    prs: list[dict],
    token: str,
    source_owner: str,
    source_repo: str,
):
    """Clone source repo, create eval branches, and push to target."""
    tmpdir = tempfile.mkdtemp(prefix="eval-clone-")
    clone_dir = os.path.join(tmpdir, "repo")

    try:
        log.info("Cloning %s (full history)...", source_url)
        subprocess.run(
            ["git", "clone", "--no-tags", source_url, clone_dir],
            check=True,
            capture_output=True,
            text=True,
        )

        # Detect default branch
        result = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            cwd=clone_dir, capture_output=True, text=True,
        )
        default_branch = result.stdout.strip().split("/")[-1] if result.returncode == 0 else "main"
        log.info("Default branch: %s", default_branch)

        # Fetch each PR's head ref and create base branches
        for pr in prs:
            pr_num = pr["number"]
            base_sha = pr["base"]["sha"]

            log.info("Fetching PR #%d head...", pr_num)
            subprocess.run(
                ["git", "fetch", "origin", f"pull/{pr_num}/head:eval/pr-{pr_num}"],
                cwd=clone_dir, check=True, capture_output=True, text=True,
            )

            # Create base branch pointing at the PR's base SHA
            subprocess.run(
                ["git", "branch", f"eval/base-{pr_num}", base_sha],
                cwd=clone_dir, check=True, capture_output=True, text=True,
            )

        # Set up target remote with auth
        target_url = f"https://x-access-token:{token}@github.com/{target_repo_full}.git"
        subprocess.run(
            ["git", "remote", "add", "target", target_url],
            cwd=clone_dir, check=True, capture_output=True, text=True,
        )

        # Push default branch
        log.info("Pushing default branch (%s) to target...", default_branch)
        subprocess.run(
            ["git", "push", "target", f"{default_branch}:{default_branch}"],
            cwd=clone_dir, check=True, capture_output=True, text=True,
        )

        # Push all eval branches
        eval_branches = []
        for pr in prs:
            pr_num = pr["number"]
            eval_branches.extend([f"eval/pr-{pr_num}", f"eval/base-{pr_num}"])

        log.info("Pushing %d eval branches to target...", len(eval_branches))
        subprocess.run(
            ["git", "push", "target"] + eval_branches,
            cwd=clone_dir, check=True, capture_output=True, text=True,
        )

        return default_branch

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Repo management
# ---------------------------------------------------------------------------

def delete_repo_if_exists(gh: GitHub, repo_full: str):
    """Delete a repo if it exists."""
    resp = gh.get(f"/repos/{repo_full}")
    if resp.status_code == 200:
        log.info("Deleting existing repo %s...", repo_full)
        del_resp = gh.delete(f"/repos/{repo_full}")
        if del_resp.status_code == 204:
            log.info("Deleted %s", repo_full)
            # Wait a moment for GitHub to process
            time.sleep(2)
        else:
            log.error("Failed to delete %s: %s %s",
                      repo_full, del_resp.status_code, del_resp.text[:200])
            sys.exit(1)


def create_repo(gh: GitHub, name: str) -> dict:
    """Create a new repo in the org."""
    log.info("Creating repo %s/%s...", ORG, name)
    resp = gh.post(
        f"/orgs/{ORG}/repos",
        json={
            "name": name,
            "private": False,
            "description": f"Code review evaluation repo — {name}",
            "has_issues": True,
            "has_projects": False,
            "has_wiki": False,
        },
    )
    if resp.status_code == 201:
        log.info("Created repo %s/%s", ORG, name)
        return resp.json()
    else:
        headers_str = dict(resp.headers)
        log.error("Failed to create repo: %s %s\nHeaders: %s",
                  resp.status_code, resp.text[:500],
                  json.dumps({k: v for k, v in headers_str.items()
                              if k.lower().startswith("x-")}, indent=2))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def process_tool(
    gh: GitHub,
    tool: str,
    source_owner: str,
    source_repo: str,
    generation: str,
    prs: list[dict],
    token: str,
    dry_run: bool,
):
    """Process a single tool: create target repo, push code, recreate PRs."""
    target_name = f"{tool}-{source_repo}-{generation}"
    target_full = f"{ORG}/{target_name}"
    source_url = f"https://github.com/{source_owner}/{source_repo}"

    log.info("=" * 60)
    log.info("Processing tool: %s → %s", tool, target_full)
    log.info("=" * 60)

    if dry_run:
        log.info("[DRY RUN] Would delete %s if exists", target_full)
        log.info("[DRY RUN] Would create %s", target_full)
        log.info("[DRY RUN] Would clone %s and push %d PRs", source_url, len(prs))
        for pr in prs:
            log.info("[DRY RUN] PR #%d: %s (base: %s)",
                     pr["number"], pr["title"], pr["base"]["sha"][:8])
        return

    # Step 1: Cleanup
    delete_repo_if_exists(gh, target_full)

    # Step 2: Create repo
    create_repo(gh, target_name)

    # Step 3: Clone & push
    default_branch = clone_and_push(
        source_url, target_full, prs, token, source_owner, source_repo,
    )

    # Step 4: Collect all issue refs from all PRs first
    all_issue_refs = set()
    for pr in prs:
        refs = extract_issue_refs(pr.get("body", ""), source_owner, source_repo)
        all_issue_refs.update(refs)

    # Copy all referenced issues once
    log.info("Copying %d referenced issues...", len(all_issue_refs))
    issue_map = copy_issues(gh, source_owner, source_repo, target_full, all_issue_refs)
    log.info("Issue map: %s", issue_map)

    # Step 5: Create PRs
    for pr in prs:
        pr_num = pr["number"]
        title = pr["title"]
        body = sanitize_body(pr.get("body", ""), source_owner, source_repo)
        body = remap_issue_refs(body, issue_map)

        log.info("Creating PR for #%d: %s", pr_num, title)

        create_resp = gh.post(
            f"/repos/{target_full}/pulls",
            json={
                "title": title,
                "body": body,
                "head": f"eval/pr-{pr_num}",
                "base": f"eval/base-{pr_num}",
            },
        )

        if create_resp.status_code != 201:
            log.error("Failed to create PR for #%d: %s %s",
                      pr_num, create_resp.status_code, create_resp.text[:300])
            continue

        new_pr = create_resp.json()
        new_pr_num = new_pr["number"]
        log.info("Created PR #%d (from source #%d)", new_pr_num, pr_num)

        # Copy issue comments
        copy_issue_comments(
            gh, source_owner, source_repo, pr_num,
            target_full, new_pr_num, issue_map,
        )

        # Copy review comments (inline)
        copy_review_comments(
            gh, source_owner, source_repo, pr_num,
            target_full, new_pr_num, issue_map,
        )

        # Copy reviews
        copy_reviews(
            gh, source_owner, source_repo, pr_num,
            target_full, new_pr_num, issue_map,
        )

    log.info("Done processing %s", target_full)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", required=True,
                        help="Source repo URL (e.g. https://github.com/keycloak/keycloak)")
    parser.add_argument("--generation", required=True,
                        help="Generation number (e.g. 1)")
    parser.add_argument("--tools", default="streetrace",
                        help="Comma-separated tool names (default: streetrace)")
    parser.add_argument("--pr-count", type=int, default=10,
                        help="Number of PRs to preserve (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview without making changes")
    args = parser.parse_args()

    # Parse source URL
    parsed = urlparse(args.source_repo)
    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 2:
        log.error("Invalid source repo URL: %s", args.source_repo)
        sys.exit(1)
    source_owner, source_repo = path_parts[0], path_parts[1]

    # Get token
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.error("GITHUB_TOKEN environment variable not set")
        sys.exit(1)

    gh = GitHub(token)

    # Verify token
    user_resp = gh.get("/user")
    if user_resp.status_code != 200:
        log.error("Token validation failed: %s", user_resp.status_code)
        sys.exit(1)
    log.info("Authenticated as: %s", user_resp.json().get("login", "unknown"))

    # Find eligible PRs
    prs = find_eligible_prs(gh, source_owner, source_repo, args.pr_count)
    if not prs:
        log.error("No eligible PRs found in %s/%s", source_owner, source_repo)
        sys.exit(1)

    log.info("Found %d eligible PRs: %s", len(prs),
             ", ".join(f"#{p['number']}" for p in prs))

    # Process each tool
    tools = [t.strip() for t in args.tools.split(",")]
    for tool in tools:
        process_tool(gh, tool, source_owner, source_repo,
                     args.generation, prs, token, args.dry_run)

    log.info("All done!")


if __name__ == "__main__":
    main()
