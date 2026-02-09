# streetrace-dev-eval-code-review

Infrastructure for evaluating code review tools against real-world open-source pull requests.

## What This Org Does

This GitHub org hosts cloned copies of open-source repositories, each containing a set of real merged PRs (with their discussions, review comments, and linked issues) re-created as open PRs. Code review tools are then run against these PRs to evaluate their quality.

## Target Repos

| Source Repo | Description |
|------------|-------------|
| [keycloak/keycloak](https://github.com/keycloak/keycloak) | Identity and access management |
| [getsentry/sentry](https://github.com/getsentry/sentry) | Error tracking platform |
| [discourse/discourse](https://github.com/discourse/discourse) | Discussion platform |
| [calcom/cal.com](https://github.com/calcom/cal.com) | Scheduling infrastructure |
| [grafana/grafana](https://github.com/grafana/grafana) | Observability platform |

## Repo Naming Convention

```
{TOOL}-{REPO}-{GENERATION}
```

Examples:
- `streetrace-keycloak-1` — Keycloak, generation 1, for Streetrace evaluation
- `greptile-sentry-2` — Sentry, generation 2, for Greptile evaluation

## Tools

| Tool | Key |
|------|-----|
| Streetrace | `streetrace` |
| Greptile | `greptile` |
| GitHub Copilot | `copilot` |
| Augment | `augment` |
| Claude Code | `claude-code` |
| Codex | `codex` |
| Cursor | `cursor` |
| Paragon | `paragon` |

## What Gets Copied

For each source repo, the workflow preserves:

- **10 latest merged PRs** (with all check-runs passing)
- **PR descriptions** (sanitized — no source attribution)
- **Issue comments** (timeline discussion)
- **Review comments** (inline code comments with file/line positions)
- **Review bodies** (approve/request-changes summaries)
- **Linked issues** (copied to target with updated cross-references)
- **Full git history** (so PR diffs are accurate)

Content is sanitized: source repo URLs, author mentions, and co-author trailers are removed so PRs look native to the target repo.

## Running the Workflow

1. Go to **Actions** → **Clone Repo for Eval**
2. Click **Run workflow**
3. Fill in:
   - **Source repo URL**: e.g. `https://github.com/keycloak/keycloak`
   - **Generation**: e.g. `1`
   - **Tools**: comma-separated, e.g. `streetrace,greptile,copilot`
   - **PR count**: number of PRs (default: 10)

Or run locally:

```bash
export GITHUB_TOKEN=ghp_...
python scripts/clone_for_eval.py \
  --source-repo https://github.com/calcom/cal.com \
  --generation 1 \
  --tools streetrace \
  --pr-count 10
```

Use `--dry-run` to preview without making changes.

## Required Token Permissions

The `EVAL_GITHUB_TOKEN` secret needs a fine-grained PAT with **"All repositories"** access in this org:

| Scope | Permission |
|-------|-----------|
| Organization → Administration | Read and write |
| Repository → Contents | Read and write |
| Repository → Pull requests | Read and write |
| Repository → Issues | Read and write |
| Repository → Administration | Read and write |
| Repository → Actions | Read (optional) |
