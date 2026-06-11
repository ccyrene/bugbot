# Pull request

**Title:** {title}
**Author:** {author}
**Source → Destination:** `{source_branch}` → `{destination_branch}`
**Head commit:** `{head_commit}`

## Description
{description}

## Pre-scan: sensitive-data findings
{security_findings_block}

## Full content of changed files

The post-change content of every file touched by this PR is inlined below. **Default to reading from this section** — do not call `Read` on these paths.

{changed_files_block}

## Unified diff

```diff
{diff}
```

## Repository working tree

The PR's source branch is also checked out at `{repo_path}`. Use `Read`, `Grep`, `Glob` **only** to inspect files that are *not* in the changed-files section above (e.g. callers, configs, schemas, sibling tests). Do not re-read changed files — their full content is already in the user message.

Review per the rules in the system prompt. Return JSON only.
