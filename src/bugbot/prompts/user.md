# Pull request

**Title:** {title}
**Author:** {author}
**Source → Destination:** `{source_branch}` → `{destination_branch}`
**Head commit:** `{head_commit}`

## Description
{description}

## Repository working tree
The PR's source branch is checked out at the current working directory (`{repo_path}`). Use `Read`, `Grep`, `Glob` to inspect any file you need to verify a finding. Tools are read-only.

## Pre-scan: sensitive-data findings
{security_findings_block}

## Unified diff

```diff
{diff}
```

Review the diff per the rules in the system prompt. Verify suspicions via the tools where useful. Return JSON only.
