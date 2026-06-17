from bugbot.config import Severity
from bugbot.services.diff import parse_unified_diff
from bugbot.services.security import scan_diff, scan_line


def _wrap(content: str) -> str:
    return (
        "diff --git a/secret.py b/secret.py\n"
        "index 0..1 100644\n"
        "--- a/secret.py\n"
        "+++ b/secret.py\n"
        "@@ -0,0 +1,1 @@\n"
        f"+{content}\n"
    )


def test_detects_aws_access_key():
    findings = scan_line("a.py", 1, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    assert any(f.rule_id == "aws-access-key" for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_detects_openai_key():
    findings = scan_line("a.py", 1, 'OPENAI = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678"')
    assert any(f.rule_id == "openai-key" for f in findings)


def test_detects_openrouter_key():
    findings = scan_line("a.py", 1, 'OR = "sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789"')
    assert any(f.rule_id == "openrouter-key" for f in findings)


def test_detects_anthropic_key():
    findings = scan_line(
        "a.py", 1,
        'AK = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"',
    )
    assert any(f.rule_id == "anthropic-key" for f in findings)


def test_detects_private_key_pem():
    findings = scan_line("k.pem", 1, "-----BEGIN RSA PRIVATE KEY-----")
    assert any(f.rule_id == "private-key-pem" for f in findings)
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_detects_db_url_with_creds():
    findings = scan_line(
        "db.py", 1,
        'DB_URL = "postgres://app_user:s3cretP4ss@db.internal:5432/app"',
    )
    assert any(f.rule_id == "db-url-with-creds" for f in findings)


def test_detects_slack_webhook():
    findings = scan_line(
        "notify.py", 1,
        'URL = "https://hooks.slack.com/services/T01234567/B0123456789/abcdefghij1234567890"',
    )
    assert any(f.rule_id == "slack-webhook" for f in findings)


def test_detects_github_pat():
    findings = scan_line("c.py", 1, 'TOK = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"')
    assert any(f.rule_id == "github-token" for f in findings)


def test_password_assignment_with_real_value():
    findings = scan_line("c.py", 1, 'password = "Hunter2-real-value"')
    assert any(f.rule_id == "password-assignment" for f in findings)


def test_password_assignment_ignored_for_placeholder():
    # `your-password-here` is a placeholder, must NOT fire.
    findings = scan_line("c.py", 1, 'password = "your-password-here"')
    assert not any(f.rule_id == "password-assignment" for f in findings)


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = scan_line("a.py", 1, f"TOKEN={jwt}")
    assert any(f.rule_id == "jwt" for f in findings)


def test_snippet_does_not_contain_raw_secret_for_aws():
    findings = scan_line("a.py", 1, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    aws = next(f for f in findings if f.rule_id == "aws-access-key")
    # Masked snippet keeps prefix/suffix but cannot leak the full value.
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.snippet
    # Raw match is preserved for local handling but is never serialised.
    assert aws.raw_match == "AKIAIOSFODNN7EXAMPLE"


def test_clean_line_yields_no_findings():
    findings = scan_line("a.py", 1, "def add(x, y):\n    return x + y")
    # Filter the LOW-severity private IP rule etc — none should fire here.
    assert findings == []


def test_scan_diff_only_picks_up_added_lines():
    diff = (
        "diff --git a/x.py b/x.py\n"
        "index a..b 100644\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,2 @@\n"
        '-old_token = "ghp_REMOVEDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        '+new_token = "ghp_NEWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        " untouched\n"
    )
    files = parse_unified_diff(diff)
    findings = scan_diff(files)
    # Only the added line should generate a finding.
    assert len(findings) == 1
    assert "NEW" in findings[0].raw_match


def test_full_diff_e2e():
    diff = _wrap('SECRET = "sk-or-v1-' + "x" * 40 + '"')
    findings = scan_diff(parse_unified_diff(diff))
    assert any(f.rule_id == "openrouter-key" for f in findings)
    assert findings[0].line == 1
    assert findings[0].file == "secret.py"
