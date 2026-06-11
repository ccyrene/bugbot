from bugbot.libs.redact import redact


def test_redact_aws_key():
    out = redact('key = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "REDACTED" in out


def test_redact_db_url():
    out = redact("postgres://user:hunter2@db/app")
    assert "hunter2" not in out
    assert "postgres://****:****@db/app" in out


def test_redact_openrouter_key():
    out = redact("sk-or-v1-" + "a" * 40)
    assert "REDACTED" in out
    assert "a" * 40 not in out


def test_redact_pem_private_key():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = redact(pem)
    assert "MIIEpAIBAAKCAQEA" not in out
    assert "REDACTED" in out


def test_redact_password_assignment():
    out = redact('password = "MyR3alP4ssw0rd!"')
    assert "MyR3alP4ssw0rd" not in out
    assert "REDACTED" in out


def test_redact_does_not_touch_clean_text():
    out = redact("def add(x, y):\n    return x + y\n")
    assert out == "def add(x, y):\n    return x + y\n"
