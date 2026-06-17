from bugbot.services.diff import filter_files, parse_unified_diff


DIFF = """diff --git a/src/app.py b/src/app.py
index 0000001..0000002 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,4 +1,6 @@
 import os
-old_password = "abc"
+# new code
+import requests
+API_KEY = "sk-or-v1-realLookingSecretValue1234567890XYZ"
 def main():
     pass
diff --git a/docs/README.md b/docs/README.md
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/docs/README.md
@@ -0,0 +1,2 @@
+# README
+hello
diff --git a/lock/yarn.lock b/lock/yarn.lock
index aaa..bbb 100644
--- a/lock/yarn.lock
+++ b/lock/yarn.lock
@@ -1 +1 @@
-old
+new
"""


def test_parse_three_files():
    files = parse_unified_diff(DIFF)
    paths = [f.path for f in files]
    assert paths == ["src/app.py", "docs/README.md", "lock/yarn.lock"]


def test_new_file_flag():
    files = parse_unified_diff(DIFF)
    assert files[1].is_new is True
    assert files[0].is_new is False


def test_added_line_numbers_map_to_new_file():
    files = parse_unified_diff(DIFF)
    app = files[0]
    added = app.added_lines()
    # The diff adds these at lines 2, 3, 4 of the NEW file.
    lines = [n for n, _ in added]
    assert lines == [2, 3, 4]
    contents = [c for _, c in added]
    assert "# new code" in contents
    assert any("sk-or-v1-" in c for c in contents)


def test_old_lines_tracked_for_deletion():
    files = parse_unified_diff(DIFF)
    app = files[0]
    deletions = [
        ln for h in app.hunks for ln in h.lines if ln.kind == "-"
    ]
    assert len(deletions) == 1
    assert deletions[0].old_lineno == 2
    assert "old_password" in deletions[0].content


def test_filter_files_by_glob():
    files = parse_unified_diff(DIFF)
    kept = filter_files(files, ["*.lock", "lock/**"])
    paths = [f.path for f in kept]
    assert "lock/yarn.lock" not in paths
    assert "src/app.py" in paths
