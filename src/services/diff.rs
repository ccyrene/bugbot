//! Unified-diff parser — just enough to map each added line back to its line
//! number in the post-change file, so inline comments land correctly. Ported
//! from the Python `services/diff.py`; no third-party diff lib by design.

use std::sync::LazyLock;

use globset::{Glob, GlobSetBuilder};
use regex::Regex;

static FILE_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^diff --git a/(.+?) b/(.+?)$").expect("file header re"));

static HUNK_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").expect("hunk header re")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub new_lineno: Option<u32>,
    pub old_lineno: Option<u32>,
    pub kind: char, // '+', '-', ' '
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct DiffHunk {
    pub new_start: u32,
    pub new_count: u32,
    pub old_start: u32,
    pub old_count: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, Default)]
pub struct FileDiff {
    pub old_path: String,
    pub new_path: String,
    pub is_new: bool,
    pub is_deleted: bool,
    pub is_binary: bool,
    pub hunks: Vec<DiffHunk>,
}

impl FileDiff {
    fn new(old_path: String, new_path: String) -> Self {
        FileDiff {
            old_path,
            new_path,
            ..Default::default()
        }
    }

    /// The path to anchor comments / scan against (post-change, unless this is
    /// a deletion).
    pub fn path(&self) -> &str {
        if self.is_deleted {
            &self.old_path
        } else {
            &self.new_path
        }
    }

    pub fn added_line_numbers(&self) -> Vec<u32> {
        self.hunks
            .iter()
            .flat_map(|h| h.lines.iter())
            .filter(|l| l.kind == '+')
            .filter_map(|l| l.new_lineno)
            .collect()
    }

    /// (new_lineno, content) for every added (`+`) line.
    pub fn added_lines(&self) -> Vec<(u32, &str)> {
        self.hunks
            .iter()
            .flat_map(|h| h.lines.iter())
            .filter(|l| l.kind == '+')
            .filter_map(|l| l.new_lineno.map(|n| (n, l.content.as_str())))
            .collect()
    }
}

fn strip_prefix(path: &str) -> String {
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
        .to_string()
}

pub fn parse_unified_diff(diff: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    // Index of the hunk currently being filled within `current`.
    let mut in_hunk = false;
    let mut new_lineno: u32 = 0;
    let mut old_lineno: u32 = 0;

    for raw in diff.lines() {
        // --- file header ---
        if let Some(caps) = FILE_HEADER_RE.captures(raw) {
            if let Some(done) = current.take() {
                files.push(done);
            }
            current = Some(FileDiff::new(
                strip_prefix(&caps[1]),
                strip_prefix(&caps[2]),
            ));
            in_hunk = false;
            continue;
        }

        let Some(file) = current.as_mut() else {
            continue;
        };

        if raw.starts_with("new file mode") {
            file.is_new = true;
            continue;
        }
        if raw.starts_with("deleted file mode") {
            file.is_deleted = true;
            continue;
        }
        if raw.starts_with("Binary files") || raw.starts_with("GIT binary patch") {
            file.is_binary = true;
            continue;
        }
        if raw.starts_with("--- ")
            || raw.starts_with("+++ ")
            || raw.starts_with("index ")
            || raw.starts_with("similarity ")
            || raw.starts_with("rename ")
        {
            continue;
        }

        // --- hunk header ---
        if let Some(caps) = HUNK_HEADER_RE.captures(raw) {
            let old_start = caps[1].parse().unwrap_or(0);
            let old_count = caps
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(1);
            let new_start = caps[3].parse().unwrap_or(0);
            let new_count = caps
                .get(4)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(1);
            file.hunks.push(DiffHunk {
                new_start,
                new_count,
                old_start,
                old_count,
                lines: Vec::new(),
            });
            in_hunk = true;
            new_lineno = new_start;
            old_lineno = old_start;
            continue;
        }

        if !in_hunk {
            continue;
        }
        let hunk = file
            .hunks
            .last_mut()
            .expect("in_hunk implies a hunk exists");

        if raw.is_empty() {
            // A bare blank line inside a hunk = a context line with empty content.
            hunk.lines.push(DiffLine {
                new_lineno: Some(new_lineno),
                old_lineno: Some(old_lineno),
                kind: ' ',
                content: String::new(),
            });
            new_lineno += 1;
            old_lineno += 1;
            continue;
        }

        let kind = raw.as_bytes()[0] as char;
        let content = raw[1..].to_string();
        match kind {
            '+' => {
                hunk.lines.push(DiffLine {
                    new_lineno: Some(new_lineno),
                    old_lineno: None,
                    kind: '+',
                    content,
                });
                new_lineno += 1;
            }
            '-' => {
                hunk.lines.push(DiffLine {
                    new_lineno: None,
                    old_lineno: Some(old_lineno),
                    kind: '-',
                    content,
                });
                old_lineno += 1;
            }
            ' ' => {
                hunk.lines.push(DiffLine {
                    new_lineno: Some(new_lineno),
                    old_lineno: Some(old_lineno),
                    kind: ' ',
                    content,
                });
                new_lineno += 1;
                old_lineno += 1;
            }
            // "\ No newline at end of file" and anything else: ignore.
            _ => {}
        }
    }

    if let Some(done) = current.take() {
        files.push(done);
    }
    files
}

/// Drop files matching any ignore glob. `*` matches across `/` (fnmatch
/// semantics), so `*.lock` matches `a/b/c.lock` and `vendor/**` matches
/// anything under `vendor/`. Invalid globs are skipped (logged).
pub fn filter_files(files: Vec<FileDiff>, ignore_globs: &[String]) -> Vec<FileDiff> {
    if ignore_globs.is_empty() {
        return files;
    }
    let mut builder = GlobSetBuilder::new();
    for g in ignore_globs {
        match Glob::new(g) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(e) => tracing::warn!("ignoring invalid glob {g:?}: {e}"),
        }
    }
    let set = match builder.build() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not build ignore globset: {e}; keeping all files");
            return files;
        }
    };
    files
        .into_iter()
        .filter(|f| !set.is_match(f.path()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
 import os
-x = 1
+x = 2
+y = 3
 print(x)
diff --git a/notes.txt b/notes.txt
new file mode 100644
--- /dev/null
+++ b/notes.txt
@@ -0,0 +1,2 @@
+hello
+world
";

    #[test]
    fn parses_two_files() {
        let files = parse_unified_diff(SAMPLE);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "src/app.py");
        assert!(files[1].is_new);
        assert_eq!(files[1].path(), "notes.txt");
    }

    #[test]
    fn added_lines_have_correct_new_numbers() {
        let files = parse_unified_diff(SAMPLE);
        // app.py: context "import os" (1), -x=1, +x=2 (2), +y=3 (3), context print (4)
        let added: Vec<(u32, &str)> = files[0].added_lines();
        assert_eq!(added, vec![(2, "x = 2"), (3, "y = 3")]);
        assert_eq!(files[0].added_line_numbers(), vec![2, 3]);
        // notes.txt new file: lines 1,2
        assert_eq!(files[1].added_line_numbers(), vec![1, 2]);
    }

    #[test]
    fn binary_marker_detected() {
        let d = "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n";
        let files = parse_unified_diff(d);
        assert!(files[0].is_binary);
    }

    #[test]
    fn filter_files_respects_globs() {
        let files = parse_unified_diff(SAMPLE);
        let globs = vec!["*.txt".to_string()];
        let kept = filter_files(files, &globs);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path(), "src/app.py");
    }

    #[test]
    fn filter_files_star_matches_across_slash() {
        let d = "diff --git a/vendor/lib/x.js b/vendor/lib/x.js\n@@ -0,0 +1,1 @@\n+code\n";
        let files = parse_unified_diff(d);
        let kept = filter_files(files, &["vendor/**".to_string()]);
        assert!(kept.is_empty());
    }
}
