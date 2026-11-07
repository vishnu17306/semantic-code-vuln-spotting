# Developer Comment Triage + Vulnerability Scanner

A Python tool that scans a codebase and reports what needs attention, sorted by severity (critical, high, medium, low), with a short suggested next step for each item.

It reads three kinds of evidence:

- developer comments in code (TODO, FIXME, notes about bugs and cleanup)
- git commit messages
- code patterns that look like vulnerabilities (SQL injection, command injection, hardcoded secrets, path traversal)

The focus of the project is understanding what developers write in natural language. The vulnerability scanner is a supporting layer: when a comment and a scanner finding are on neighbouring lines, the report links them.

## Quick start

    python3 -m venv venv
    source venv/bin/activate
    pip install pytest datasets pandas scikit-learn
    python3 triage.py triage_demo --no-commits

`triage.py` itself needs only the standard library. The other packages are for the tests and the experiments.

## Usage

    python3 triage.py <folder>                       # scan a folder and its git history
    python3 triage.py <folder> --min-severity high   # hide lower severities
    python3 triage.py <folder> --format json         # machine-readable output
    python3 triage.py <folder> --no-commits          # skip git history

The individual tools also work on their own:

    python3 scanner.py --file app.py --checks sqli,cmdi,secrets,pathtraversal --format sarif
    python3 severity_classifier.py --file app.py
    python3 commit_extractor.py

Run the tests with `python3 -m pytest -v`.

## How it works

1. `comment_extractor.py` pulls every `#` comment out of a Python file using `tokenize` (the `ast` module discards comments) and merges consecutive comment lines into one note.
2. `commit_extractor.py` reads commit messages from `git log` in the same record format.
3. `severity_classifier.py` classifies each note with keyword and marker rules and attaches a category and a short suggestion.
4. `scanner.py` finds vulnerabilities by walking the syntax tree and tracking where unsafe data flows (taint tracking). It reports in text or SARIF.
5. `triage.py` combines all of it into one severity-sorted report.

## Evaluation

**Bug reports.** 88,682 real Eclipse and Mozilla bug reports with Bugzilla severity labels, mapped to four levels. Fixed 80/20 split.

| Method | Macro-F1 | Accuracy |
|---|---|---|
| Keyword rules | 0.267 | 72% |
| TF-IDF + logistic regression | 0.466 | 66% |

**Code comments.** A hand-labeled gold set of 150 comments sampled from Python packages (pandas, scipy, scikit-learn and others), labeled critical, high, medium, low or none. 118 of them are real issues.

| Method | Macro-F1 | Accuracy |
|---|---|---|
| Keyword rules | 0.575 | 61.0% |
| TF-IDF model trained on bug reports | 0.269 | 29.7% |
| Always answer "low" | 0.261 | 64.4% |

For the question "is this comment an issue at all?", the keyword rules reach precision 0.93 and recall 0.64.

**Findings.** The model trained on bug reports beats the keyword rules on bug reports but loses on code comments, so it does not transfer. That is why `triage.py` uses the keyword rules.

## Limitations

- The keyword rules miss about a third of real issues and cannot read negation or tense ("this is NOT a security issue" is still flagged, and so is "no longer crashes").
- The gold set was labeled by one person using a written rubric, with AI assistance, and has not yet been checked by an independent second labeler.
- The gold set has no critical examples and only 17 high ones, so the tool's performance on urgent comments is not measured.
- Commit messages mostly describe work that is already done, so those findings are hints.
- Python only. Pull request descriptions are not read.
- The path traversal detector does not recognize sanitization (a validated path is still flagged), does not follow values returned by function calls, and does not cover `async def` handlers.

## Data

- Bugzilla Eclipse bug reports: `AliArshad/Bugzilla_Eclipse_Bug_Reports_Dataset` on Hugging Face
- CVEFixes (used to choose the path traversal detector): `DetectVul/CVEFixes` on Hugging Face
