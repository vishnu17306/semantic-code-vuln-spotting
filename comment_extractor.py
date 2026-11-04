import argparse
import io
import tokenize


def extract_inline_comments(source):
    """Return the # comments in the source as unified records.

    Uses `tokenize` because the `ast` module throws comments away.
    Consecutive full-line comments are merged into one record, so a
    multi-line note is read as a single piece of text. Trailing comments
    (after code on the same line) stay separate.
    Each record has the same shape that commit messages and PR notes
    use: text, source_type, location, raw_context.
    """
    source_lines = source.splitlines()
    found = []  # (line_no, text, is_full_line)

    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                line_no = tok.start[0]
                text = tok.string.lstrip("#").strip()
                if not text:
                    continue
                full_line = source_lines[line_no - 1].lstrip().startswith("#")
                found.append((line_no, text, full_line))
    except (tokenize.TokenError, IndentationError):
        # Malformed file: keep whatever we extracted before the error
        pass

    records = []
    last_line = None
    last_full = False
    for line_no, text, full_line in found:
        if full_line and last_full and last_line == line_no - 1:
            records[-1]["text"] += " " + text
        else:
            records.append({
                "text": text,
                "source_type": "inline_comment",
                "location": line_no,
                "raw_context": source_lines[line_no - 1].strip(),
            })
        last_line = line_no
        last_full = full_line
    return records


def extract_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (UnicodeDecodeError, IOError) as e:
        print(f"Skipping {filepath}: {e}")
        return []
    return extract_inline_comments(source)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract developer comments from a Python file.")
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    for r in extract_from_file(args.file):
        print(f"line {r['location']}: {r['text']}")
        print(f"    code: {r['raw_context']}\n")
