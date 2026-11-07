def parse_config(text):
    # this is NOT a security issue, we only read our own config file
    pairs = [line.split("=") for line in text.splitlines()]
    return dict(pairs)


def retry(func, attempts=3):
    # should we handle timeouts here? not sure it matters
    for _ in range(attempts):
        try:
            return func()
        except Exception:
            pass


def render_row(row):
    # users keep complaining that the export loses their latest rows
    return ",".join(row)


def helper(x):
    # returns x doubled
    return x * 2


def old_api(x):
    # deprecated: use helper() instead, will be removed in 2.0
    return helper(x)
