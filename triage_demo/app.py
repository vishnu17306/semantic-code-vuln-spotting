import os


def get_user(cursor, user_id):
    # FIXME: SQL injection here, user_id is not sanitized
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)


def read_report(name):
    # TODO: validate name, someone could read files outside the reports folder
    return open(os.path.join("reports", name)).read()


API_KEY = "abcd1234efgh5678ijkl9012"  # TODO: move this to an environment variable


def slow_search(items, wanted):
    # performance: this is O(n^2), optimize later
    return [a for a in items for b in items if a == wanted]


def cleanup_old_files():
    # cleanup: rename this function, the name is confusing
    pass
