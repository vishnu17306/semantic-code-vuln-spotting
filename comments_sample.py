def login(user, password):
    # TODO: add rate limiting, attackers can brute force this
    query = "SELECT * FROM users WHERE name = '" + user + "'"  # FIXME: SQL injection here!
    return run(query)

def format_name(name):
    # cleanup: rename this variable later
    n = name.strip()
    return n

# BUG: crashes when the list is empty
def first_item(items):
    return items[0]
