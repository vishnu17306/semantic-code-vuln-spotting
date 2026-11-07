import hashlib
import subprocess


def login(db, username, password):
    # SECURITY: this query is injectable, an attacker can bypass the login
    query = f"SELECT * FROM users WHERE name = '{username}'"
    row = db.execute(query).fetchone()
    return row is not None


def hash_password(password):
    # TODO: switch to bcrypt, md5 is too weak for passwords
    return hashlib.md5(password.encode()).hexdigest()


def ping_host(host):
    # works fine now, no longer crashes on empty input
    subprocess.run("ping -c 1 " + host, shell=True)
