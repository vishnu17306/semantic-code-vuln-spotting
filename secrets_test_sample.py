# --- VULNERABLE examples ---

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"  # VULNERABLE

STRIPE_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKE"  # VULNERABLE

api_key = "a1b2c3d4e5f6g7h8i9j0k1l2"  # VULNERABLE

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
fakekeydata...
-----END RSA PRIVATE KEY-----
"""  # VULNERABLE (header line)


# --- SAFE examples ---

AWS_KEY_SAFE = os.environ.get("AWS_ACCESS_KEY_ID")  # SAFE

def get_config():
    return {"timeout": 30, "retries": 3}  # SAFE
