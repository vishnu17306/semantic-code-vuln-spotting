# --- VULNERABLE examples ---

def get_user_v1(user_id):  # VULNERABLE
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

def get_user_v2(user_id):  # VULNERABLE
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def get_user_v3(user_id):  # VULNERABLE
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

def login_v1(username, password):  # VULNERABLE
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

def search_v1(term):  # VULNERABLE
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")


# --- SAFE examples ---

def get_user_safe_v1(user_id):  # SAFE
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def get_user_safe_v2(user_id):  # SAFE
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

def login_safe(username, password):  # SAFE
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )

def search_safe(term):  # SAFE
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{term}%",))

def static_query():  # SAFE
    cursor.execute("SELECT * FROM users")
    
# --- SCOPING TEST ---

def build_unsafe(user_id):  # VULNERABLE - taints 'query' in THIS function's scope
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def build_safe(order_id):  # SAFE - 'query' here is a DIFFERENT variable, safely parameterized
    query = "SELECT * FROM orders WHERE id = ?"
    cursor.execute(query, (order_id,))