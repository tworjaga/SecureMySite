"""Sample vulnerable Flask application for testing."""

import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['DEBUG'] = True  # CRITICAL: Debug mode enabled
app.config['SECRET_KEY'] = 'hardcoded-secret-key-12345'  # CRITICAL: Hardcoded secret

# CRITICAL: SQL Injection vulnerability
@app.route('/user/<username>')
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: String concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return str(cursor.fetchall())

# CRITICAL: Command injection
@app.route('/run')
def run_command():
    cmd = request.args.get('cmd', '')
    # Vulnerable: os.system with user input
    os.system(cmd)
    return "Command executed"

# HIGH: XSS vulnerability
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Vulnerable: Unescaped output
    return render_template_string(f"<h1>Hello, {name}!</h1>")

# HIGH: Unsafe eval
@app.route('/calc')
def calculate():
    expr = request.args.get('expr', '0')
    # Vulnerable: eval with user input
    result = eval(expr)
    return str(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
