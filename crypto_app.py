from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
import sqlite3
import os
import hashlib
import json
import time
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = 'crypto_super_secret_key_2024'  # Weak secret key

# Database initialization
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'crypto.db')

def init_crypto_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            balance REAL DEFAULT 10000.0,
            is_admin INTEGER DEFAULT 0,
            api_key TEXT
        )''')
        
        # Transactions table
        c.execute('''CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            type TEXT,
            crypto_symbol TEXT,
            amount REAL,
            price REAL,
            timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        # Crypto prices table (simulated)
        c.execute('''CREATE TABLE crypto_prices (
            symbol TEXT PRIMARY KEY,
            price REAL,
            last_updated DATETIME
        )''')
        
        # Insert default data
        c.execute("INSERT INTO users (username, password, email, is_admin, api_key) VALUES ('admin', 'admin123', 'admin@crypto.com', 1, 'admin_api_key_123')")
        c.execute("INSERT INTO users (username, password, email, api_key) VALUES ('user1', 'user123', 'user1@crypto.com', 0, 'user_api_key_456')")
        c.execute("INSERT INTO users (username, password, email, api_key) VALUES ('trader', 'trader123', 'trader@crypto.com', 0, 'trader_api_key_789')")
        
        # Insert crypto prices
        c.execute("INSERT INTO crypto_prices (symbol, price, last_updated) VALUES ('BTC', 45000.0, datetime('now'))")
        c.execute("INSERT INTO crypto_prices (symbol, price, last_updated) VALUES ('ETH', 3200.0, datetime('now'))")
        c.execute("INSERT INTO crypto_prices (symbol, price, last_updated) VALUES ('ADA', 1.2, datetime('now'))")
        c.execute("INSERT INTO crypto_prices (symbol, price, last_updated) VALUES ('DOT', 25.0, datetime('now'))")
        
        # Feedback table
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            message TEXT,
            timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        
        conn.commit()
        conn.close()

# Vulnerable authentication function
def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    return user

# Vulnerable admin check
def is_admin(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: SQL Injection
    query = f"SELECT is_admin FROM users WHERE id = {user_id}"
    c.execute(query)
    result = c.fetchone()
    conn.close()
    return result and result[0] == 1

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[5]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULNERABLE: SQL Injection
        query = f"INSERT INTO users (username, password, email, api_key) VALUES ('{username}', '{password}', '{email}', '{secrets.token_hex(16)}')"
        try:
            c.execute(query)
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
            conn.close()
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM crypto_prices")
    crypto_prices = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', crypto_prices=crypto_prices)

@app.route('/trade', methods=['GET', 'POST'])
def trade():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        crypto_symbol = request.form['crypto_symbol']
        amount = float(request.form['amount'])
        trade_type = request.form['trade_type']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get current price
        c.execute("SELECT price FROM crypto_prices WHERE symbol = ?", (crypto_symbol,))
        price_result = c.fetchone()
        if not price_result:
            flash('Invalid cryptocurrency!', 'error')
            return redirect(url_for('trade'))
        
        price = price_result[0]
        total_cost = amount * price
        
        # Get user balance
        c.execute("SELECT balance FROM users WHERE id = ?", (session['user_id'],))
        user_balance = c.fetchone()[0]
        
        if trade_type == 'buy' and user_balance < total_cost:
            flash('Insufficient balance!', 'error')
            return redirect(url_for('trade'))
        
        # Execute trade
        if trade_type == 'buy':
            new_balance = user_balance - total_cost
            c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        else:  # sell
            new_balance = user_balance + total_cost
            c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, session['user_id']))
        
        # Record transaction
        c.execute("INSERT INTO transactions (user_id, type, crypto_symbol, amount, price, timestamp) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                 (session['user_id'], trade_type, crypto_symbol, amount, price))
        
        conn.commit()
        conn.close()
        
        flash(f'{trade_type.capitalize()} order executed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM crypto_prices")
    crypto_prices = c.fetchall()
    conn.close()
    
    return render_template('trade.html', crypto_prices=crypto_prices)

@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", (session['user_id'],))
    transactions = c.fetchall()
    conn.close()
    
    return render_template('transactions.html', transactions=transactions)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message']
        user_id = session['user_id']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO feedback (user_id, message, timestamp) VALUES (?, ?, datetime('now'))", (user_id, message))
        conn.commit()
        conn.close()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('feedback.html')

# VULNERABLE: 403 Forbidden Bypass Routes
# These routes are supposed to be admin-only but have bypass vulnerabilities

@app.route('/admin/users')
def admin_users():
    # VULNERABLE: Weak admin check that can be bypassed
    if 'user_id' not in session:
        abort(403)
    
    # VULNERABLE: Can be bypassed by manipulating session or using SQL injection
    if not is_admin(session['user_id']):
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, balance, is_admin, api_key FROM users")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>')
def admin_user_detail(user_id):
    # VULNERABLE: Same weak admin check
    if 'user_id' not in session:
        abort(403)
    
    if not is_admin(session['user_id']):
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    c.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    transactions = c.fetchall()
    conn.close()
    
    return render_template('admin_user_detail.html', user=user, transactions=transactions)

@app.route('/admin/system')
def admin_system():
    # VULNERABLE: Weak admin check
    if 'user_id' not in session:
        abort(403)
    
    if not is_admin(session['user_id']):
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM transactions")
    transaction_count = c.fetchone()[0]
    c.execute("SELECT SUM(balance) FROM users")
    total_balance = c.fetchone()[0]
    conn.close()
    
    system_info = {
        'user_count': user_count,
        'transaction_count': transaction_count,
        'total_balance': total_balance,
        'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return render_template('admin_system.html', system_info=system_info)

@app.route('/admin/feedback')
def admin_feedback():
    if 'user_id' not in session or not is_admin(session['user_id']):
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT feedback.id, users.username, feedback.message, feedback.timestamp FROM feedback JOIN users ON feedback.user_id = users.id ORDER BY feedback.timestamp DESC''')
    feedbacks = c.fetchall()
    conn.close()
    return render_template('admin_feedback.html', feedbacks=feedbacks)

# VULNERABLE: API endpoints with 403 bypass
@app.route('/api/users')
def api_users():
    # VULNERABLE: Can be bypassed by manipulating headers or using different HTTP methods
    if request.headers.get('X-Admin-Key') != 'admin_secret_key_2024':
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, balance FROM users")
    users = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'balance': user[3]
    } for user in users])

@app.route('/api/user/<int:user_id>')
def api_user_detail(user_id):
    # VULNERABLE: Weak authentication
    if request.headers.get('X-API-Key') not in ['admin_api_key_123', 'user_api_key_456', 'trader_api_key_789']:
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        abort(404)
    
    return jsonify({
        'id': user[0],
        'username': user[1],
        'email': user[2],
        'balance': user[4],
        'is_admin': bool(user[5]),
        'api_key': user[6]
    })

@app.route('/api/transactions')
def api_transactions():
    # VULNERABLE: Can be bypassed by using specific user agents or referrers
    user_agent = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    
    if 'admin' not in user_agent.lower() and 'crypto-admin' not in referrer.lower():
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 100")
    transactions = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': t[0],
        'user_id': t[1],
        'type': t[2],
        'crypto_symbol': t[3],
        'amount': t[4],
        'price': t[5],
        'timestamp': t[6]
    } for t in transactions])

@app.route('/api/system/status')
def api_system_status():
    # VULNERABLE: Can be bypassed by using specific IP addresses or request patterns
    client_ip = request.remote_addr
    if client_ip not in ['127.0.0.1', '::1', 'localhost']:
        abort(403)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM transactions")
    transaction_count = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        'status': 'online',
        'users': user_count,
        'transactions': transaction_count,
        'uptime': time.time()
    })

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    results = None
    query = ''
    if request.method == 'POST':
        query = request.form['query'].strip().upper()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT symbol, price, last_updated FROM crypto_prices WHERE symbol LIKE ?", (f"%{query}%",))
        results = c.fetchall()
        conn.close()
        if not results:
            results = [('Error', 'No results found.', '')]
    return render_template('search.html', results=results, query=query)

@app.route('/api/search_crypto')
def api_search_crypto():
    query = request.args.get('query', '').strip().upper()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: SQL Injection via direct string formatting
    sql = f"SELECT symbol, price, last_updated FROM crypto_prices WHERE symbol LIKE '%{query}%'"
    try:
        c.execute(sql)
        results = c.fetchall()
        conn.close()
        return jsonify({'results': results})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)})

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/initdb')
def setup():
    init_crypto_db()
    return 'Crypto database initialized!'

if __name__ == '__main__':
    init_crypto_db()
    app.run(debug=True, host='0.0.0.0', port=5000) 