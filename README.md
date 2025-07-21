# CryptoTrader Pro - Vulnerable Cryptocurrency Trading Platform

A deliberately vulnerable cryptocurrency trading web application designed for educational purposes to demonstrate 403-forbidden bypass techniques and other security vulnerabilities.

## 🚨 **DISCLAIMER**

This application is intentionally vulnerable and should **ONLY** be used in controlled, educational environments. Do not deploy this application in production or expose it to the internet.

## 🎯 Overview

CryptoTrader Pro is a realistic cryptocurrency trading platform that simulates a real-world application with intentional security flaws. The application demonstrates various 403-forbidden bypass techniques that attackers might use to access restricted administrative functions.

## 🏗️ Features

### User Features
- User registration and authentication
- Cryptocurrency trading (Buy/Sell)
- Real-time price tracking
- Transaction history
- Portfolio management
- Dashboard with market overview

### Admin Features (Vulnerable)
- User management
- System statistics
- Transaction monitoring
- Account details

## 🔓 403 Forbidden Bypass Vulnerabilities

### 1. SQL Injection in Admin Check

**Location:** `crypto_app.py` - `is_admin()` function
```python
def is_admin(user_id):
    conn = sqlite3.connect('crypto.db')
    c = conn.cursor()
    # VULNERABLE: SQL Injection
    query = f"SELECT is_admin FROM users WHERE id = {user_id}"
    c.execute(query)
    result = c.fetchone()
    conn.close()
    return result and result[0] == 1
```

**Exploitation:**
- Access admin pages by manipulating the user_id parameter
- Example: `http://localhost:5000/admin/users` with session manipulation

### 2. Header-Based Authentication Bypass

**Location:** `/api/users` endpoint
```python
@app.route('/api/users')
def api_users():
    # VULNERABLE: Can be bypassed by manipulating headers
    if request.headers.get('X-Admin-Key') != 'admin_secret_key_2024':
        abort(403)
```

**Exploitation:**
```bash
curl -H "X-Admin-Key: admin_secret_key_2024" http://localhost:5000/api/users
```

### 3. User Agent Bypass

**Location:** `/api/transactions` endpoint
```python
@app.route('/api/transactions')
def api_transactions():
    user_agent = request.headers.get('User-Agent', '')
    referrer = request.headers.get('Referer', '')
    
    if 'admin' not in user_agent.lower() and 'crypto-admin' not in referrer.lower():
        abort(403)
```

**Exploitation:**
```bash
curl -H "User-Agent: admin-browser" http://localhost:5000/api/transactions
```

### 4. IP Address Bypass

**Location:** `/api/system/status` endpoint
```python
@app.route('/api/system/status')
def api_system_status():
    client_ip = request.remote_addr
    if client_ip not in ['127.0.0.1', '::1', 'localhost']:
        abort(403)
```

**Exploitation:**
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:5000/api/system/status
```

### 5. API Key Bypass

**Location:** `/api/user/<user_id>` endpoint
```python
@app.route('/api/user/<int:user_id>')
def api_user_detail(user_id):
    if request.headers.get('X-API-Key') not in ['admin_api_key_123', 'user_api_key_456', 'trader_api_key_789']:
        abort(403)
```

**Exploitation:**
```bash
curl -H "X-API-Key: admin_api_key_123" http://localhost:5000/api/user/1
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip

### Installation Steps

1. **Clone or download the application**
```bash
git clone <repository-url>
cd vul_labs
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Initialize the database**
```bash
python crypto_app.py
```
The database will be automatically created with sample data.

4. **Run the application**
```bash
python crypto_app.py
```

5. **Access the application**
- Open your browser and go to `http://localhost:5000`
- Use the demo accounts provided on the login page

## 👥 Demo Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| user1 | user123 | Regular User |
| trader | trader123 | Regular User |

## 🎯 Exploitation Scenarios

### Scenario 1: Access Admin Panel
1. Login as a regular user
2. Try to access `/admin/users` - you'll get a 403 error
3. Use SQL injection or session manipulation to bypass the admin check

### Scenario 2: API Access
1. Try to access `/api/users` without proper headers
2. Add the required headers to bypass authentication
3. Explore other API endpoints with different bypass techniques

### Scenario 3: System Information
1. Attempt to access `/api/system/status` from external IP
2. Use IP spoofing techniques to bypass the IP restriction

## 🔧 Vulnerable Endpoints

### Admin Pages (403 Protected)
- `/admin/users` - User management
- `/admin/users/<id>` - User details
- `/admin/system` - System statistics

### API Endpoints (403 Protected)
- `/api/users` - List all users
- `/api/user/<id>` - Get user details
- `/api/transactions` - Get all transactions
- `/api/system/status` - System status

## 🛡️ Security Lessons

This application demonstrates several important security concepts:

1. **Input Validation**: Always validate and sanitize user inputs
2. **Authentication**: Implement proper authentication mechanisms
3. **Authorization**: Use role-based access control (RBAC)
4. **Session Management**: Secure session handling
5. **API Security**: Implement proper API authentication
6. **Header Security**: Don't rely on easily spoofable headers
7. **IP Restrictions**: IP-based restrictions can be bypassed

## 🧪 Testing Tools

### Manual Testing
- Browser Developer Tools
- cURL commands
- Burp Suite
- OWASP ZAP

### Automated Testing
- SQLMap for SQL injection testing
- Custom scripts for header manipulation
- Security scanners

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [403 Forbidden Bypass Techniques](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Authentication Bypass](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_Authentication)

## ⚠️ Responsible Disclosure

If you find additional vulnerabilities in this application, please report them responsibly. Remember that this is an educational tool designed to demonstrate security concepts.

## 📄 License

This project is for educational purposes only. Use at your own risk in controlled environments.

---

**Remember**: This application is intentionally vulnerable. Never use it in production environments or expose it to the internet. 