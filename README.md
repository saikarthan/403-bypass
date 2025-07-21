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

- Browser Developer Tools
- cURL commands
- Burp Suite
- OWASP ZAP

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