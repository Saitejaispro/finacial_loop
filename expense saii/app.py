from flask import Flask, render_template, request, redirect, session, url_for, flash, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = "secret_key_for_session"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('expenses.db')
    cursor = conn.cursor()
    
    # 1. Users Table (Updated with is_admin and join_date)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0,
            join_date TEXT
        )
    ''')
    
    # 2. Expenses Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            category TEXT,
            amount REAL,
            description TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # 3. Traffic Table (New)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            page_views INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# --- Helper: Track Traffic ---
def log_traffic():
    today = datetime.now().strftime("%Y-%m-%d")
    conn = sqlite3.connect('expenses.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic WHERE date = ?", (today,))
    row = cursor.fetchone()
    
    if row:
        cursor.execute("UPDATE traffic SET page_views = page_views + 1 WHERE date = ?", (today,))
    else:
        cursor.execute("INSERT INTO traffic (date, page_views) VALUES (?, 1)", (today,))
        
    conn.commit()
    conn.close()

# --- Routes ---

@app.route('/')
def home():
    log_traffic() 
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        join_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            conn = sqlite3.connect('expenses.db')
            cursor = conn.cursor()
            # Auto-Admin Logic: If 0 users exist, make this one Admin
            cursor.execute("SELECT count(*) FROM users")
            user_count = cursor.fetchone()[0]
            is_admin = 1 if user_count == 0 else 0
            
            cursor.execute("INSERT INTO users (username, password, is_admin, join_date) VALUES (?, ?, ?, ?)", 
                           (username, hashed_pw, is_admin, join_date))
            conn.commit()
            conn.close()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except:
            flash("Username already exists.")
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('expenses.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3] 
            
            if user[3] == 1: 
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password")
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    log_traffic()
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('expenses.db')
    cursor = conn.cursor()
    
    # Get Expenses
    cursor.execute("SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC", (session['user_id'],))
    expenses = cursor.fetchall()
    
    # Get Total
    cursor.execute("SELECT SUM(amount) FROM expenses WHERE user_id = ?", (session['user_id'],))
    total = cursor.fetchone()[0] or 0
    
    # Get Chart Data
    cursor.execute("SELECT category, SUM(amount) FROM expenses WHERE user_id = ? GROUP BY category", (session['user_id'],))
    data = cursor.fetchall()
    
    conn.close()
    
    categories = [row[0] for row in data]
    amounts = [row[1] for row in data]
    
    return render_template('dashboard.html', 
                           expenses=expenses, 
                           total=total, 
                           name=session['username'],
                           categories=categories, 
                           amounts=amounts)

@app.route('/add_expense', methods=['POST'])
def add_expense():
    if 'user_id' in session:
        category = request.form['category']
        amount = request.form['amount']
        desc = request.form['description']
        date = datetime.now().strftime("%Y-%m-%d")
        
        conn = sqlite3.connect('expenses.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO expenses (user_id, date, category, amount, description) VALUES (?, ?, ?, ?, ?)",
                       (session['user_id'], date, category, amount, desc))
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

@app.route('/download')
def download_expenses():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('expenses.db')
    cursor = conn.cursor()
    cursor.execute("SELECT date, category, amount, description FROM expenses WHERE user_id = ?", (session['user_id'],))
    expenses = cursor.fetchall()
    conn.close()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Date', 'Category', 'Amount', 'Description'])
    cw.writerows(expenses)
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=my_expenses.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return "Access Denied: You are not an admin.", 403
    
    conn = sqlite3.connect('expenses.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, join_date, is_admin FROM users")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM traffic ORDER BY date DESC LIMIT 7")
    traffic_data = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM expenses")
    total_expenses = cursor.fetchone()[0]
    conn.close()
    
    return render_template('admin.html', users=users, traffic=traffic_data, total_users=total_users, total_expenses=total_expenses)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
