from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('task_manager.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        task_name TEXT NOT NULL,
                        description TEXT,
                        category TEXT,
                        priority TEXT,
                        due_date TEXT,
                        is_completed BOOLEAN DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                     (username, email, password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('tasks'))
        else:
            return 'Invalid credentials'

    return render_template('login.html')

# Display Tasks
@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('tasks.html', tasks=tasks)

# Create Task
@app.route('/create-task', methods=['POST'])
def create_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task_name = request.form['task_name']
    description = request.form['description']
    category = request.form['category']
    priority = request.form['priority']
    due_date = request.form['due_date']

    conn = get_db_connection()
    conn.execute('INSERT INTO tasks (user_id, task_name, description, category, priority, due_date) VALUES (?, ?, ?, ?, ?, ?)',
                 (session['user_id'], task_name, description, category, priority, due_date))
    conn.commit()
    conn.close()

    return redirect(url_for('tasks'))

# Delete Task
@app.route('/delete-task/<int:id>')
def delete_task(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM tasks WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    return redirect(url_for('tasks'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
