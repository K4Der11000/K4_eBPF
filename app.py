from flask import Flask, render_template_string, request, redirect, url_for, session, send_file
import os, datetime, shutil

app = Flask(__name__)
app.secret_key = 'secret'

LOG_FILE = 'logs/suspicious.log'
ARCHIVE_FOLDER = 'logs/archive'
os.makedirs(ARCHIVE_FOLDER, exist_ok=True)

USERS = {
    'admin': {'password': 'kader11000', 'role': 'admin'},
    'viewer': {'password': 'viewerpass', 'role': 'viewer'}
}

def log_event(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{datetime.datetime.now()}] {msg}\n")

index_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>eBPF Monitor - Home</title>
    <style>
        body { background-color: #0d0d0d; color: #00ff88; font-family: monospace; padding: 20px; }
        header { font-size: 2em; margin-bottom: 20px; }
        .controls { margin-bottom: 20px; }
        input[type=text] { padding: 5px; width: 200px; }
        button, a.button { background-color: #00ff88; color: black; padding: 5px 10px; margin-left: 5px; border: none; text-decoration: none; }
        pre { background-color: #111; padding: 10px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <header>kader11000 — eBPF Web Monitor</header>
    <div class="controls">
        <form method="get">
            <input type="text" name="keyword" placeholder="Search" value="{{ keyword }}">
            <button type="submit">Search</button>
            <a href="/download-log" class="button">Download Log</a>
            {% if role == 'admin' %}<a href="/admin" class="button">Admin Panel</a>{% endif %}
            <a href="/logout" class="button">Logout</a>
        </form>
    </div>
    <pre>{% for line in logs %}{{ line }}{% endfor %}</pre>
</body>
</html>
"""

login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - eBPF Monitor</title>
    <style>
        body { background-color: #000; color: #00ff88; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; }
        form { border: 1px solid #00ff88; padding: 20px; background: #111; }
        h2 { margin-bottom: 20px; }
        input { display: block; margin-bottom: 10px; padding: 5px; width: 100%; }
        button { padding: 5px 10px; background-color: #00ff88; border: none; color: black; }
    </style>
</head>
<body>
    <form method="POST">
        <h2>Login to eBPF Monitor</h2>
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

admin_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - eBPF Monitor</title>
    <style>
        body { background-color: #0f0f0f; color: #00ff88; font-family: monospace; padding: 20px; }
        header { font-size: 1.5em; margin-bottom: 20px; }
        form { margin-bottom: 20px; }
        input, button { margin: 5px; padding: 5px; }
        a { color: #00ff88; display: block; }
    </style>
</head>
<body>
    <header>Admin Control Panel</header>
    <form method="post">
        <button name="clear" value="1">Clear Log (archive)</button><br>
        <input type="text" name="pid" placeholder="PID to kill">
        <button name="stop_process" value="1">Kill Process</button>
    </form>
    <h3>Archived Logs:</h3>
    {% for name in archives %}
        <a href="/download-archive/{{ name }}">{{ name }}</a>
    {% endfor %}
    <br><a href="/">Back to Home</a>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    keyword = request.args.get('keyword', '')
    with open(LOG_FILE) as f:
        lines = f.readlines()
    if keyword:
        lines = [line for line in lines if keyword.lower() in line.lower()]
    return render_template_string(index_template, logs=lines, keyword=keyword, role=session.get('role'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        if user in USERS and USERS[user]['password'] == pwd:
            session['username'] = user
            session['role'] = USERS[user]['role']
            return redirect(url_for('index'))
    return render_template_string(login_template)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/download-log')
def download_log():
    return send_file(LOG_FILE, as_attachment=True)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        if 'clear' in request.form:
            now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            shutil.copy(LOG_FILE, f'{ARCHIVE_FOLDER}/suspicious_{now}.log')
            open(LOG_FILE, 'w').close()
        elif 'stop_process' in request.form:
            pid = request.form.get('pid')
            log_event(f"[ADMIN] Would terminate process {pid} (simulated)")
    archives = os.listdir(ARCHIVE_FOLDER)
    return render_template_string(admin_template, archives=archives)

@app.route('/download-archive/<name>')
def download_archive(name):
    return send_file(os.path.join(ARCHIVE_FOLDER, name), as_attachment=True)

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
    app.run(debug=True)
