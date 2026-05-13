from flask import Flask, render_template, request, redirect, session, Response
import mysql.connector
import pandas as pd
from reportlab.pdfgen import canvas
import io
import pickle

app = Flask(__name__)
app.secret_key = "mysecretkey"

# ---------------- MySQL Connection ----------------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root123",
    database="sql_injection_project"
)

cursor = db.cursor()

# ---------------- Load ML Model + Vectorizer (IMPORTANT PLACE) ----------------
model = pickle.load(open("sqli_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))


# ---------------- ML SQL Injection Detection Function ----------------
def detect_sqli_ml(payload):
    data = vectorizer.transform([payload])
    prediction = model.predict(data)[0]
    return prediction   # 0 = Safe, 1 = Attack


# ---------------- AUTO IP BLOCKING FUNCTIONS ----------------
def is_ip_blocked(ip):
    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=%s", (ip,))
    data = cursor.fetchone()
    if data:
        return True
    return False


def block_ip(ip):
    try:
        cursor.execute("INSERT INTO blocked_ips(ip_address) VALUES(%s)", (ip,))
        db.commit()
    except:
        pass


def count_blocked_attempts(ip):
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE ip_address=%s AND status='BLOCKED'", (ip,))
    count = cursor.fetchone()[0]
    return count


# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/register')


# ---------------- REGISTER ----------------
@app.route('/register')
def register_page():
    return render_template("register.html")


@app.route('/register_user', methods=['POST'])
def register_user():
    try:
        db.reconnect(attempts=3, delay=2)

        username = request.form['username']
        password = request.form['password']

        query = "INSERT INTO users(username, password) VALUES(%s, %s)"
        cursor.execute(query, (username, password))
        db.commit()

        return "✅ User Registered Successfully <br><a href='/login'>Go to Login</a>"

    except Exception as e:
        return f"❌ Error: {e}"


# ---------------- LOGIN ----------------
@app.route('/login')
def login_page():
    return render_template("login.html")


@app.route('/login_user', methods=['POST'])
def login_user():
    try:
        db.reconnect(attempts=3, delay=2)

        ip = request.remote_addr

        # Check if IP is blocked
        if is_ip_blocked(ip):
            return "🚫 Your IP is BLOCKED due to suspicious activity."

        username = request.form['username']
        password = request.form['password']

        query = "SELECT * FROM users WHERE username=%s AND password=%s"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()

        if user:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "❌ Invalid Login <br><a href='/login'>Try Again</a>"

    except Exception as e:
        return f"❌ Error: {e}"


# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"""
        <h2>Welcome {session['username']}</h2>

        <h3>Dashboard Menu</h3>

        <a href='/test'>Test SQL Injection Detection</a><br><br>
        <a href='/logs'>View Attack Logs</a><br><br>
        <a href='/blocked'>View Blocked IPs</a><br><br>

        <a href='/download_logs'>Download Logs Report (CSV)</a><br><br>
        <a href='/download_pdf'>Download Logs Report (PDF)</a><br><br>

        <a href='/logout'>Logout</a>
        """
    else:
        return redirect('/login')


# ---------------- SQL INJECTION TEST PAGE ----------------
@app.route('/test')
def test_page():
    if 'username' not in session:
        return redirect('/login')

    ip = request.remote_addr

    if is_ip_blocked(ip):
        return "🚫 Your IP is BLOCKED. Access Denied."

    return render_template("test_input.html")


# ---------------- CHECK INPUT (ML DETECTION) ----------------
@app.route('/check_input', methods=['POST'])
def check_input():
    if 'username' not in session:
        return redirect('/login')

    user_input = request.form['user_input']
    ip = request.remote_addr
    username = session['username']

    # If IP already blocked
    if is_ip_blocked(ip):
        return "🚫 Your IP is BLOCKED. Access denied."

    # ML Detection Result
    result = detect_sqli_ml(user_input)

    if result == 1:
        cursor.execute(
            "INSERT INTO attack_logs(ip_address, username, payload, status) VALUES(%s,%s,%s,%s)",
            (ip, username, user_input, "BLOCKED")
        )
        db.commit()

        attempts = count_blocked_attempts(ip)

        # Auto block after 3 attacks
        if attempts >= 3:
            block_ip(ip)
            return "🚫 SQL Injection detected 3 times. Your IP is now BLOCKED!"

        return f"⚠ SQL Injection Detected by ML Model! Blocked. Attempts = {attempts}/3 <br><a href='/test'>Back</a>"

    else:
        cursor.execute(
            "INSERT INTO attack_logs(ip_address, username, payload, status) VALUES(%s,%s,%s,%s)",
            (ip, username, user_input, "ALLOWED")
        )
        db.commit()

        return "✅ Safe Input Allowed by ML Model. <br><a href='/test'>Back</a>"


# ---------------- VIEW LOGS ----------------
@app.route('/logs')
def view_logs():
    if 'username' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC")
    logs = cursor.fetchall()

    output = """
    <h2>Attack Logs</h2>
    <table border='1'>
    <tr>
        <th>ID</th>
        <th>IP Address</th>
        <th>Username</th>
        <th>Payload</th>
        <th>Status</th>
        <th>Time</th>
    </tr>
    """

    for log in logs:
        output += f"""
        <tr>
            <td>{log[0]}</td>
            <td>{log[1]}</td>
            <td>{log[2]}</td>
            <td>{log[3]}</td>
            <td>{log[4]}</td>
            <td>{log[5]}</td>
        </tr>
        """

    output += "</table><br><a href='/dashboard'>Back</a>"
    return output


# ---------------- VIEW BLOCKED IPS ----------------
@app.route('/blocked')
def blocked_list():
    if 'username' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    data = cursor.fetchall()

    output = "<h2>Blocked IP Addresses</h2><table border='1'>"
    output += "<tr><th>ID</th><th>IP Address</th><th>Blocked Time</th><th>Action</th></tr>"

    for row in data:
        output += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td><a href='/unblock/{row[1]}'>Unblock</a></td>
        </tr>
        """

    output += "</table><br><a href='/dashboard'>Back</a>"
    return output


# ---------------- UNBLOCK IP ROUTE ----------------
@app.route('/unblock/<ip>')
def unblock_ip(ip):
    if 'username' not in session:
        return redirect('/login')

    cursor.execute("DELETE FROM blocked_ips WHERE ip_address=%s", (ip,))
    db.commit()

    return redirect('/blocked')


# ---------------- DOWNLOAD LOGS CSV ----------------
@app.route('/download_logs')
def download_logs():
    if 'username' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC")
    logs = cursor.fetchall()

    df = pd.DataFrame(logs, columns=["ID", "IP Address", "Username", "Payload", "Status", "Time"])
    csv_data = df.to_csv(index=False)

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=attack_logs_report.csv"}
    )


# ---------------- DOWNLOAD LOGS PDF ----------------
@app.route('/download_pdf')
def download_pdf():
    if 'username' not in session:
        return redirect('/login')

    cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC")
    logs = cursor.fetchall()

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer)

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(160, 800, "SQL Injection Attack Logs Report")

    pdf.setFont("Helvetica", 12)
    y = 760

    pdf.drawString(30, y, "ID")
    pdf.drawString(70, y, "IP Address")
    pdf.drawString(200, y, "Username")
    pdf.drawString(300, y, "Status")
    pdf.drawString(380, y, "Time")

    y -= 20

    for log in logs:
        if y < 50:
            pdf.showPage()
            pdf.setFont("Helvetica", 12)
            y = 800

        pdf.drawString(30, y, str(log[0]))
        pdf.drawString(70, y, str(log[1])[:15])
        pdf.drawString(200, y, str(log[2])[:12])
        pdf.drawString(300, y, str(log[4]))
        pdf.drawString(380, y, str(log[5])[:19])

        y -= 20

    pdf.save()
    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment;filename=attack_logs_report.pdf"}
    )


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')


# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True)