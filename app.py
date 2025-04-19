import os
import mimetypes
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# 📌 Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Ensure directories exist
os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
os.makedirs(os.path.join(basedir, 'uploads'), exist_ok=True)

# 📌 User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Hashed password
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

# ✅ Initialize DB & Create Admin User
with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(role="admin").first():
        hashed_password = generate_password_hash("admin123", method='pbkdf2:sha256')
        admin = User(username="admin", password=hashed_password, role="admin")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully!")

# 📌 Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# 📌 Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'user_dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

# 📌 Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# 📌 User Dashboard
@app.route('/user_dashboard')
def user_dashboard():
    if 'username' in session and session['role'] == 'user':
        return render_template('user_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# 📌 Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['role'] == 'admin':
        return render_template('admin_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# 📌 Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# 📌 File Upload Configuration
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 📌 Function to check allowed files
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 📌 File Upload Route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file selected!", "warning")
        return redirect(request.referrer)

    file = request.files['file']

    if file.filename == '':
        flash("No file selected!", "warning")
        return redirect(request.referrer)

    if not allowed_file(file.filename):
        flash("Invalid file type!", "danger")
        return redirect(request.referrer)

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    flash("File uploaded successfully!", "success")
    return redirect(url_for('display_file', filename=filename))

# 📌 Display Uploaded File
@app.route('/display/<filename>')
def display_file(filename):
    file_ext = filename.rsplit('.', 1)[1].lower()

    # Serve images & PDFs directly
    if file_ext in ['pdf', 'png', 'jpg', 'jpeg', 'gif']:
        return render_template('display.html', filename=filename, file_type=file_ext)

    # Use Google Docs Viewer for Word & PowerPoint files
    if file_ext in ['doc', 'docx', 'ppt', 'pptx']:
        file_url = f"{request.url_root}uploads/{filename}"
        return render_template('display.html', filename=filename, file_url=file_url, file_type='gdocs')

    # Provide a download link for unsupported formats
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# 📌 Serve Uploaded Files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ✅ FIXED DEBUG ISSUE & PORT CONFLICT
if __name__ == '__main__':
    app.run(debug=True, port=5001, use_reloader=False)
    