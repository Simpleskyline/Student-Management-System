from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = "supersecretkey"  # required for session & flash

# ======================
# Flask-Login Setup
# ======================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Fake "users DB" for now
users = {
    "admin@example.com": {"password": "1234", "username": "Admin"}
}

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    # Normally we'd fetch from DB, here just fake user
    for email, data in users.items():
        if email == user_id:
            return User(id=email, username=data["username"])
    return None

# ======================
# Routes
# ======================
students = []

@app.route('/')
def index():
    return render_template('index.html', students=students)

@app.route('/students')
def student_list():
    return render_template('students.html', students=students)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # You’d normally save to DB here
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        users[email] = {"username": username, "password": password}
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user_data = users.get(email)
        if user_data and user_data["password"] == password:
            user = User(id=email, username=user_data["username"])
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You’ve been logged out.", "info")
    return redirect(url_for("login"))

@app.route('/add', methods=['GET', 'POST'])
def add_student():
    if request.method == 'POST':
        name = request.form['name']
        course = request.form['course']
        grade = request.form['grade']

        students.append({
            'name': name,
            'course': course,
            'grade': grade
        })

        return redirect(url_for('student_list'))
    return render_template('add_student.html')

# Make current_user always available in templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
