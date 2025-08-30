from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy # provides database integration with SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key' # used for session security
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sms.db' # configures the database to use SQLite, storing data in a file called sms.db
db = SQLAlchemy(app) # initializes the database
login_manager = LoginManager(app) # sets up user session management
login_manager.login_view = 'login' # redirects unauthenticated users to the login page


# ----------------------------
# DATABASE MODELS
# inherits from UserMixin to provide user authentication features
# ----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# it is required by Flask-Login to load a user object the database based on their user_id
# it retrieves a user record by ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------------------
# ROUTES
# ----------------------------

@app.route('/')
def home():
    return redirect(url_for('login'))


# REGISTER
# GET: Displays the registration form(register.html)
# POST: processes form data
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role", "student")

        user = User(username=username, email=email, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login credentials", "danger")
    return render_template("login.html")


# DASHBOARD (role-based access)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == "admin":
        students = Student.query.all()
    elif current_user.role == "teacher":
        students = Student.query.filter_by(created_by=current_user.id).all()
    else:  # student role
        students = []  # students can’t view list
    return render_template("dashboard.html", user=current_user, students=students)


# ADD STUDENT (admin & teacher only)
# GET: Displays the form to add a student (add_student.html).
# POST: Creates a new Student record with the provided, saves it, and redirects to the dashboard.
@app.route('/add-student', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add students.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name")
        age = request.form.get("age")
        new_student = Student(name=name, age=age, created_by=current_user.id)
        db.session.add(new_student)
        db.session.commit()
        flash("Student added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_student.html")


# DELETE STUDENT (admin only)
# Allows only admins to delete a student by ID
@app.route('/delete-student/<int:student_id>')
@login_required
def delete_student(student_id):
    if current_user.role != "admin":
        flash("Only admins can delete students.", "danger")
        return redirect(url_for("dashboard"))

    student = Student.query.get_or_404(student_id)
    db.session.delete(student)
    db.session.commit()
    flash("Student deleted successfully!", "success")
    return redirect(url_for("dashboard"))


# LOGOUT
# Logs out the current user and redirects to the login page.
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Initializes the database when the app starts
# runs the flask app in debug mode (for development only)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
