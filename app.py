import os
import logging
from flask_migrate import Migrate
from flask import Flask, render_template, redirect, url_for, request, flash
from functools import wraps
from flask import abort
from flask_sqlalchemy import SQLAlchemy# Provides a toolkit for interacting with relational databases eg: SQLite from sqlalchemy import func
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt  # Provides secure password hashing
from flask_wtf import FlaskForm  # Help build secure forms with CSRF protection
from models import Course  # import your Course model
from wtforms import StringField, PasswordField, SelectField, IntegerField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, Length, Regexp, ValidationError, EqualTo  # Help validate input automatically

app = Flask(__name__)  # Creates application called app
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Generate a random secret key for production; replace with env var in real use
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sms.db'  # Specifies that the database is a SQLite file named sms.db
app.config['WTF_CSRF_ENABLED'] = True  # Explicitly enable CSRF protection (default is True, but included for clarity)
db = SQLAlchemy(app)  # Initializes a SQLAlchemy instance and binds it to your Flask application (app)
migrate = Migrate(app, db) # Initializes migrate
bcrypt = Bcrypt(app)  # Initializes a Flask-Bcrypt instance and binds it to your Flask application (app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
logging.basicConfig(level=logging.DEBUG)


# ----------------------------
# DATABASE MODELS
# ----------------------------

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])   # <-- ADD THIS
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField("Role", choices=[("student", "Student"), ("teacher", "Teacher"), ("admin", "Admin")], validators=[DataRequired()])
    submit = SubmitField('Register')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # ✅ Link to student profile
    student_profile = db.relationship('Student', uselist=False, backref='user')

student_courses = db.Table(
    'student_courses',
    db.Column('student_id', db.Integer, db.ForeignKey('student.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True)
)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    # ✅ One-to-one course assignment
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    course = db.relationship("Course", backref="students")


class Course(db.Model):  # Ensure this class is defined
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(10), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    grade = db.Column(db.String(10), nullable=False)

class SelectCourseForm(FlaskForm):
    course = SelectField('Select Course', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Enroll')

    def __init__(self, *args, **kwargs):
        super(SelectCourseForm, self).__init__(*args, **kwargs)
        # populate the dropdown with available courses from the database
        self.course.choices = [(c.id, c.name) for c in Course.query.all()]

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------------------
# FORMS (for validation and CSRF protection)
# ----------------------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=15)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long."),
            Regexp(
                regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message="Password must include at least one uppercase, one lowercase, one number, and one special character."
            )
        ]
    )
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('admin', 'Admin')],
                       default='student')
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Please choose a different one.')


class LoginForm(FlaskForm):
    identifier = StringField("Email or Username", validators=[DataRequired(), Length(min=3, max=100)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

class AddStudentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=150)])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=1, message='Age must be a positive integer')])
    course = SelectField('Course', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Student')


class EditStudentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=150)])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=1, message='Age must be a positive integer')])
    submit = SubmitField('Update Student')


class AddCourseForm(FlaskForm):
    name = StringField("Course Name", validators=[DataRequired(), Length(min=2, max=100)])
    code = StringField("Course Code", validators=[DataRequired(), Length(min=2, max=20)])  # ✅ new field
    description = TextAreaField("Course Description", validators=[Length(max=500)])
    submit = SubmitField("Add Course")

class AddGradeForm(FlaskForm):
    student_id = SelectField('Student', coerce=int, validators=[DataRequired()])
    course_id = SelectField('Course', coerce=int, validators=[DataRequired()])
    grade = StringField('Grade', validators=[DataRequired(), Length(min=1, max=10)])
    submit = SubmitField('Add Grade')


# ----------------------------
# ROUTES
# ----------------------------

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template("index.html")  # Now renders index.html for unauthenticated users


# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # ✅ Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("⚠️ Username already exists. Please choose another one.", "danger")
            return render_template('register.html', form=form)

        # ✅ Check if email already exists
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash("⚠️ Email already registered. Please log in instead.", "danger")
            return render_template('register.html', form=form)

        # ✅ If both unique, proceed with registration
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        # ✅ Automatically create Student profile if role is "student"
        if new_user.role == "student":
            student_profile = Student(
                name=new_user.username,
                age=18,  # default or placeholder, can be updated later
                created_by=new_user.id
            )
            db.session.add(student_profile)
            db.session.commit()

        flash("✅ Your account has been created! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# LOGIN
from sqlalchemy import func

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        logging.debug(f"Login form data: {form.data}, CSRF token: {form.csrf_token.data}")
        if form.validate_on_submit():
            # ✅ Try to find user by email OR username (case-insensitive)
            user = User.query.filter(
                (func.lower(User.email) == func.lower(form.identifier.data)) |
                (func.lower(User.username) == func.lower(form.identifier.data))
            ).first()

            if user:
                try:
                    if bcrypt.check_password_hash(user.password, form.password.data):
                        login_user(user, remember=form.remember.data)
                        logging.debug(f"Login successful for user: {user.email}")
                        return redirect(url_for("dashboard"))
                    else:
                        logging.debug("Password verification failed")
                        flash("Incorrect password", "danger")
                except ValueError as e:
                    logging.error(f"Bcrypt error: {str(e)}")
                    flash(f"Authentication error: {str(e)}", "danger")
            else:
                logging.debug("User not found")
                flash("No account found with that email/username", "danger")
        else:
            logging.debug(f"Login form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {form[field].label.text}: {error}", "danger")
            return render_template("login.html", form=form)

    return render_template("login.html", form=form)

def role_required(*roles):
    """Restrict access to specific roles"""
    def wrapper(fn):
        @wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)  # Forbidden
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# DASHBOARD (role-based access)
@app.route("/dashboard")
@login_required
def dashboard():
    # Redirect based on role
    if current_user.role == "student":
        return redirect(url_for("student_dashboard"))
    elif current_user.role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    elif current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    else:
        # fallback if role is missing
        flash("Invalid role or role not assigned.", "danger")
        return redirect(url_for("logout"))

@app.route("/student/dashboard")
@role_required("student")
def student_dashboard():
    return render_template("student_dashboard.html")

@app.route("/teacher/dashboard")
@role_required("teacher")
def teacher_dashboard():
    return render_template("teacher_dashboard.html")

@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

# ADD STUDENT (admin & teacher only)
@app.route('/add-student', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add students.", "danger")
        return redirect(url_for("dashboard"))

    form = AddStudentForm()

    # ✅ Populate courses dynamically inside the request
    courses = Course.query.all()
    form.course.choices = [(c.id, c.name) for c in courses] if courses else [(0, "No courses available")]

    if form.course.choices == [(0, "No courses available")]:
        flash("No courses available. Please add a course first.", "warning")
        return redirect(url_for("add_course"))

    if request.method == 'POST':
        logging.debug(f"Add student form data: {form.data}, CSRF token: {form.csrf_token.data}")
        if form.validate_on_submit():
            new_student = Student(
                name=form.name.data,
                age=form.age.data,
                created_by=current_user.id,
                course_id=form.course.data
            )
            try:
                db.session.add(new_student)
                db.session.commit()
                flash("Student added successfully!", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding student: {str(e)}", "danger")
        else:
            logging.debug(f"Add student form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {form[field].label.text}: {error}", "danger")
            return render_template("add_student.html", form=form)

    return render_template("add_student.html", form=form)


# EDIT STUDENT (admin & teacher only, teacher only for their students)
@app.route('/edit-student/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    student = Student.query.get_or_404(student_id)
    if current_user.role == "admin" or (current_user.role == "teacher" and student.created_by == current_user.id):
        form = EditStudentForm(obj=student)
        if request.method == 'POST':
            logging.debug(f"Edit student form data: {form.data}, CSRF token: {form.csrf_token.data}")
            if form.validate_on_submit():
                student.name = form.name.data
                student.age = form.age.data
                try:
                    db.session.commit()
                    flash("Student updated successfully!", "success")
                    return redirect(url_for("dashboard"))
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error updating student: {str(e)}", "danger")
            else:
                logging.debug(f"Edit student form validation failed: {form.errors}")
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f"Error in {form[field].label.text}: {error}", "danger")
                return render_template("edit_student.html", form=form, student=student)
        return render_template("edit_student.html", form=form, student=student)
    else:
        flash("You don’t have permission to edit this student.", "danger")
        return redirect(url_for("dashboard"))


# DELETE STUDENT (admin only)
@app.route('/delete-student/<int:student_id>')
@login_required
def delete_student(student_id):
    if current_user.role != "admin":
        flash("Only admins can delete students.", "danger")
        return redirect(url_for("dashboard"))

    student = Student.query.get_or_404(student_id)
    try:
        db.session.delete(student)
        db.session.commit()
        flash("Student deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting student: {str(e)}", "danger")
    return redirect(url_for("dashboard"))


# ADD COURSE (admin & teacher only)
@app.route('/add-course', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add courses.", "danger")
        return redirect(url_for("dashboard"))

    form = AddCourseForm()  # ✅ use the right form
    if request.method == 'POST':
        logging.debug(f"Add course form data: {form.data}, CSRF token: {form.csrf_token.data}")
        if form.validate_on_submit():
            new_course = Course(
                name=form.name.data,
                code=form.code.data,
                description=form.description.data,
                created_by=current_user.id
            )
            try:
                db.session.add(new_course)
                db.session.commit()
                flash("Course added successfully!", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding course: {str(e)}", "danger")
        else:
            logging.debug(f"Add course form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {form[field].label.text}: {error}", "danger")
            return render_template("add_course.html", form=form)
    return render_template("add_course.html", form=form)

@app.route('/select-course', methods=['GET', 'POST'])
@login_required
def select_course():
    if current_user.role != "student":
        flash("Only students can select courses.", "danger")
        return redirect(url_for("dashboard"))

    # 🚫 Prevent re-selection if already chosen
    if current_user.student_profile and current_user.student_profile.course_id:
        flash("You have already selected a course. Contact admin if you need changes.", "info")
        return redirect(url_for("dashboard"))

    form = SelectCourseForm()
    form.course.choices = [(c.id, f"{c.name} ({c.code})") for c in Course.query.all()]

    if form.validate_on_submit():
        current_user.student_profile.course_id = form.course.data
        db.session.commit()
        flash("Course selected successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("select_course.html", form=form)

# ADD GRADE (admin & teacher only, teacher only for their students/courses)
@app.route('/add-grade', methods=['GET', 'POST'])
@login_required
def add_grade():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add grades.", "danger")
        return redirect(url_for("dashboard"))

    form = AddGradeForm()
    # Populate form choices in the route to avoid context issues
    if current_user.role == "admin":
        students = Student.query.all()
        courses = Course.query.all()
    else:  # teacher
        students = Student.query.filter_by(created_by=current_user.id).all()
        courses = Course.query.filter_by(created_by=current_user.id).all()

    logging.debug(f"Courses for user {current_user.id} ({current_user.role}): {[(c.id, c.name) for c in courses]}")
    logging.debug(f"Students for user {current_user.id} ({current_user.role}): {[(s.id, s.name) for s in students]}")

    form.student_id.choices = [(student.id, student.name) for student in students] if students else [
        (0, "No students available")]
    form.course_id.choices = [(course.id, course.name) for course in courses] if courses else [
        (0, "No courses available")]

    if form.course_id.choices == [(0, "No courses available")]:
        flash("No courses available to assign grades. Please add a course first.", "warning")
        return redirect(url_for("add_course"))
    if form.student_id.choices == [(0, "No students available")]:
        flash("No students available to assign grades. Please add a student first.", "warning")
        return redirect(url_for("add_student"))

    if request.method == 'POST':
        logging.debug(f"Add grade form data: {form.data}, CSRF token: {form.csrf_token.data}")
        if form.validate_on_submit():
            if form.student_id.data == 0 or form.course_id.data == 0:
                flash("Please select a valid student and course.", "danger")
                return render_template("add_grade.html", form=form)

            student = Student.query.get(form.student_id.data)
            course = Course.query.get(form.course_id.data)
            if not student or not course:
                flash("Invalid student or course ID.", "danger")
                return render_template("add_grade.html", form=form)

            if current_user.role == "teacher" and (
                    student.created_by != current_user.id or course.created_by != current_user.id):
                flash("You can only add grades for your students and courses.", "danger")
                return render_template("add_grade.html", form=form)

            new_grade = Grade(student_id=form.student_id.data, course_id=form.course_id.data, grade=form.grade.data)
            try:
                db.session.add(new_grade)
                db.session.commit()
                flash("Grade added successfully!", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding grade: {str(e)}", "danger")
        else:
            logging.debug(f"Add grade form validation failed: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"Error in {form[field].label.text}: {error}", "danger")
            return render_template("add_grade.html", form=form)
    return render_template("add_grade.html", form=form)

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            logging.error(f"Error creating database: {str(e)}")
    app.run(host='0.0.0.0', port=5555, debug=True)