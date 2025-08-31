# DOCUMENT filename="app.py"
import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy #provides a toolkit for interacting with relational databases eg:SQLite
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt # Provides secure password hashing
from flask_wtf import FlaskForm # Help build secure forms with CSRF protection
from wtforms import StringField, PasswordField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, Length, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Generate a random secret key for production; replace with env var in real use
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sms.db' # Specifies that the database is a SQLite file named sms.db
db = SQLAlchemy(app) # Initializes a SQLAlchemy instance and binds it to your Flask application (app)
bcrypt = Bcrypt(app) # Initializes a Flask-Bcrypt instance and binds it to your Flask application (app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ----------------------------
# MODELS
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


# New models for courses and grades
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Teacher or admin who created the course


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    grade = db.Column(db.String(10), nullable=False)  # e.g., 'A', 'B+', etc.


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------------------
# FORMS (for validation and CSRF protection)
# ----------------------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('admin', 'Admin')],
                       default='student')
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class AddStudentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=150)])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=1, message='Age must be a positive integer')])
    submit = SubmitField('Add Student')


class EditStudentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=150)])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=1, message='Age must be a positive integer')])
    submit = SubmitField('Update Student')


class AddCourseForm(FlaskForm):
    name = StringField('Course Name', validators=[DataRequired(), Length(min=1, max=150)])
    submit = SubmitField('Add Course')


class AddGradeForm(FlaskForm):
    student_id = IntegerField('Student ID', validators=[DataRequired()])
    course_id = IntegerField('Course ID', validators=[DataRequired()])
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
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash("Account created! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {str(e)}", "danger")
    return render_template("register.html", form=form)


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login credentials", "danger")
    return render_template("login.html", form=form)


# DASHBOARD (role-based access)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == "admin":
        students = Student.query.all()
        courses = Course.query.all()
        grades = Grade.query.all()
    elif current_user.role == "teacher":
        students = Student.query.filter_by(created_by=current_user.id).all()
        courses = Course.query.filter_by(created_by=current_user.id).all()
        grades = Grade.query.join(Student).filter(Student.created_by == current_user.id).all()
    else:  # student role
        students = []  # Students can’t view student list
        courses = Course.query.all()  # Allow students to view courses
        grades = Grade.query.filter_by(student_id=current_user.id).all() if hasattr(current_user,
                                                                                    'id') else []  # Assuming students have associated student records; this needs linking
    return render_template("dashboard.html", user=current_user, students=students, courses=courses, grades=grades)


# ADD STUDENT (admin & teacher only)
@app.route('/add-student', methods=['GET', 'POST'])
@login_required
def add_student():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add students.", "danger")
        return redirect(url_for("dashboard"))

    form = AddStudentForm()
    if form.validate_on_submit():
        new_student = Student(name=form.name.data, age=form.age.data, created_by=current_user.id)
        try:
            db.session.add(new_student)
            db.session.commit()
            flash("Student added successfully!", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding student: {str(e)}", "danger")
    return render_template("add_student.html", form=form)


# EDIT STUDENT (admin & teacher only, teacher only for their students)
@app.route('/edit-student/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    student = Student.query.get_or_404(student_id)
    if current_user.role == "admin" or (current_user.role == "teacher" and student.created_by == current_user.id):
        form = EditStudentForm(obj=student)
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

    form = AddCourseForm()
    if form.validate_on_submit():
        new_course = Course(name=form.name.data, created_by=current_user.id)
        try:
            db.session.add(new_course)
            db.session.commit()
            flash("Course added successfully!", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding course: {str(e)}", "danger")
    return render_template("add_course.html", form=form)


# ADD GRADE (admin & teacher only, teacher only for their students/courses)
@app.route('/add-grade', methods=['GET', 'POST'])
@login_required
def add_grade():
    if current_user.role not in ["admin", "teacher"]:
        flash("You don’t have permission to add grades.", "danger")
        return redirect(url_for("dashboard"))

    form = AddGradeForm()
    if form.validate_on_submit():
        # Basic check if student and course exist
        student = Student.query.get(form.student_id.data)
        course = Course.query.get(form.course_id.data)
        if not student or not course:
            flash("Invalid student or course ID.", "danger")
            return render_template("add_grade.html", form=form)

        # For teachers, check ownership
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
    return render_template("add_grade.html", form=form)


# LOGOUT
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5555, debug=True)