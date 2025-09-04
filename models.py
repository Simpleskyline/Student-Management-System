from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# User model (for authentication)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    student_profile = db.relationship('Student', backref='user', uselist=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)

    def __repr__(self):
        return f"<Course {self.name}>"

class Enrollment(db.Model):
    __tablename__ = "enrollment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="enrollments")
    course = db.relationship("Course", backref="enrollments")


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Float, nullable=False)
    out_of = db.Column(db.Float, nullable=False)

    user = db.relationship("User", backref="grades")
    course = db.relationship("Course", backref="grades")

# Student model (CRUD data)
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(100), nullable=False)
    grade = db.Column(db.String(10), nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
