# 🎓 Student Management System (SMS)

A simple **Student Management System** built with **Python (Flask)** that allows administrators, teachers, and students to manage academic records efficiently.  

**I am currently in the development phase and feel free to make your improvement suggestions on the code**

---

## 🚀 Features

- 👨‍🎓 **Student Management** – Add, update, delete, and view student records.  
- 📚 **Course Management** – Assign students to courses and track enrollment.  
- 📝 **Grades & Reports** – Teachers can record grades, and students can view their performance.  
- 🔐 **Authentication System** – Role-based login (Admin / Teacher / Student).  
- 📅 **Attendance Tracking** (optional, depending on scope).  
- 📊 **Dashboard** – Simple analytics for administrators.  

---

## 🛠️ Tech Stack

- **Backend:** [Flask](https://flask.palletsprojects.com/) (Python)  
- **Database:** SQLite (default) | MySQL/PostgreSQL (optional)  
- **Frontend:** HTML, CSS, Bootstrap, Jinja2 templates  
- **ORM:** SQLAlchemy (for database management)  

---

## 📂 Project Structure

Student-Management-System/

│── app.py # Main Flask app

│── requirements.txt # Dependencies

│── /templates # HTML templates (base.html, index.html, dashboard.html, etc.)

│── /static # CSS, JS, images

│── /instance # Local database (SQLite)

│── /models # Database models (Student, Course, User, etc.)

│── /routes # Flask route handlers

⚙️ Installation & Setup

1. **Clone the repository**
    
   git clone https://github.com/your-username/student-management-system.git
   
2. **Create a virtual environment & activate**

    python -m venv venv
    
    source venv/bin/activate   # On Linux/Mac
    
    venv\Scripts\activate      # On Windows

3. **Install dependencies**

    pip install -r requirements.txt

4. **Run the Flask app**

    python app.py

5.**Open in browser**

    http://127.0.0.1:5000/
