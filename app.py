from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Temporary "database" (later you can use SQLite/MySQL/Postgres)
students = []

@app.route('/')
def index():
    return render_template('index.html', students=students)

@app.route('/students')
def student_list():
    return render_template('students.html', students=students)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
