from wtforms import SelectMultipleField
from wtforms.widgets import ListWidget, CheckboxInput

class CourseSelectionForm(FlaskForm):
    courses = SelectMultipleField(
        'Select Courses',
        coerce=int,
        option_widget=CheckboxInput(),
        widget=ListWidget(prefix_label=False)
    )
    submit = SubmitField('Save Courses')
