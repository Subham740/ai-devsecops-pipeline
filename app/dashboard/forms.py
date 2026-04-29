from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class ScanForm(FlaskForm):
    filename = StringField('File Name',
                          validators=[DataRequired(), Length(min=1, max=100)],
                          render_kw={"placeholder": "e.g., my_script.py"})
    code = TextAreaField('Code to Scan',
                        validators=[DataRequired()],
                        render_kw={"placeholder": "Paste your Python code here for security analysis...",
                                 "rows": 8})
    submit = SubmitField('Run Security Scan')