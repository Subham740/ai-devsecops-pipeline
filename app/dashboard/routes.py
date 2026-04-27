from flask import Blueprint, render_template
from flask_login import login_required
from app.models import Employee

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    employees = Employee.query.all()
    return render_template('dashboard.html', employees=employees)
