from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required
from app.storage import get_storage
from app.auth.forms import LoginForm, RegistrationForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    storage = get_storage()

    if request.is_json:
        data = request.get_json() or {}
        username = (data.get('username') or '').strip()
        password = data.get('password')
        if not username or not password:
            return jsonify(status='error', message='Missing username or password'), 400

        user = storage.get_user_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            return jsonify(status='ok', session_token=f'session-{user.id}')

        return jsonify(status='error', message='Invalid credentials'), 401

    form = LoginForm()
    if form.validate_on_submit():
        user = storage.get_user_by_username(form.username.data.strip())
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard.index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            get_storage().create_user(form.username.data.strip(), form.password.data)
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('auth.login'))
        except ValueError as exc:
            flash(str(exc), 'danger')
    return render_template('register.html', title='Register', form=form)

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
