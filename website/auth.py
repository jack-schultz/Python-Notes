from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged In", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect Password", category="error")
        else:
            flash("Account Does Not Exist")

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')


        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email Already in Use', category='error')
        elif len(email) < 4:
            flash('Email Must Be Greater Than 3 Characters.', category='error')
        elif len(firstname) < 2:
            flash('First Name Must Be Greater Than 1 Character.', category='error')
        elif password1 != password2:
            flash('Passwords Don\'t Match.', category='error')
        elif len(password1) < 8:
            flash('Password Must Be At Least 8 Characters.', category='error')
        else:
            new_user = User(email=email, firstname=firstname, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account Created', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)