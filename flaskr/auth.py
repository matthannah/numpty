import psycopg2.extras
import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        else:
            cursor.execute(
                "SELECT id FROM \"user\" WHERE username = %s", (username,)
            )
            print(cursor.query)
            if cursor.fetchone() is not None:
                error = 'User {} is already registered.'.format(username)

        if error is None:
            cursor.execute(
                "INSERT INTO \"user\" (username, password) VALUES (%s, %s)",
                (username, generate_password_hash(password))
            )
            print(cursor.query)
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        error = None

        cursor.execute(
            "SELECT * FROM \"user\" WHERE username = %s", (username,)
        )
        print(cursor.query)
        user = cursor.fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    cursor = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        cursor.execute(
            "SELECT * FROM \"user\" WHERE id = %s", (user_id,)
        )
        print(cursor.query)
        g.user = cursor.fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
