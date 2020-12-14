import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

# 这里创建了一个名称为 'auth' 的 Blueprint 。和应用对象一样， 蓝图需要知道是在哪里定义的，因此把 __name__ 作为函数的第二个参数。
# url_prefix 会添加到所有与该蓝图关联的 URL 前面。
bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = register.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'
        elif db.execute(
                'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            # fetchone() 根据查询返回一个记录行。 如果查询没有结果，则返回 None
            error = 'User {} is already register.'.format(username)

        if error is None:
            # 使用 generate_password_hash() 生成安全的哈希值并储存 到数据库中
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))
        #  flash() 用于储存在渲染模块时可以调用的信息
        flash(error)
    return render_template('auth/register.html')


@bp.route('/login', methods=('POST', 'GET',))
def login():
    if request.method == 'POST':
        username = register.form['username']
        password = register.form['password']
        error = None
        db = get_db()
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username)
        ).fetchone()
        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)
    return render_template('auth/login.html')