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
            'SELECT * FROM u,ser WHERE username = ?', (username)
        ).fetchone()
        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            # check_password_hash() 以相同的方式哈希提交的 密码并安全的比较哈希值。如果匹配成功，那么密码就是正确的。
            error = 'Incorrect password'

        if error is None:
            # session是一个dict，它用于储存横跨请求的值。当验证成功后，用户的 id 被储存于一个新的会话中。
            # 会话数据被储存到一个向浏览器发送的 cookie 中，在后继请求中，浏览器会返回它。 Flask 会安全对数据进行sign以防数据被篡改。
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)
    return render_template('auth/login.html')


# bp.before_app_request() 注册一个在视图函数之前运行的函数，不论URL是什么。
# load_logged_in_user 检查用户id是否已经储存在session中，并从数据库中获取用户数据
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


# 注销的时候需要把用户id从session中移除。然后load_logged_in_user就不会在后继请求中载入用户了
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# 装饰器返回一个新的视图，该视图包含了传递给装饰器的原视图。新的函数检查用户 是否已载入。
# 如果已载入，那么就继续正常执行原视图，否则就重定向到登录页面
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view
