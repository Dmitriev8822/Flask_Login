from flask import Flask, request, render_template, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'gZ6TeW@b&2@w%gc##2Y2rXe75J5rBu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager(app)

db = SQLAlchemy(app)
app.app_context().push()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    users = list()
    last_user = len(User.query.all())
    cnt = 0
    for user in User.query.all():
        users.append([user.id, user.login, cnt])
        cnt += 1

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        if user_id:
            if user_id.isdigit() and int(user_id) <= last_user:
                User.query.filter_by(id=user_id).delete()
                db.session.commit()
                print("User successfully delete.")

                return redirect(request.referrer)

            elif user_id == 'ALL':
                all_users = User.query.all()
                for user in all_users:
                    User.query.filter_by(id=user.id).delete()
                    db.session.commit()
                    print(f'User: {user.id}; successfully delete.')

                return redirect(request.referrer)
            else:
                flash("User not found.")
        else:
            flash('Field must be fill.')

    return render_template('table.html', data=users)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    login = request.form.get('login')
    password = request.form.get('password')

    print(f'SIGN IN\n[\nLogin: {login};\nPassword: {password}.\n]\n')

    if request.method == 'POST':
        if not (login and password):
            flash('Fields must be fill.')
        elif login == 'admin' and password == 'admin':
            return redirect(url_for('admin'))
        else:
            user = User.query.filter_by(login=login).first()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    print("Successfully authorized.")
                    return redirect(url_for('mpl'))
                else:
                    flash('Password incorrectly')
            else:
                flash('User not found.')

    return render_template('sign_in.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('mp')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    login = request.form.get('login')
    password = request.form.get('password')

    print(f'SIGN UP\n[\nLogin: {login};\nPassword: {password}.\n]\n')

    if request.method == 'POST':
        if not (login and password):
            flash('Fields must be fill.')
        elif User.query.filter_by(login=login).first() and login == User.query.filter_by(login=login).first().login:
            flash("Name has already been used")
        else:
            hash_psw = generate_password_hash(password)
            new_user = User(login=login, password=hash_psw)
            db.session.add(new_user)
            db.session.commit()

            print("Successfully registration.")

            return redirect(url_for('sign_in'))

    return render_template('sign_up.html')


@app.route('/')
@app.route('/mp')
def mp():
    return render_template('mp.html')


@app.route('/mpl')
@login_required
def mpl():
    return render_template('mpl.html')

@app.after_request
def redirect_singin(response):
    if response.status_code == 401:
        return redirect('sign_in')
    return response


def users_generate(quty):
    cnt = 1
    for i in range(quty):
        user_find = False
        while not user_find:
            user = f'user_{cnt}'
            if User.query.filter_by(login=user).first() and user == User.query.filter_by(login=user).first().login:
                cnt += 1
            else:
                user_find = True
                new_user = User(login=user, password='pbkdf2:sha256:600000$2zE9gr3pDWwYPn77$2b7cc45e502b8b1a2421ecbfd2e4102f72aa3c17b25b90e59f9009a618ac3209')
                db.session.add(new_user)
                db.session.commit()


if __name__ == "__main__":
    app.run()
