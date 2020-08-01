from flask import Flask, render_template, flash, url_for, redirect, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask_bootstrap import Bootstrap

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLACHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = "96f80aa1b9a84b36eca9ea80943227de4e1c1d69390b3cce6e1a633a009a21ab"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'log'

db = SQLAlchemy(app)

bootstrap = Bootstrap(app)

class data_b(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), default=False, nullable=False)
    email = db.Column(db.String(50), default=False, nullable=False)
    password = db.Column(db.String(80), default=False, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def _repr_(self):
        return 'data_b %s' % self.id


@login_manager.user_loader
def load_user(user_id):
    data_b.query.get(int(user_id))


class register(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(), Email('invalid email'), Length(min=10, max=50)])
    password = PasswordField('password', validators=[DataRequired('short username'), Length(min=10)])
    submit = SubmitField('submit')


class login(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired('wrong password')])
    remember = BooleanField('remember me')
    submit = SubmitField('submit')


class update(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired(), Email('invalid email'), Length(min=10, max=50)])
    submit = SubmitField('submit')


@app.route('/register', methods=['GET', 'POST'])
def reg():
    form = register()
    if request.method == 'GET':
        return render_template('register.html', form=form)
    else:
        user = data_b.query.filter_by(username=form.username.data).first()
        if user:
            flash('the username or email exists choose a different one')
            return redirect(url_for('reg'))
        else:
            username = form.username.data
            email = form.email.data
            password = form.password.data
            new = data_b(username=username, email=email, password=generate_password_hash(password, method='sha256'))
            db.session.add(new)
            db.session.commit()
            flash('account created successfully now login to your account')
            return redirect(url_for('log'))


@app.route('/login', methods=['GET', 'POST'])
def log():
    nxt = request.args.get('next')
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = login()

    user = data_b.query.filter_by(username=form.username.data).first()
    if user:
        if check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for(nxt))
        else:
            flash('invalid creadentials the fields may be case sensitive', 'danger')
            return redirect(url_for('log'))

    return render_template('login.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
       return render_template('home.html')


@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for('log'))
    return redirect(url_for('log'))

@app.route('/home/account', methods=['GET', 'POST'])
def profile():
   form = update()
   username = form.username.data
   email = form.email.data
   return render_template('account.html', form=form)


if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)

