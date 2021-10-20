from flask import Flask, url_for, jsonify
from flask import render_template,request,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash,check_password_hash
import os

from datetime import datetime
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///progress.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False,unique=True)
    password = db.Column(db.String(16))
    minutes = db.Column(db.Integer,default=0)
    level = db.Column(db.Integer,default=1)
    ex = db.Column(db.Integer,default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

require_ex = [10,40,50,60,80] + [i for i in range(120,5740,60)]

@app.route("/", methods=["GET", "POST"])
def top():
    if request.method == "GET":
        if current_user.is_anonymous:
            return redirect('/login')
        req = require_ex[current_user.level-1] - current_user.ex
        return render_template('top.html', user=current_user,req=req)
    else:
        user = User.query.filter_by(username=current_user.username).first()
        m = request.form.get('m')
        h = request.form.get('h')
        h = int(h)
        m = int(m)
        user.minutes += (h*60 + m)
        user.ex += (h*60 + m)
        while True:
            if user.ex >= require_ex[user.level-1]:
                user.level += 1
                user.ex = user.ex - require_ex[user.level-1]
            else:
                break
        db.session.commit()
        req = require_ex[user.level-1] - user.ex
        return render_template('top.html', req=req,user=current_user)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        user = User(username=username,
                    password=generate_password_hash(password, method='sha256'))
        db.session.add(user)
        db.session.commit()

        return redirect('/login')
    else:
        return render_template('signup.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(
            username=username).first()  # 見つからなかった場合の例外処理も追加したい
        #print(user.ex,user.minutes,user.level,user.username,user.password)
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('top'))

    else:
        return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route("/user/<int:id>/delete",methods=["GET"])
@login_required
def delete_user(id):
  status_code = 200
  response = {
    'message': ''
    }

  try:
    db.session.query(User).filter(User.id==id).delete()
    db.session.commit()

  except Exception as err:
    db.session.rollback()
    status_code = 500
    response['message'] = 'db error'

  else:
    response['message'] = 'Successfully Delete User'

  finally:
    db.session.close()
    return redirect('/')


if __name__ == '__main__':
    app.run()
