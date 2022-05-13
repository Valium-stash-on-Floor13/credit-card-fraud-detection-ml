from flask import Flask, render_template, url_for, request,g, redirect,session,logging
from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from  flask_login import UserMixin, LoginManager, login_user, login_required, logout_user,current_user
import pandas as pd, numpy as np
import pickle
import csv
import os


app = Flask(__name__)
app.config['SECRET_KEY' ]=os.urandom(24)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'



# load the model from disk
filename = 'model.pkl'
clf = pickle.load(open(filename, 'rb'))




class LoginForm(FlaskForm):
	username= StringField('username', validators=[InputRequired(), Length(min=3, max=25)])
	password= StringField('password', validators=[InputRequired(), Length(min=6, max=80)])
	
class RegisterForm(FlaskForm):
	
	name= StringField('name', validators=[InputRequired(), Length(min=3, max=25)])
	username= StringField('username', validators=[InputRequired(), Length(min=3, max=25)])
	password= StringField('password', validators=[InputRequired(), Length(min=6, max=80)])


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25))
    username = db.Column(db.String(25), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))






@app.route('/main')
def main():
	return render_template('main.html')

@app.route('/about')
def about():
	return render_template('about.html')

@app.route('/demo')
def demo():
	return render_template('demo.html')

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route('/single', methods=["GET", "POST"])
def single():
	return render_template('single.html')
	
@app.route('/')
@app.route('/login', methods=["GET", "POST"])
def login():
	form= LoginForm()

	if form.validate_on_submit():
		userexists= User.query.filter_by(username= form.username.data).first()
		if userexists:
			if check_password_hash(userexists.password, form.password.data):
				login_user(userexists,  remember=True)
				return redirect(url_for('main',  name=current_user.name))
		# return '<h1 class="card" class="bg-primary text-white p-2">Invalid Credentials!</h1>'

	return render_template('index.html', form=form)
        
        
        
        
        
            
	

@app.route('/register', methods=["GET", "POST"])
def register():
	form= RegisterForm()
	if form.validate_on_submit():
		hashed_pass= generate_password_hash(form.password.data, method='sha256')
		new_user= User(name=form.name.data, username=form.username.data, password= hashed_pass)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for("login"))
	return render_template('register.html', form=form)



@app.route('/predict', methods = ["GET", "POST"])
def predict():
	if request.method == 'POST':
		if request.files:
			uploaded_file = request.files['multipleTran']
			filepath = os.path.join("uploads", uploaded_file.filename)
			uploaded_file.save(filepath)
			with open(filepath) as csv_file:
				csv_reader = csv.reader(csv_file)
				total=0
				total_fraud=0
				total_legit=0
				data=[]
				text=""
				next(csv_reader)
				for line in csv_reader:
					total+=1
					
					linex = [float(x) for x in line]
					vect = np.array(linex).reshape(1, -1)
					my_prediction = clf.predict(vect)
					
					if my_prediction:
						total_fraud+=1
						text="Fraud"
					else:
						total_legit+=1
						text="Valid"
					linex.insert(0,text)
					data.append(linex)

	return render_template('main.html', data=data,total=total, total_fraud=total_fraud, total_legit=total_legit)

@app.route('/predictsingle', methods = ["GET", "POST"])
def predictsingle():
	my_prediction=0
	if request.method == 'POST':
		if request.files:
			uploaded_file = request.files['multipleTran']
			filepath = os.path.join("uploads", uploaded_file.filename)
			uploaded_file.save(filepath)
			with open(filepath) as csv_file:
				csv_reader = csv.reader(csv_file)

				for line in csv_reader:
					linex = [float(x) for x in line]
					vect = np.array(linex).reshape(1, -1)
					my_prediction = clf.predict(vect)

					if(my_prediction):
						# Fraud Value
						message="Fraud"
						
					else:
						# Real Value
						message="Valid"
					
	return render_template('single.html',message=message)



if __name__ == '__main__':
	db.create_all()
	app.run(debug=True)

	
