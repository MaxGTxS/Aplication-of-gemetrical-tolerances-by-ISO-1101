from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, SelectField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, LoginManager, login_required, logout_user, UserMixin, current_user


#aplikacja
app = Flask(__name__)
import os
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'instance', 'users.db')}"

app.config['SECRET_KEY'] = "123"
#baza danych
db = SQLAlchemy(app)
migrate = Migrate(app,db)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25),nullable=False, unique=True)
    name = db.Column(db.String(75), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    email_preference = db.Column(db.String(50), default='powiadomienie')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    #haslo w hashu
    password_hash = db.Column(db.String(128))

@property
def password(self):
    raise AttributeError('hasła nie można odczytać')
@password.setter
def password(self, password):
    self.password_hash = generate_password_hash(password)
def verify_password(self, password):
    return check_password_hash(self.password_hash, password)

def __repr__(self):
    return f'<Users {self.name}>'

#rejestracja
class UserForm(FlaskForm):
    name=StringField("Name", validators=[DataRequired()])
    username=StringField("Username", validators=[DataRequired()])
    email =StringField("Email", validators=[DataRequired()])
    password_hash=PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Hasła muszą być identyczne')])
    password_hash2=PasswordField("Confirm Password", validators=[DataRequired()])
    email_preference = SelectField(
        '',
        choices=[('ta opcja jest na razie niedostępna ')]
    )
    submit = SubmitField("Submit")
    def validate_username(self, field):
        user = Users.query.filter_by(username=field.data).first()
        if user:
            flash("Nazwa użytkownika jest już zajęta. Wybierz inną.")
            raise ValidationError('Nazwa użytkownika jest już zajęta. Wybierz inną.')



#usuniecie z bazy danych kogos
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("Użytkownik pomyślnie usunięty")
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html", form=form, name=name, our_users=our_users)
    
    except:
        flash("Błąd z usunięciem użytkownika, spróbuj ponownie")
        return render_template("add_user.html", form=form, name=name, our_users=our_users)


             

#zmienianie danych konta
@app.route('/update/<int:id>', methods = ['GET','POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)

    if request.method == "POST":
        if form.username.data != name_to_update.username and Users.query.filter_by(username=form.username.data).first():
            flash("Nazwa użytkownika jest już zajęta. Wybierz inną.", 'error')
        if  form.email.data != name_to_update.email and Users.query.filter_by(email=form.email.data).first():
            flash("Email juz istnieje i widnieje u nas w bazie. Prawdopodobnie juz masz założone konto, zaloguj się.", 'error')   
        else:
            name_to_update.username = request.form['username']
            name_to_update.name = request.form['name']
            name_to_update.email = request.form['email']
            

            try:
                    db.session.commit()
                    flash("Profil pomyślnie zaktualizowany")
                    return render_template("update.html",
                                   form=form,
                                   name_to_update = name_to_update,
                                   id = id)
            except:
                    flash("Dane które próbujesz zmienić są juz zajęte")
                    return render_template("update.html",
                                   form=form,
                                   name_to_update = name_to_update,
                                   id = id
                                   )
    
        
    return render_template("update.html",
                                   form=form,
                                   name_to_update = name_to_update,
                                   id = id)
    
#haslo
class PasswordForm(FlaskForm):
    email=StringField("Podaj email", validators=[DataRequired()])
    password_hash = PasswordField("Podaj hasło", validators=[DataRequired()])
    submit = SubmitField("Submit")

#stworzenie klasy wtf
class NamerForm(FlaskForm):
    name=StringField("Whats your name", validators=[DataRequired()])
    submit = SubmitField("Submit")

#rejestracja z dodaniem do bazy danych
@app.route('/user/add', methods=['GET','POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            #hashing hasla
            hashed_pw = generate_password_hash(form.password_hash.data, 'pbkdf2:sha256')
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data, password_hash=hashed_pw )
            db.session.add(user)
            db.session.commit()
            flash("Dodano użytkownika pomyślnie")
        else: 
            flash("Email juz istnieje i widnieje u nas w bazie. Prawdopodobnie juz masz założone konto, zaloguj się.", 'error')   
        name = form .name.data
        form.username.data=''
        form.name.data=''
        form.email.data= ''
        form.password_hash.data=''

    our_users = Users.query.order_by(Users.date_added)
    
    return render_template("add_user.html", form=form, name=name, our_users=our_users)

#logowanie
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password =PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

#strona logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('user'))
            else:
                flash("Złe hasło")
        else:
            flash("Próba logowania nie udana, spróbuj jeszcze raz lub nie ma takiego użytkownika, zarejestruj się")
    return render_template('login.html', form=form)

#wylogowanie
@app.route('/logout', methods=['GET', 'POST'])    
@login_required
def logout():
    logout_user()
    flash("Użytkownik pomyślnie wylogowany")
    return redirect(url_for('login'))

#stworzenie strony glownej
@app.route('/')
def index():
    return render_template('index.html')

#stworzenie strony z url user na ktorej jest profil uzytkownika
@app.route('/user')
@login_required
def user():
    return render_template("user.html")

#stworzenie kolejnej strony odpowiedzialnej za wyswietlanie bledow
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

#strony z informacjami
@app.route('/wstep')
def wstep():
    return render_template('wstep.html')

@app.route('/kierunek')
def kierunek():
    return render_template('kierunek.html')

@app.route('/polozenie')
def polozenie():
    return render_template('polozenie.html')

#strony testowe
@app.route('/test_1')
@login_required
def test_1():
    return render_template('test_1.html')

@app.route('/test_2')
@login_required
def test_2():
    return render_template('test_2.html')

@app.route('/test_3')
@login_required
def test_3():
    return render_template('test_3.html')

@app.route('/test_4')
@login_required
def test_4():
    return render_template('test_4.html')

# dzialanie strony do otwarcia przez aplikacje
import webbrowser
import os
from threading import Timer

def open_browser():
    chrome_path = "C:/Program Files/Google/Chrome/Application/chrome.exe"
    if os.path.exists(chrome_path):
        webbrowser.get(f'"{chrome_path}" %s').open("http://127.0.0.1:5000/")
    else:
        webbrowser.open("http://127.0.0.1:5000/")  # fallback

if __name__ == "__main__":
    Timer(3, open_browser).start()
    app.run(host='127.0.0.1', port=5000)

