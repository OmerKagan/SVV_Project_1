from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_oauthlib.client import OAuth

app = Flask(__name__)
app.secret_key = '123app'

# Disable CSRF protection, otherwise CSRF token is required
app.config['WTF_CSRF_ENABLED'] = False

# Define a map containing emails and corresponding passwords
user_credentials = {
    'user1@login.com': 'password1',
    'user2@login.com': 'password2',
    'user3@login.com': 'password3'
}

# Configure Google OAuth
app.config['GOOGLE_ID'] = '942550748965-626q4fdhqc983jit0pg1ij7381skoo01.apps.googleusercontent.com'
app.config['GOOGLE_SECRET'] = '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'
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = ''
    if form.email.data == '' or form.password.data == '':
        error = 'Empty email or password!'
    if form.validate_on_submit():
        # Check credentials and authenticate user
        if authenticate_user(form.email.data, form.password.data):
            session['user'] = form.email.data
            return redirect(url_for('entry_page'))
        else:
            error = 'Invalid email or password!'
    return render_template('login.html', form=form, error=error)

@app.route('/entry-page')
def entry_page():
    if 'user' in session:
        return render_template('entry_page.html', user=session['user'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/google-login')
def google_login():
    return google.authorize(callback=url_for('google_authorized', _external=True))

@app.route('/google-authorized')
def google_authorized():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo')
    session['user'] = user_info.data['email']
    return redirect(url_for('entry_page'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

def authenticate_user(email, password):
    # Check if the email exists in the user_credentials map and if the password matches
    if email in user_credentials and user_credentials[email] == password:
        return True
    else:
        return False

if __name__ == '__main__':
    app.run(debug=True)