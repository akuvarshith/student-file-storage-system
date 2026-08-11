import os
import mimetypes
import uuid
from functools import wraps
import smtplib
from email.mime.text import MIMEText

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import boto3
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config as BotoConfig

from config import Config
import db as database

app = Flask(__name__)
app.config.from_object(Config)

database.init_app(app)

s3_client = boto3.client(
    's3',
    region_name=app.config['S3_REGION'],
    config=BotoConfig(
        signature_version='s3v4',
        s3={
            'addressing_style': 'virtual'
        }
    )
)

reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def send_reset_email(to_email, reset_url):
    """Send the password reset link via SMTP."""
    msg = MIMEText(
        f'Click the link below to reset your password:\n\n{reset_url}\n\n'
        'This link expires in 30 minutes. If you did not request this, ignore this email.'
    )
    msg['Subject'] = 'Reset your Student File Storage password'
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to_email

    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(app.config['MAIL_DEFAULT_SENDER'], [to_email], msg.as_string())

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def allowed_file(filename):
    """Return True only if the filename has an extension in our
    explicit allow-list. Files with no extension, or an extension
    not on the list, are rejected."""
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    )


def login_required(view):
    """Decorator: redirect to the login page if no user is logged in."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get('user_id') is None:
            flash('Please log in to continue.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view


@app.before_request
def load_logged_in_user():
    """Runs before every request. If a user_id is stored in the
    session, load the full user row into g.user so templates
    (base.html) can check g.user to decide what to show in the nav."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = database.get_db()
        g.user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()


# ---------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        db = database.get_db()
        error = None

        if not name:
            error = 'Name is required.'
        elif not email:
            error = 'Email is required.'
        elif not password or len(password) < 6:
            error = 'Password must be at least 6 characters long.'

        if error is None:
            existing = db.execute(
                'SELECT id FROM users WHERE email = ?', (email,)
            ).fetchone()
            if existing is not None:
                error = f'An account with email {email} already exists.'

        if error is None:
            db.execute(
                'INSERT INTO users (name, email, password_hash) '
                'VALUES (?, ?, ?)',
                (name, email, generate_password_hash(password))
            )
            db.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))

        flash(error)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        db = database.get_db()
        error = None

        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()

        if user is None or not check_password_hash(user['password_hash'], password):
            error = 'Invalid email or password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            flash(f'Welcome back, {user["name"]}!')
            return redirect(url_for('dashboard'))

        flash(error)

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# ---------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        db = database.get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        # Same message either way — never reveal which emails are registered.
        if user is not None:
            token = reset_serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                send_reset_email(email, reset_url)
            except Exception as e:
                flash(f'Could not send reset email: {e}')
                return redirect(url_for('forgot_password'))

        flash('If that email is registered, a reset link has been sent.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = reset_serializer.loads(
            token, salt='password-reset', max_age=app.config['RESET_TOKEN_EXPIRY']
        )
    except SignatureExpired:
        flash('That reset link has expired. Please request a new one.')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('That reset link is invalid.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)

        db = database.get_db()
        db.execute('UPDATE users SET password_hash = ? WHERE email = ?',
                   (generate_password_hash(password), email))
        db.commit()
        flash('Your password has been reset. Please log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# ---------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    db = database.get_db()
    file_count = db.execute(
        'SELECT COUNT(*) AS c FROM files WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()['c']
    return render_template('dashboard.html', file_count=file_count)


# ---------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('That file type is not allowed.')
            return redirect(request.url)

        original_filename = secure_filename(file.filename)
        unique_key = (
            f"user_{session['user_id']}/"
            f"{uuid.uuid4().hex}_{original_filename}"
        )

        # Determine the file size BEFORE handing the stream to boto3.
        # Some versions of boto3/s3transfer close the underlying file
        # object once the upload finishes (this varies by Python and
        # Werkzeug version), so reading .tell() *after* upload_fileobj
        # can raise "ValueError: I/O operation on closed file." Measuring
        # first, then rewinding to the start, avoids relying on the
        # stream still being open once the upload call returns.
        file.stream.seek(0, os.SEEK_END)
        file_size = file.stream.tell()
        file.stream.seek(0)

        try:
            s3_client.upload_fileobj(
                file,
                app.config['S3_BUCKET'],
                unique_key
            )
        except (ClientError, BotoCoreError) as e:
            flash(f'Upload failed: {e}')
            return redirect(request.url)

        db = database.get_db()
        db.execute(
            'INSERT INTO files '
            '(user_id, original_filename, s3_key, file_size) '
            'VALUES (?, ?, ?, ?)',
            (session['user_id'], original_filename, unique_key, file_size)
        )
        db.commit()

        flash(f'"{original_filename}" was uploaded successfully.')
        return redirect(url_for('my_files'))

    return render_template('upload.html')


# ---------------------------------------------------------------------
# My Files
# ---------------------------------------------------------------------

@app.route('/files')
@login_required
def my_files():
    db = database.get_db()
    files = db.execute(
        'SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('files.html', files=files)


# ---------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        # Either the file doesn't exist, or it belongs to someone
        # else — either way we return 404, never leaking which.
        abort(404)

    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': app.config['S3_BUCKET'],
                'Key': file_record['s3_key'],
                'ResponseContentDisposition':
                    f'attachment; filename="{file_record["original_filename"]}"'
            },
            ExpiresIn=app.config['PRESIGNED_URL_EXPIRY']
        )
    except (ClientError, BotoCoreError) as e:
        flash(f'Could not generate a download link: {e}')
        return redirect(url_for('my_files'))

    return redirect(presigned_url)

# ---------------------------------------------------------------------
# View (Preview in Browser)
# ---------------------------------------------------------------------

PREVIEWABLE_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt'}


@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    extension = file_record['original_filename'].rsplit('.', 1)[-1].lower()
    if extension not in PREVIEWABLE_EXTENSIONS:
        flash('This file type cannot be previewed online. Please download it instead.')
        return redirect(url_for('my_files'))

    content_type, _ = mimetypes.guess_type(file_record['original_filename'])
    if content_type is None:
        content_type = 'application/octet-stream'

    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': app.config['S3_BUCKET'],
                'Key': file_record['s3_key'],
                'ResponseContentDisposition':
                    f'inline; filename="{file_record["original_filename"]}"',
                'ResponseContentType': content_type
            },
            ExpiresIn=app.config['PRESIGNED_URL_EXPIRY']
        )
    except (ClientError, BotoCoreError) as e:
        flash(f'Could not generate a preview link: {e}')
        return redirect(url_for('my_files'))

    return redirect(presigned_url)

# ---------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------

@app.errorhandler(413)
def file_too_large(e):
    flash('That file is too large. The maximum upload size is 16 MB.')
    return redirect(url_for('upload'))


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config['DEBUG']
    )
