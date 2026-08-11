import os
import mimetypes
import uuid
import secrets
from datetime import datetime, timedelta
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
        'SELECT COUNT(*) AS c FROM files WHERE user_id = ? AND deleted_at IS NULL',
        (session['user_id'],)
    ).fetchone()['c']

    storage_used = db.execute(
        'SELECT COALESCE(SUM(file_size), 0) AS total FROM files '
        'WHERE user_id = ? AND deleted_at IS NULL',
        (session['user_id'],)
    ).fetchone()['total']

    category_breakdown = db.execute(
        'SELECT category, COUNT(*) AS c FROM files '
        'WHERE user_id = ? AND deleted_at IS NULL '
        'GROUP BY category ORDER BY c DESC',
        (session['user_id'],)
    ).fetchall()

    quota = app.config['STORAGE_QUOTA_DISPLAY']
    storage_percent = min(100, round((storage_used / quota) * 100, 1)) if quota else 0

    return render_template(
        'dashboard.html',
        file_count=file_count,
        storage_used=storage_used,
        storage_quota=quota,
        storage_percent=storage_percent,
        category_breakdown=category_breakdown
    )


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

        category = request.form.get('category', 'Other')
        if category not in app.config['FILE_CATEGORIES']:
            category = 'Other'

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
            '(user_id, original_filename, s3_key, file_size, category) '
            'VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], original_filename, unique_key, file_size, category)
        )
        db.commit()

        flash(f'"{original_filename}" was uploaded successfully.')
        return redirect(url_for('my_files'))

    return render_template('upload.html', categories=app.config['FILE_CATEGORIES'])


# ---------------------------------------------------------------------
# My Files
# ---------------------------------------------------------------------

SORT_OPTIONS = {
    'newest': 'upload_date DESC',
    'oldest': 'upload_date ASC',
    'name': 'original_filename COLLATE NOCASE ASC',
    'size': 'file_size DESC',
}


@app.route('/files')
@login_required
def my_files():
    db = database.get_db()

    q = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    ext = request.args.get('ext', '').strip().lower()
    favorites_only = request.args.get('favorites') == '1'
    sort = request.args.get('sort', 'newest')
    if sort not in SORT_OPTIONS:
        sort = 'newest'

    query = 'SELECT * FROM files WHERE user_id = ? AND deleted_at IS NULL'
    params = [session['user_id']]

    if q:
        query += ' AND original_filename LIKE ?'
        params.append(f'%{q}%')
    if category:
        query += ' AND category = ?'
        params.append(category)
    if ext:
        query += ' AND LOWER(original_filename) LIKE ?'
        params.append(f'%.{ext}')
    if favorites_only:
        query += ' AND is_favorite = 1'

    query += ' ORDER BY ' + SORT_OPTIONS[sort]

    files = db.execute(query, params).fetchall()
    return render_template(
        'files.html',
        files=files,
        categories=app.config['FILE_CATEGORIES'],
        q=q, category=category, ext=ext,
        favorites_only=favorites_only, sort=sort
    )


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
# Favorites
# ---------------------------------------------------------------------

@app.route('/files/<int:file_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    new_value = 0 if file_record['is_favorite'] else 1
    db.execute('UPDATE files SET is_favorite = ? WHERE id = ?', (new_value, file_id))
    db.commit()

    # Bounce back to wherever the star was clicked from (e.g. "My
    # Files" with an active search/filter still in the query string).
    return redirect(request.referrer or url_for('my_files'))


# ---------------------------------------------------------------------
# Edit (rename + recategorize)
# ---------------------------------------------------------------------

@app.route('/files/<int:file_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    if request.method == 'POST':
        new_category = request.form.get('category', 'Other')
        original_ext = file_record['original_filename'].rsplit('.', 1)[-1].lower()
        new_name = secure_filename(request.form.get('filename', '').strip())

        error = None
        if not new_name:
            error = 'Please enter a valid file name.'
        elif '.' not in new_name or new_name.rsplit('.', 1)[-1].lower() != original_ext:
            # The S3 object and its content-type never change on rename,
            # so we don't allow the extension to change either -- that
            # keeps "View" and "Download" working correctly afterwards.
            error = f"The file type can't be changed \u2014 the name must still end in .{original_ext}."
        elif new_category not in app.config['FILE_CATEGORIES']:
            error = 'Please choose a valid category.'

        if error is None:
            db.execute(
                'UPDATE files SET original_filename = ?, category = ? WHERE id = ?',
                (new_name, new_category, file_id)
            )
            db.commit()
            flash('File updated.')
            return redirect(url_for('my_files'))

        flash(error)

    return render_template(
        'edit.html', file=file_record, categories=app.config['FILE_CATEGORIES']
    )


# ---------------------------------------------------------------------
# Trash (soft delete / restore / permanent delete)
# ---------------------------------------------------------------------

@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    db.execute('UPDATE files SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?', (file_id,))
    db.commit()
    flash(f'"{file_record["original_filename"]}" was moved to Trash.')
    return redirect(url_for('my_files'))


@app.route('/trash')
@login_required
def trash():
    db = database.get_db()
    files = db.execute(
        'SELECT * FROM files WHERE user_id = ? AND deleted_at IS NOT NULL '
        'ORDER BY deleted_at DESC',
        (session['user_id'],)
    ).fetchall()
    return render_template('trash.html', files=files)


@app.route('/files/<int:file_id>/restore', methods=['POST'])
@login_required
def restore_file(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    db.execute('UPDATE files SET deleted_at = NULL WHERE id = ?', (file_id,))
    db.commit()
    flash(f'"{file_record["original_filename"]}" was restored.')
    return redirect(url_for('trash'))


@app.route('/files/<int:file_id>/purge', methods=['POST'])
@login_required
def purge_file(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    try:
        s3_client.delete_object(
            Bucket=app.config['S3_BUCKET'],
            Key=file_record['s3_key']
        )
    except (ClientError, BotoCoreError) as e:
        flash(f'Could not delete the file from storage: {e}')
        return redirect(url_for('trash'))

    # Deleting the row also deletes any of its share links, because
    # shares.file_id has ON DELETE CASCADE (and db.py turns on
    # PRAGMA foreign_keys, so SQLite actually enforces it).
    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
    db.commit()
    flash(f'"{file_record["original_filename"]}" was permanently deleted.')
    return redirect(url_for('trash'))


# ---------------------------------------------------------------------
# Sharing
# ---------------------------------------------------------------------

SHARE_EXPIRY_CHOICES = {
    '1h': timedelta(hours=1),
    '1d': timedelta(days=1),
    '7d': timedelta(days=7),
    'never': None,
}


def _now_str():
    """UTC 'now' formatted the same way SQLite writes CURRENT_TIMESTAMP
    ('YYYY-MM-DD HH:MM:SS'), so it can be bound as a plain string and
    compared directly against TIMESTAMP columns. We deliberately never
    bind a raw Python datetime object as a query parameter here --
    that relies on sqlite3's default datetime adapter, which is
    deprecated as of Python 3.12."""
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


@app.route('/files/<int:file_id>/share', methods=['GET', 'POST'])
@login_required
def manage_share(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    if request.method == 'POST':
        choice = request.form.get('expires_in', '7d')
        delta = SHARE_EXPIRY_CHOICES.get(choice, SHARE_EXPIRY_CHOICES['7d'])
        expires_at = (datetime.utcnow() + delta).strftime('%Y-%m-%d %H:%M:%S') if delta else None
        token = secrets.token_urlsafe(32)

        db.execute(
            'INSERT INTO shares (file_id, token, created_by, expires_at) '
            'VALUES (?, ?, ?, ?)',
            (file_id, token, session['user_id'], expires_at)
        )
        db.commit()
        flash('Share link created.')
        return redirect(url_for('manage_share', file_id=file_id))

    active_share = db.execute(
        'SELECT * FROM shares WHERE file_id = ? AND revoked = 0 '
        'AND (expires_at IS NULL OR expires_at > ?) '
        'ORDER BY created_at DESC LIMIT 1',
        (file_id, _now_str())
    ).fetchone()

    share_url = None
    if active_share is not None:
        share_url = url_for('shared_file', token=active_share['token'], _external=True)

    return render_template(
        'share.html', file=file_record, active_share=active_share, share_url=share_url
    )


@app.route('/files/<int:file_id>/share/revoke', methods=['POST'])
@login_required
def revoke_share(file_id):
    db = database.get_db()
    file_record = db.execute(
        'SELECT id FROM files WHERE id = ? AND user_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if file_record is None:
        abort(404)

    db.execute('UPDATE shares SET revoked = 1 WHERE file_id = ? AND revoked = 0', (file_id,))
    db.commit()
    flash('Share link revoked.')
    return redirect(url_for('manage_share', file_id=file_id))


def _get_valid_share(token):
    """Look up a share by token, joined with its file. Returns None
    unless the share exists, is not revoked, has not expired, AND its
    file is not sitting in Trash. (If the owner restores the file, a
    previously-created link becomes valid again automatically.)"""
    db = database.get_db()
    return db.execute(
        'SELECT shares.id AS share_id, shares.token, shares.expires_at, '
        '       shares.access_count, '
        '       files.id AS file_id, files.original_filename, '
        '       files.s3_key, files.file_size '
        'FROM shares JOIN files ON files.id = shares.file_id '
        'WHERE shares.token = ? AND shares.revoked = 0 '
        'AND files.deleted_at IS NULL '
        'AND (shares.expires_at IS NULL OR shares.expires_at > ?)',
        (token, _now_str())
    ).fetchone()


@app.route('/shared/<token>')
def shared_file(token):
    share = _get_valid_share(token)
    if share is None:
        abort(404)

    extension = share['original_filename'].rsplit('.', 1)[-1].lower()
    previewable = extension in PREVIEWABLE_EXTENSIONS
    return render_template('shared_file.html', share=share, previewable=previewable)


@app.route('/shared/<token>/download')
def shared_download(token):
    share = _get_valid_share(token)
    if share is None:
        abort(404)

    db = database.get_db()
    db.execute('UPDATE shares SET access_count = access_count + 1 WHERE id = ?', (share['share_id'],))
    db.commit()

    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': app.config['S3_BUCKET'],
                'Key': share['s3_key'],
                'ResponseContentDisposition':
                    f'attachment; filename="{share["original_filename"]}"'
            },
            ExpiresIn=app.config['PRESIGNED_URL_EXPIRY']
        )
    except (ClientError, BotoCoreError) as e:
        flash(f'Could not generate a download link: {e}')
        return redirect(url_for('shared_file', token=token))

    return redirect(presigned_url)


@app.route('/shared/<token>/view')
def shared_view(token):
    share = _get_valid_share(token)
    if share is None:
        abort(404)

    extension = share['original_filename'].rsplit('.', 1)[-1].lower()
    if extension not in PREVIEWABLE_EXTENSIONS:
        abort(404)

    content_type, _ = mimetypes.guess_type(share['original_filename'])
    if content_type is None:
        content_type = 'application/octet-stream'

    db = database.get_db()
    db.execute('UPDATE shares SET access_count = access_count + 1 WHERE id = ?', (share['share_id'],))
    db.commit()

    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': app.config['S3_BUCKET'],
                'Key': share['s3_key'],
                'ResponseContentDisposition':
                    f'inline; filename="{share["original_filename"]}"',
                'ResponseContentType': content_type
            },
            ExpiresIn=app.config['PRESIGNED_URL_EXPIRY']
        )
    except (ClientError, BotoCoreError) as e:
        flash(f'Could not generate a preview link: {e}')
        return redirect(url_for('shared_file', token=token))

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
