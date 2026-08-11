import os
from dotenv import load_dotenv

# Load variables from a .env file in the project root, if one exists.
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask's session cookie signing key. MUST be overridden in .env
    # with a long random value before deployment — see Section 9.8.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key')

    # SQLite database file lives right next to this config file.
    DATABASE = os.path.join(BASE_DIR, 'site.db')

    # S3 settings — must match the bucket you created in Part C.
    S3_BUCKET = os.environ.get('S3_BUCKET', '')
    S3_REGION = os.environ.get('S3_REGION', 'ap-south-1')

    # Reject uploads larger than 16 MB outright, before they even
    # reach our upload logic. Flask enforces this automatically.
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # Only these file extensions may be uploaded.
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'ppt', 'pptx',
        'xls', 'xlsx', 'txt', 'png', 'jpg', 'jpeg', 'zip'
    }

    # Presigned download links expire after this many seconds.
    PRESIGNED_URL_EXPIRY = 300  # 5 minutes

    # Categories a file can be organized under. Used by the upload
    # form, the "My Files" filter dropdown, and the edit-file page.
    FILE_CATEGORIES = ['Assignment', 'Notes', 'Project', 'Reference', 'Other']

    # Purely informational storage bar shown on the dashboard. This is
    # NOT enforced anywhere -- uploads are never blocked because of it.
    STORAGE_QUOTA_DISPLAY = 200 * 1024 * 1024  # 200 MB
# --- Password reset (forgot password) ---
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    RESET_TOKEN_EXPIRY = 1800  # 30 minutes

    # Session cookie hardening: JavaScript can never read the cookie,
    # and it is not sent on most cross-site requests. See Part P for
    # why SESSION_COOKIE_SECURE is deliberately NOT set here.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Whether Flask's interactive debugger and auto-reloader are on.
    # Controlled by FLASK_DEBUG in .env — MUST be "0" once deployed.
    DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'
