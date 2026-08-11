import sqlite3
import click
from flask import current_app, g


def get_db():
    """Open a new database connection for this request, if one
    isn't already open, and store it on Flask's request-scoped
    'g' object so repeated calls within the same request reuse it."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # Rows behave like dictionaries (row['email']) instead of
        # plain tuples — much easier to read in templates and routes.
        g.db.row_factory = sqlite3.Row
        # Enforce foreign key constraints (off by default in SQLite).
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request,
    if one was opened."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Run schema.sql against the database, creating fresh tables."""
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


@click.command('init-db')
def init_db_command():
    """CLI command: `flask --app app init-db`
    Wipes existing tables and creates new, empty ones."""
    init_db()
    click.echo('Initialized the database.')


def init_app(app):
    """Register database teardown and the init-db CLI command
    with the Flask application."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
