from flask import render_template


def error(message, status_code):
    return render_template('inform.html', error=message, status_code=status_code), status_code