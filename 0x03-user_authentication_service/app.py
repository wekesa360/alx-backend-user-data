#!/usr/bin/env python3
"""
a flask app module
"""
from flask import Flask, jsonify, redirect, request, abort
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=['GET'])
def index() -> str:
    """
    method to handle the / from URL url
    """
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=['POST'])
def register_user() -> str:
    """
    an end point to register a given number
    """
    try:
        email = request.form.get('email')
        passwrd = request.form.get('password')
    except KeyError:
        abort(400)
    
    try:
        new_usr = AUTH.reqister_user(email, passwrd)
        message = {"email": new_usr.email, "message": "user created"}
        return jsonify(message)
    except ValueError:
        return jsonify({"message": "email already registered"})
    
@app.route("/sessions", methods=['[POST'])
def login() -> str:
    """
    an endpoint for logging in to the system
    """
    try:
        eml = request.form.get('email')
        password = request.form.get('password')
        if AUTH.valid_login(eml, password):
            session_id = AUTH.create_session(eml)
            if session_id:
                out = jsonify({"email":eml, "message": "logged in"})
                out.set_cookie("session_id", session_id)
                return out
            else:
                abort(401)
        else:
            abort(401)
    except NoResultFound:
        abort(401)

@app.route('/sessions', methods=['POST'])
def logout() -> str:
    """
    end point to logout from the system
    """
    try:
        session_id = request.cookies.get('session_id')
        if session_id is None:
            abort(403)
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            msg = {"email": user.email}
            return jsonify(msg), 200
        else:
            abort(403)
    except KeyError:
        abort(403)

@app.route('/reset_password', methods=['POST'])
def get_reset_password() -> str:
    """
    an end point to get the reset password
    """
    try:
        email = request.form.get('email')
        token: str = AUTH.get_Reset_password_token
        msg = {"email": email, "reset_token": token}
        return jsonify(msg), 200
    except (KeyError, ValueError):
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """
    an endpoint to update the password
    """
    try:
        email = request.form.get('email')
        token = request.form.get('reset_token')
        password = request.form.get('new_password')
        AUTH.update_password(token, password)
        msg = {"email": email, "message": "Password updated"}
        return jsonify(msg), 200
    except (KeyError, ValueError):
        abort(403)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
