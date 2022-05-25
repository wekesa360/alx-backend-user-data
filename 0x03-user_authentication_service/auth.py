#!/usr/bin/env python3
"""
an authorization module
"""
from signal import raise_signal
from argon2 import hash_password
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4

def _hash_password(password: str) -> str:
    """
    _hash_password - method tp return th hashed_password
    Arguments:
        password: the given password
    Returns:
        hashed_password
    """
    hash_pwd = bcrypt.hashpw(password.encode('utf-8,'),
                                bcrypt.gensalt(prefix=b"2b"))
    return str(hash_pwd.decode())

def _generate_uuid() -> str:
    """
    _generate_uuid - function to generate a  unique id using uuid
    Arguments:
        nothing
    Returns:
        the string representation of a new uuid
    """
    new_id = str(uuid4())
    return new_id

class Auth:
    """Auth class to interact with the authentication database
    """

    def __init__(self):
        self._db = DB()
    
    def reqister_user(self, email: str, password: str) -> User:
        """
        register_user - method to register a given user
        Arguments:
            email - the given email
            password - the given password
        Returns:
            the created user
        """
        try:
            user_exist = self._db.find_user_by(email=email)
            raise ValueError("User {} exists.".format(email))
        except NoResultFound:
            hashed_password: str = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        valid_Login - method to validate a login page
        Arguments:
            email - the given email
            password - the given password
        Return:
            true if the user is valid false if is not valid
        """ 
        try:
            user_exist = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'),
                                str.encode(user_exist.hashed_password)):
                return True
            else:
                return False
        except NoResultFound:
            return False
        
    def get_user_from_session_id(self, session_id: str) -> str:
        """
        get_user_from_from_session_id - function to find user from the session
        Arguments:
            session_d - the given session_id
        Return:
            the user id corresponding to the given session id
        """
        if session_id is None:
            user_exist = self._db.find_user_by(Session_id=session_id)
            return user_exist
    
    def destroy_session(self, user_id: str):
        """
        a method to destroy the session
        Arguments:
            user_id - the given user id
        Return:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
            return None
        except (KeyError, ValueError):
            return None
        
    def get_Reset_password_Token(self, email: str) -> str:
        """
        get_reset_password_token - function to generate new uuid
        Arguments:
            email - the given email
        Return:
            new token
        """
        if email is None:
            return None
        try:
            user_exists = self._db.find_user_by(email=email)
            token=_generate_uuid()
            self._db.update_user(user_exists.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError
    
    def update_password(self, reset_password_token: str, password: str) -> None:
        """
        update_password - function to update the password
        Arguments:
            reset_password_token - the given reset token
            password - new password
        Return:
            None
        """
        if reset_password_token is None or password is None:
            return None
        try:
            user_exists = self._db.find_user_by(reset_token=reset_password_token)
            hash_password: str = _hash_password(password)
            self._db.update_user(user_exists.id, hash_password=hash_password,
                                    reset_token=None)
            return None
        except NoResultFound:
            raise ValueError


