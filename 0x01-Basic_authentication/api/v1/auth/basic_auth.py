#!/usr/bin/env/ python3

"""
basic authentication modules
"""
from api.v1.auth.auth import Auth
from base64 import b64decode
from typing import TypeVar, List, Tuple
from models.user import User

class BasicAuth(Auth):
    """
    base authentication module
    """
    def __init__(self) -> None:
        """
        initialize method fot BasicAuth
        """
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        method - to extract base64 authentication
        Arguments:
            authorization_header - authorization header 
        Returns:
         the base64 part of the Authorization header
        """
        if authorization_header is None:
             return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith('Basic'):
            return None
        split_auth = authorization_header.split()
        if len(split_auth) == 1:
            return None
        return split_auth[1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        function to decode Base64
        Arguments:
            base64_authorization_header - authorization header header
        Returns:
            decoded value of a Base64 string base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            d_dcd = b64decode(base64_authorization_header).decode('utf-8')
        except Exception as e:
            return None
        return d_dcd
    
    def extract_user_credentials(self,
                                    decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        extract_user_credentials - function to extract username, password
        Arguments:
           decoded_base_64_authorization_header - the given base_64_authorization
        Returns:
            the username & password
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        username_password = decoded_base64_authorization_header.split(':', 1)
        return (username_password[0], username_password[1])
    
    def user_object_from_credentials(self,
                                        user_email: str, user_pwd: str,
                                        ) -> TypeVar('User'):
        """
        user_object_from_credentials - function to return the user instance
        Arguments:
            user_email: the given user email
            user_pwd: the given user password
        Returns:
            the user instance
        """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        usr: List[TypeVar('User')]
        try:
            usr = User.search({'email': user_email})
        except Exception:
            return None
        
        if usr is None:
            return None
        for u in usr:
            if u.is_valid_password(user_pwd):
                return u
        return None
    
    def current_user(self, request=None) -> TypeVar('User'):
        """
        current_user - function to get information about current user
        """
        hdr: str = self.authorization_header(request)
        if hdr is None:
            return None
        ext_b64: str = self.extract_base64_authorization_header(hdr)
        if ext_b64 is None:
            return None
        dec_b64: str = self.decode_base64_authorization_header(ext_b64)
        if dec_b64 is None:
            return None
        email: str
        password: str 
        email, password = self.extract_user_credentials(dec_b64)
        if email is None or password is None:
            return None
        cur_usr = self.user_object_from_credentials(email, password)
        return cur_usr
        