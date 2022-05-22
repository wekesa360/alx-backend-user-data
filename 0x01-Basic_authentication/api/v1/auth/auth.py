#!/usr/bin/env python3
"""
a python module to create a basic authentication method
"""

from flask import request
from typing import List, TypeVar

class Auth:
    """
    class for basic authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require_Auth - a function to check the authorization path
        Arguments:
            path: the given path
            excluded_paths: the path to be excluded
        Returns:
        True if the path is not in excluded_paths
        """
        if path is None or excluded_path is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'

        for p in excluded_paths:
            if p.endswith('*'):
                pth = p[:-1]
                if path.startswith(pth):
                    return False