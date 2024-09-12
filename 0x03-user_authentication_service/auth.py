#!/usr/bin/env python3
"""
Auth module
"""
from db import DB
from uuid import uuid4
from user import User
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hash a password for a user.

    Args:
        password (str): Password of user.

    Returns:
        bytes: Hashed password.
    """
    return hashpw(password.encode('utf-8'), gensalt())


def _generate_uuid() -> str:
    """Generate a new UUID.

    Returns:
        str: String representation of a new UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user.

        Args:
            email (str): Email of user.
            password (str): Password of user.

        Raises:
            ValueError: If user already exists.

        Returns:
            User: The registered user object.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate login credentials of a user.

        Args:
            email (str): Email of user.
            password (str): Password of user.

        Returns:
            bool: True if login is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return checkpw(password.encode('utf-8'), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session for a user.

        Args:
            email (str): Email of user.

        Returns:
            str or None: String representation of session ID, or None if
            user is not found.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get a user from a session ID.

        Args:
            session_id (str): Session ID of user.

        Returns:
            User or None: The user object if found, None otherwise.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy a session for a user.

        Args:
            user_id (int): User ID.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token for a user.

        Args:
            email (str): Email of user.

        Raises:
            ValueError: If the user is not found.

        Returns:
            str: The reset token.
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError(f"User with email {email} not found")

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password.

        Args:
            reset_token (str): Reset token of user.
            password (str): New password for user.

        Raises:
            ValueError: If reset token is invalid or user not found.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id,
                hashed_password=hashed_password,
                reset_token=None
            )
        except NoResultFound:
            raise ValueError("Invalid reset token")
