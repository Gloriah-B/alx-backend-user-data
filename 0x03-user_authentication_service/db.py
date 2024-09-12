#!/usr/bin/env python3
"""
DB class for managing database operations.
"""

from sqlalchemy import create_engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar
from user import Base, User


DATA = ['id', 'email', 'hashed_password', 'session_id', 'reset_token']


class DB:
    """DB class to interact with the SQLite database."""

    def __init__(self):
        """Initialize a new DB instance."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """Create a new session if it does not exist."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database.

        Args:
            email (str): The email of the user.
            hashed_password (str): The hashed password of the user.

        Returns:
            User: The newly created user.

        Raises:
            ValueError: If email or hashed_password is missing.
        """
        if not email or not hashed_password:
            raise ValueError("Email and hashed password are required")

        user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(user)
        session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by specific attributes.

        Returns:
            User: The user found.

        Raises:
            NoResultFound: If no user is found matching the criteria.
            InvalidRequestError: If the query is invalid.
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
            if not user:
                raise NoResultFound("No user found matching the criteria.")
            return user
        except InvalidRequestError:
            raise InvalidRequestError("Invalid query provided.")

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update user attributes.

        Args:
            user_id (int): The ID of the user to update.

        Raises:
            ValueError: If trying to update a non-existing attribute.
        """
        user = self.find_user_by(id=user_id)
        for key, val in kwargs.items():
            if key not in DATA:
                raise ValueError(f"Invalid attribute: {key}")
            setattr(user, key, val)
        self._session.commit()
