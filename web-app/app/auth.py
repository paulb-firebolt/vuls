"""Authentication and JWT handling"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import bcrypt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .config import settings
from .models.base import get_db
from .models.user import User

# Password hashing using Argon2
pwd_hasher = PasswordHasher()

# JWT token scheme
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash (supports both Argon2 and legacy bcrypt)"""
    # First try Argon2 (current standard)
    try:
        pwd_hasher.verify(hashed_password, plain_password)
        return True
    except (VerifyMismatchError, InvalidHashError):
        pass

    # If Argon2 fails, try bcrypt (legacy support)
    try:
        if hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$') or hashed_password.startswith('$2y$'):
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        pass

    return False


def is_bcrypt_hash(hashed_password: str) -> bool:
    """Check if a hash is a bcrypt hash"""
    return hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$') or hashed_password.startswith('$2y$')


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_hasher.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def verify_token(token: str) -> Optional[str]:
    """Verify a JWT token and return the username"""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate a user with username and password"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None

    # If user has a bcrypt hash, migrate to Argon2
    if is_bcrypt_hash(user.hashed_password):
        user.hashed_password = get_password_hash(password)
        db.commit()

    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get the current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    username = verify_token(credentials.credentials)
    if username is None:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_current_user_from_cookie(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get the current user from cookie (for web interface)"""
    token = request.cookies.get("access_token")
    if not token:
        return None

    # Remove "Bearer " prefix if present
    if token.startswith("Bearer "):
        token = token[7:]

    username = verify_token(token)
    if username is None:
        return None

    user = db.query(User).filter(User.username == username).first()
    return user


def get_current_active_user_from_cookie(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """Get the current active user from cookie (for web interface)"""
    user = get_current_user_from_cookie(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


def get_current_user_flexible(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """Get current user from either cookie or Authorization header"""
    import logging
    logger = logging.getLogger(__name__)

    user = None
    debug_info = []

    # First try cookie authentication (for web interface)
    token = request.cookies.get("access_token")
    debug_info.append(f"Cookie token: {token[:20] if token else 'None'}...")

    if token:
        # Remove "Bearer " prefix if present (the login form sets it as "Bearer {token}")
        if token.startswith("Bearer "):
            token = token[7:]
            debug_info.append("Removed Bearer prefix from cookie")

        username = verify_token(token)
        debug_info.append(f"Username from token: {username}")

        if username:
            user = db.query(User).filter(User.username == username).first()
            debug_info.append(f"User found: {user.username if user else 'None'}")

    # If cookie auth failed, try Authorization header (for API)
    if not user:
        auth_header = request.headers.get("Authorization")
        debug_info.append(f"Auth header: {auth_header[:20] if auth_header else 'None'}...")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            username = verify_token(token)
            debug_info.append(f"Username from header token: {username}")

            if username:
                user = db.query(User).filter(User.username == username).first()
                debug_info.append(f"User from header: {user.username if user else 'None'}")

    logger.info(f"Auth debug: {'; '.join(debug_info)}")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated. Debug: {'; '.join(debug_info)}"
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user


def get_current_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Get the current admin user"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user
