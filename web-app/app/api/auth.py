"""Authentication API routes"""

from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..models.base import get_db
from ..models.user import User
from ..auth import authenticate_user, create_access_token, get_password_hash, get_current_active_user

router = APIRouter()


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    is_admin: bool = False


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login endpoint"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Register a new user (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    # Check if user already exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        is_admin=user_data.is_admin
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user info"""
    return current_user


@router.post("/login-form")
async def login_form(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Form-based login that redirects to dashboard"""
    user = authenticate_user(db, username, password)
    if not user:
        # Redirect back to login with error
        return RedirectResponse(url="/login?error=invalid_credentials", status_code=302)

    # Create access token
    access_token = create_access_token(data={"sub": user.username})

    # Create redirect response to dashboard
    response = RedirectResponse(url="/", status_code=302)

    # Set the token as a cookie
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=1800,  # 30 minutes
        samesite="lax"
    )

    return response


@router.post("/logout")
async def logout():
    """Logout endpoint"""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="access_token")
    return response


@router.post("/create-admin")
async def create_admin_user(db: Session = Depends(get_db)):
    """Create initial admin user (only if no users exist)"""
    user_count = db.query(User).count()
    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin user already exists"
        )

    # Create default admin user
    hashed_password = get_password_hash("admin123")
    admin_user = User(
        username="admin",
        email="admin@vuls.local",
        hashed_password=hashed_password,
        is_admin=True
    )
    db.add(admin_user)
    db.commit()

    return {"message": "Admin user created", "username": "admin", "password": "admin123"}
