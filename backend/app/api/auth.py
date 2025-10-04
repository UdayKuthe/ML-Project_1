"""
Authentication API endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer
import logging
from datetime import datetime

from ..models.schemas import (
    UserRegistrationRequest, UserLoginRequest, TokenResponse, UserResponse,
    ErrorResponse, SuccessResponse
)
from ..utils.auth import (
    create_access_token_for_user, hash_password, validate_password, 
    validate_email, auth_manager, get_current_user
)
from ..utils.database import get_user_by_email, create_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", 
             response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED,
             responses={
                 400: {"model": ErrorResponse, "description": "Validation error"},
                 409: {"model": ErrorResponse, "description": "User already exists"}
             })
async def register_user(user_data: UserRegistrationRequest):
    """
    Register a new user
    
    - **email**: Valid email address
    - **full_name**: User's full name
    - **password**: Strong password (min 8 chars, uppercase, lowercase, digit)
    - **confirm_password**: Must match password
    """
    try:
        # Validate email format
        if not validate_email(user_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Validate password strength
        password_validation = validate_password(user_data.password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["message"]
            )
        
        # Check if user already exists
        existing_user = get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Hash password
        hashed_password = hash_password(user_data.password)
        
        # Create user
        user_id = create_user(
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password
        )
        
        # Get created user
        user = get_user_by_email(user_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
        
        # Create access token
        access_token = create_access_token_for_user(user)
        
        # Prepare response
        user_response = UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user["full_name"],
            is_active=user["is_active"],
            created_at=user.get("created_at"),
            updated_at=user.get("updated_at")
        )
        
        logger.info(f"User registered successfully: {user_data.email}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_manager.access_token_expire_minutes * 60,
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during user registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration"
        )

@router.post("/login",
             response_model=TokenResponse,
             responses={
                 401: {"model": ErrorResponse, "description": "Invalid credentials"},
                 400: {"model": ErrorResponse, "description": "Validation error"}
             })
async def login_user(login_data: UserLoginRequest):
    """
    Authenticate user and return access token
    
    - **email**: User's email address
    - **password**: User's password
    """
    try:
        # Authenticate user
        user = auth_manager.authenticate_user(login_data.email, login_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if user is active
        if not user.get("is_active", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        # Create access token
        access_token = create_access_token_for_user(user)
        
        # Prepare response
        user_response = UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user["full_name"],
            is_active=user["is_active"],
            created_at=user.get("created_at"),
            updated_at=user.get("updated_at")
        )
        
        logger.info(f"User logged in successfully: {login_data.email}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_manager.access_token_expire_minutes * 60,
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during user login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )

@router.get("/profile", 
            response_model=UserResponse,
            responses={
                401: {"model": ErrorResponse, "description": "Unauthorized"}
            })
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """
    Get current user's profile information
    
    Requires valid JWT token in Authorization header
    """
    try:
        user_response = UserResponse(
            id=current_user["id"],
            email=current_user["email"],
            full_name=current_user["full_name"],
            is_active=current_user["is_active"],
            created_at=current_user.get("created_at"),
            updated_at=current_user.get("updated_at")
        )
        
        return user_response
        
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user profile"
        )

@router.post("/validate-token",
             response_model=UserResponse,
             responses={
                 401: {"model": ErrorResponse, "description": "Invalid token"}
             })
async def validate_token(current_user: dict = Depends(get_current_user)):
    """
    Validate JWT token and return user information
    
    Useful for frontend to check if token is still valid
    """
    try:
        user_response = UserResponse(
            id=current_user["id"],
            email=current_user["email"],
            full_name=current_user["full_name"],
            is_active=current_user["is_active"],
            created_at=current_user.get("created_at"),
            updated_at=current_user.get("updated_at")
        )
        
        logger.info(f"Token validated for user: {current_user['email']}")
        return user_response
        
    except Exception as e:
        logger.error(f"Error validating token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error validating token"
        )

@router.post("/refresh-token",
             response_model=TokenResponse,
             responses={
                 401: {"model": ErrorResponse, "description": "Unauthorized"}
             })
async def refresh_token(current_user: dict = Depends(get_current_user)):
    """
    Refresh JWT token
    
    Generate a new token for the current user
    """
    try:
        # Create new access token
        access_token = create_access_token_for_user(current_user)
        
        # Prepare response
        user_response = UserResponse(
            id=current_user["id"],
            email=current_user["email"],
            full_name=current_user["full_name"],
            is_active=current_user["is_active"],
            created_at=current_user.get("created_at"),
            updated_at=current_user.get("updated_at")
        )
        
        logger.info(f"Token refreshed for user: {current_user['email']}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_manager.access_token_expire_minutes * 60,
            user=user_response
        )
        
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error refreshing token"
        )
