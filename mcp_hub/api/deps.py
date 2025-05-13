from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Request, Cookie
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from ..db.base import get_db
from ..db.models import User
from ..services.auth_service import AuthService
from ..core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/token", auto_error=False)


def get_token_from_cookie_or_header(
    request: Request,
    access_token: Optional[str] = Cookie(None),
    token_from_header: Optional[str] = Depends(oauth2_scheme)
) -> Optional[str]:
    """从Cookie或Header获取Token"""
    if access_token:
        return access_token
    return token_from_header


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie_or_header)
) -> User:
    """获取当前已认证用户"""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未提供认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = AuthService.get_current_user(db, token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="用户已被禁用"
        )
    return user


def get_optional_user(
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie_or_header)
) -> Optional[User]:
    """获取当前用户，如果未登录则返回None"""
    if not token:
        return None
    
    try:
        user = AuthService.get_current_user(db, token)
        if not user or not user.is_active:
            return None
        return user
    except Exception:
        return None


def get_current_active_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """获取当前已认证的管理员用户"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有足够的权限"
        )
    return current_user 