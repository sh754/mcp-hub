from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt, ExpiredSignatureError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from ..db.models import User
from ..models.user import TokenData
from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger("auth_service")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = settings.APP_SECRET_KEY
ALGORITHM = settings.ALGORITHM


class AuthService:
    """认证服务"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """获取密码哈希"""
        return pwd_context.hash(password)
    
    @staticmethod
    def get_user(db: Session, username: str) -> Optional[User]:
        """根据用户名获取用户"""
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
        """验证用户"""
        user = AuthService.get_user(db, username)
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """创建访问令牌"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str) -> Optional[TokenData]:
        """解码令牌"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                logger.warning("令牌中没有用户名")
                return None
            return TokenData(username=username)
        except ExpiredSignatureError:
            logger.warning("令牌已过期")
            return None
        except JWTError as e:
            logger.warning(f"解码令牌失败: {e}")
            return None
        except Exception as e:
            logger.error(f"处理令牌时发生错误: {e}")
            return None
    
    @staticmethod
    def get_current_user(db: Session, token: str) -> Optional[User]:
        """获取当前用户"""
        if not token:
            return None
            
        token_data = AuthService.decode_token(token)
        if token_data is None:
            return None
        
        user = AuthService.get_user(db, username=token_data.username)
        if user is None:
            return None
        
        return user 