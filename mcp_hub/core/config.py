from pydantic_settings import BaseSettings
from typing import List, Union, Optional
import os
from pathlib import Path


class Settings(BaseSettings):
    """应用程序设置，从.env文件加载"""
    
    APP_NAME: str = "MCP Hub"
    APP_PORT: int = 5000
    APP_SECRET_KEY: str
    API_PREFIX: str = "/api"
    
    # Docker环境标识
    IS_DOCKER: bool = False
    
    # 数据库配置
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str
    DB_POOL_SIZE: int = 10  # 默认连接池大小
    DB_POOL_RECYCLE: int = 300  # 默认连接回收时间(秒)
    DB_MAX_OVERFLOW: int = 20  # 连接池最大溢出连接数
    DB_POOL_TIMEOUT: int = 60  # 连接池获取连接超时时间
    DB_READ_TIMEOUT: int = 300  # 读取超时时间
    DB_WRITE_TIMEOUT: int = 300  # 写入超时时间
    DB_WAIT_TIMEOUT: int = 7200  # 等待超时时间
    DB_INTERACTIVE_TIMEOUT: int = 7200  # 交互超时时间
    
    # 安全配置
    ACCESS_CONTROL_ALLOW_ORIGINS: str
    ADMIN_USERNAME: str
    ADMIN_PASSWORD: str
    ADMIN_EMAIL: str
    
    # 认证配置
    ALGORITHM: str = "HS256"  # JWT签名算法，默认HS256
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 令牌过期时间，默认60分钟
    
    # 日志配置
    LOG_LEVEL: str = "INFO"
    
    # MCP工具配置
    MCP_TOOL_WORKER: int = 1
    
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """获取SQLAlchemy数据库URI"""
        return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    @property
    def ORIGINS(self) -> List[str]:
        """获取CORS允许的源列表"""
        return self.ACCESS_CONTROL_ALLOW_ORIGINS.split(",")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings() 