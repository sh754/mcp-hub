from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from .base import Base


class MCPTool(Base):
    """MCP工具模型"""
    
    __tablename__ = "mcp_tools"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    module_path = Column(String(255), nullable=False)  # 模块路径，如mcp_tools.mysql
    enabled = Column(Boolean, default=True)  # 是否启用
    port = Column(Integer, nullable=False)  # 工具监听的端口
    config = Column(JSON)  # 工具配置，存储为JSON
    usage_examples = Column(Text)  # 使用示例
    is_uvicorn = Column(Boolean, default=True)  # 是否使用uvicorn启动
    worker = Column(Integer, default=2)  # uvicorn worker数量
    auto_start = Column(Boolean, default=False)  # 开机自动启动
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    security_rules = relationship("SecurityRule", back_populates="mcp_tool", cascade="all, delete-orphan")


class SecurityRule(Base):
    """安全规则模型，定义允许访问的IP地址或网段"""
    
    __tablename__ = "security_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    mcp_tool_id = Column(Integer, ForeignKey("mcp_tools.id"), nullable=False)
    name = Column(String(100), nullable=False)
    rule_type = Column(String(20), nullable=False)
    value = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    mcp_tool = relationship("MCPTool", back_populates="security_rules")


class User(Base):
    """用户模型"""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now()) 