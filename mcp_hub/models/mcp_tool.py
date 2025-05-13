from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class SecurityRuleBase(BaseModel):
    name: str
    rule_type: str = Field(..., description="'all', 'single_ip', 'ip_range', 'subnet'")
    value: str
    enabled: bool = True


class SecurityRuleCreate(SecurityRuleBase):
    pass


class SecurityRuleUpdate(SecurityRuleBase):
    name: Optional[str] = None
    rule_type: Optional[str] = None
    value: Optional[str] = None
    enabled: Optional[bool] = None


class SecurityRule(SecurityRuleBase):
    id: int
    mcp_tool_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True


class MCPToolBase(BaseModel):
    name: str
    description: Optional[str] = None
    module_path: str
    port: int
    enabled: bool = True
    config: Optional[Dict[str, Any]] = None
    usage_examples: Optional[str] = None
    is_uvicorn: bool = True
    worker: int = 2
    auto_start: bool = False


class MCPToolCreate(MCPToolBase):
    pass


class MCPToolUpdate(MCPToolBase):
    name: Optional[str] = None
    description: Optional[str] = None
    module_path: Optional[str] = None
    port: Optional[int] = None
    enabled: Optional[bool] = None
    is_uvicorn: Optional[bool] = None
    worker: Optional[int] = None
    auto_start: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    usage_examples: Optional[str] = None


class MCPTool(MCPToolBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    security_rules: List[SecurityRule] = []

    class Config:
        orm_mode = True


class MCPToolDetail(MCPTool):
    """带有所有安全规则的详细MCP工具信息"""
    pass 