from fastapi import APIRouter
from .auth import router as auth_router
from .mcp_tools import router as mcp_tools_router

api_router = APIRouter()

# 注册认证路由
api_router.include_router(auth_router, prefix="/auth", tags=["认证"])

# 注册MCP工具路由
api_router.include_router(mcp_tools_router, prefix="/mcp-tools", tags=["MCP工具"]) 