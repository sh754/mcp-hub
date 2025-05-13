import psutil
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Form, Response, UploadFile, File, BackgroundTasks, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
import os
import json
import tempfile
import shutil
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
import uuid
import threading
import sys
import time

from ...db.base import get_db
from ...db.models import User, MCPTool, SecurityRule
from ...services.mcp_tool_service import MCPToolService
from ...services.auth_service import AuthService
from ...core.config import settings
from ...core.logging import get_logger
from ..deps import get_current_user, get_current_active_admin, get_optional_user
from ...models.mcp_tool import MCPToolCreate, MCPToolUpdate, SecurityRuleCreate

logger = get_logger("web_routes")
router = APIRouter()

# 设置模板目录
templates = Jinja2Templates(directory="mcp_hub/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """仪表盘页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有MCP工具
    tools = MCPToolService.get_all_tools(db)
    
    # 获取工具状态
    tools_with_status = []
    running_tools = 0
    stopped_tools = 0
    
    for tool in tools:
        status = MCPToolService.get_tool_status(tool.id, db)
        if status["status"] == "running":
            running_tools += 1
        else:
            stopped_tools += 1
        # 创建工具属性的字典
        tool_dict = {
            "id": tool.id,
            "name": tool.name,
            "description": tool.description,
            "module_path": tool.module_path,
            "enabled": tool.enabled,
            "auto_start": tool.auto_start,
            "port": tool.port,
            "config": tool.config,
            "usage_examples": tool.usage_examples,
            "created_at": tool.created_at,
            "updated_at": tool.updated_at,
            "is_uvicorn": tool.is_uvicorn,
            "worker": tool.worker,
            "security_rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "rule_type": rule.rule_type,
                    "value": rule.value,
                    "enabled": rule.enabled
                } for rule in tool.security_rules
            ],
            "status": status["status"]
        }
        tools_with_status.append({**tool_dict, "status": status["status"]})
    
    # 获取系统资源使用情况
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    
    # 获取安全规则数量
    total_security_rules = sum(len(tool.security_rules) for tool in tools)
    
    # 统计信息
    stats = {
        "total_tools": len(tools),
        "running_tools": running_tools,
        "stopped_tools": stopped_tools,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "disk_usage": disk_usage,
        "total_security_rules": total_security_rules,
        "login_attempts": 0,  # 可以从日志或数据库中获取
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 模拟最近活动数据
    recent_activities = [
        {
            "title": "系统启动",
            "description": "MCP Hub系统已成功启动",
            "user": "系统",
            "time": (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "title": "工具添加",
            "description": "新增MySQL查询工具",
            "user": "admin",
            "time": (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        }
    ]
    
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "dashboard",
            "stats": stats,
            "recent_activities": recent_activities
        }
    )


@router.get("/mcp-tools", response_class=HTMLResponse)
async def mcp_tools_list(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """MCP工具列表页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有MCP工具
    tools = MCPToolService.get_all_tools(db)
    
    # 获取工具状态
    tools_with_status = []
    for tool in tools:
        status = MCPToolService.get_tool_status(tool.id, db)
        # 创建工具属性的字典
        tool_dict = {
            "id": tool.id,
            "name": tool.name,
            "description": tool.description,
            "module_path": tool.module_path,
            "enabled": tool.enabled,
            "auto_start": tool.auto_start,
            "port": tool.port,
            "config": tool.config,
            "usage_examples": tool.usage_examples,
            "created_at": tool.created_at,
            "updated_at": tool.updated_at
        }
        tools_with_status.append({**tool_dict, "status": status["status"]})
    
    return templates.TemplateResponse(
        "mcp_tools.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "mcp_tools",
            "tools": tools_with_status,
            "messages": []
        }
    )


@router.get("/mcp-tools/create", response_class=HTMLResponse)
async def mcp_tool_create_form(
    request: Request,
    current_user: Optional[User] = Depends(get_optional_user)
):
    """创建MCP工具表单页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        "mcp_tool_edit.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "mcp_tools",
            "tool": None,
            "messages": []
        }
    )


# 启动和停止所有工具的路由位于具体工具路由之前
@router.get("/mcp-tools/start-all", response_class=HTMLResponse)
async def mcp_tools_start_all(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """启动所有MCP工具"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有启用的工具
    tools = db.query(MCPTool).filter(MCPTool.enabled == True).all()
    
    # 启动所有工具
    for tool in tools:
        MCPToolService.start_tool(tool.id, db)
    
    return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)


@router.get("/mcp-tools/stop-all", response_class=HTMLResponse)
async def mcp_tools_stop_all(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """停止所有MCP工具"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有工具
    tools = db.query(MCPTool).all()
    
    # 停止所有工具
    for tool in tools:
        MCPToolService.stop_tool(tool.id)
    
    return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)


@router.get("/mcp-tools/{tool_id}", response_class=HTMLResponse)
async def mcp_tool_detail(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """MCP工具详情页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具状态
    status = MCPToolService.get_tool_status(tool_id, db)
    # 创建工具属性的字典
    tool_dict = {
        "id": tool.id,
        "name": tool.name,
        "description": tool.description,
        "module_path": tool.module_path,
        "enabled": tool.enabled,
        "auto_start": tool.auto_start,
        "port": tool.port,
        "config": tool.config,
        "usage_examples": tool.usage_examples,
        "created_at": tool.created_at,
        "updated_at": tool.updated_at,
        "is_uvicorn": tool.is_uvicorn,
        "worker": tool.worker,
        "security_rules": [
            {
                "id": rule.id,
                "name": rule.name,
                "rule_type": rule.rule_type,
                "value": rule.value,
                "enabled": rule.enabled
            } for rule in tool.security_rules
        ],
        "status": status["status"]
    }
    
    return templates.TemplateResponse(
        "mcp_tool_detail.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "mcp_tools",
            "tool": tool_dict,
            "messages": []
        }
    )


@router.get("/mcp-tools/{tool_id}/edit", response_class=HTMLResponse)
async def mcp_tool_edit_form(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """编辑MCP工具表单页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        "mcp_tool_edit.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "mcp_tools",
            "tool": tool,
            "messages": []
        }
    )


@router.post("/mcp-tools", response_class=HTMLResponse)
async def mcp_tool_create(
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    module_path: str = Form(...),
    port: int = Form(...),
    enabled: bool = Form(False),
    auto_start: bool = Form(False),
    is_uvicorn: bool = Form(False),
    worker: int = Form(2),
    config: Optional[str] = Form(None),
    usage_examples: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """处理创建MCP工具请求"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 解析配置JSON
    config_dict = {}
    if config:
        try:
            config_dict = json.loads(config)
        except json.JSONDecodeError:
            return templates.TemplateResponse(
                "mcp_tool_edit.html",
                {
                    "request": request,
                    "current_user": current_user,
                    "active_page": "mcp_tools",
                    "tool": None,
                    "messages": [{"type": "danger", "text": "配置JSON格式不正确"}]
                }
            )
    
    # 创建工具
    tool_data = MCPToolCreate(
        name=name,
        description=description,
        module_path=module_path,
        port=port,
        enabled=enabled,
        auto_start=auto_start,
        is_uvicorn=is_uvicorn,
        worker=worker,
        config=config_dict,
        usage_examples=usage_examples
    )
    
    try:
        tool = MCPToolService.create_tool(db, tool_data)
        if auto_start:
            MCPToolService.start_tool(tool.id, db)
        return RedirectResponse(f"/mcp-tools/{tool.id}", status_code=HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"创建MCP工具失败: {e}")
        return templates.TemplateResponse(
            "mcp_tool_edit.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "mcp_tools",
                "tool": None,
                "messages": [{"type": "danger", "text": f"创建MCP工具失败: {str(e)}"}]
            }
        )


@router.post("/mcp-tools/{tool_id}", response_class=HTMLResponse)
async def mcp_tool_update(
    tool_id: int,
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    module_path: str = Form(...),
    port: int = Form(...),
    enabled: bool = Form(False),
    auto_start: bool = Form(False),
    is_uvicorn: bool = Form(False),
    worker: int = Form(2),
    config: Optional[str] = Form(None),
    usage_examples: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """处理更新MCP工具请求"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 解析配置JSON
    config_dict = {}
    if config:
        try:
            config_dict = json.loads(config)
        except json.JSONDecodeError:
            return templates.TemplateResponse(
                "mcp_tool_edit.html",
                {
                    "request": request,
                    "current_user": current_user,
                    "active_page": "mcp_tools",
                    "tool": db_tool,
                    "messages": [{"type": "danger", "text": "配置JSON格式不正确"}]
                }
            )
    
    # 更新工具
    tool_data = MCPToolUpdate(
        name=name,
        description=description,
        module_path=module_path,
        port=port,
        enabled=enabled,
        auto_start=auto_start,
        is_uvicorn=is_uvicorn,
        worker=worker,
        config=config_dict,
        usage_examples=usage_examples
    )
    
    try:
        MCPToolService.update_tool(db, tool_id, tool_data)
        return RedirectResponse(f"/mcp-tools/{tool_id}", status_code=HTTP_303_SEE_OTHER)
    except Exception as e:
        logger.error(f"更新MCP工具失败: {e}")
        return templates.TemplateResponse(
            "mcp_tool_edit.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "mcp_tools",
                "tool": db_tool,
                "messages": [{"type": "danger", "text": f"更新MCP工具失败: {str(e)}"}]
            }
        )


@router.get("/mcp-tools/{tool_id}/delete", response_class=HTMLResponse)
async def mcp_tool_delete(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """删除MCP工具"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 停止工具（如果正在运行）
    MCPToolService.stop_tool(tool_id)
    
    # 删除工具
    MCPToolService.delete_tool(db, tool_id)
    
    return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)


@router.get("/mcp-tools/{tool_id}/start", response_class=HTMLResponse)
async def mcp_tool_start(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """启动MCP工具"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 启动工具
    MCPToolService.start_tool(tool_id, db)
    
    return RedirectResponse(f"/mcp-tools/{tool_id}", status_code=HTTP_303_SEE_OTHER)


@router.get("/mcp-tools/{tool_id}/stop", response_class=HTMLResponse)
async def mcp_tool_stop(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """停止MCP工具"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 停止工具
    MCPToolService.stop_tool(tool_id)
    
    return RedirectResponse(f"/mcp-tools/{tool_id}", status_code=HTTP_303_SEE_OTHER)


@router.post("/mcp-tools/{tool_id}/security-rules", response_class=HTMLResponse)
async def add_security_rule(
    tool_id: int,
    name: str = Form(...),
    rule_type: str = Form(...),
    value: str = Form(...),
    enabled: bool = Form(False),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """添加安全规则"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    # 创建规则
    rule = SecurityRuleCreate(
        name=name,
        rule_type=rule_type,
        value=value,
        enabled=enabled
    )
    
    # 添加规则
    MCPToolService.add_security_rule(db, tool_id, rule)
    
    return RedirectResponse(f"/mcp-tools/{tool_id}", status_code=HTTP_303_SEE_OTHER)


@router.get("/security", response_class=HTMLResponse)
async def security_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """安全设置页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有MCP工具
    tools = MCPToolService.get_all_tools(db)
    
    # 模拟安全日志数据
    security_logs = [
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "info",
            "user": "admin",
            "ip": "127.0.0.1",
            "details": "成功登录"
        },
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "warning",
            "user": "未知",
            "ip": "192.168.1.100",
            "details": "无效的登录尝试"
        }
    ]
    
    return templates.TemplateResponse(
        "security.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "security",
            "tools": tools,
            "security_logs": security_logs,
            "settings": settings,
            "messages": []
        }
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    current_user: Optional[User] = Depends(get_optional_user)
):
    """登录页面"""
    # 如果用户已登录，重定向到仪表盘
    if current_user:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "messages": []}
    )


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """处理登录请求"""
    user = AuthService.authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "messages": [{"type": "danger", "text": "用户名或密码错误"}]
            }
        )
    
    # 创建会话
    response = RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 创建访问令牌
    access_token = AuthService.create_access_token(data={"sub": user.username})
    
    # 设置cookie
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    
    return response


@router.get("/logout")
async def logout():
    """退出登录"""
    response = RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response


@router.get("/mcp-tools/security-rules/{rule_id}/delete", response_class=HTMLResponse)
async def delete_security_rule(
    rule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """删除安全规则"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取规则所属工具ID，用于后续重定向
    rule = db.query(SecurityRule).filter(SecurityRule.id == rule_id).first()
    tool_id = rule.mcp_tool_id if rule else None
    
    # 删除规则
    success = MCPToolService.delete_security_rule(db, rule_id)
    
    # 如果有工具ID，则重定向到工具详情页，否则重定向到工具列表
    if tool_id:
        return RedirectResponse(f"/mcp-tools/{tool_id}", status_code=HTTP_303_SEE_OTHER)
    else:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)


@router.get("/mcp-tools/{tool_id}/security", response_class=HTMLResponse)
async def tool_security_page(
    tool_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """工具安全管理页面"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取工具
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        return RedirectResponse("/mcp-tools", status_code=HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(
        "mcp_tool_security.html",
        {
            "request": request,
            "current_user": current_user,
            "active_page": "mcp_tools",
            "tool": tool,
            "settings": settings,
            "messages": []
        }
    )


@router.post("/security/backup")
async def backup_database(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """备份数据库内容"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    try:
        # 获取数据库中的数据
        mcp_tools = db.query(MCPTool).all()
        security_rules = db.query(SecurityRule).all()
        users = db.query(User).all()
        
        # 转换为字典
        data = {
            "mcp_tools": [
                {
                    "id": tool.id,
                    "name": tool.name,
                    "description": tool.description,
                    "module_path": tool.module_path,
                    "enabled": tool.enabled,
                    "port": tool.port,
                    "config": tool.config,
                    "usage_examples": tool.usage_examples,
                    "is_uvicorn": tool.is_uvicorn,
                    "worker": tool.worker
                }
                for tool in mcp_tools
            ],
            "security_rules": [
                {
                    "mcp_tool_id": rule.mcp_tool_id,
                    "name": rule.name,
                    "rule_type": rule.rule_type,
                    "value": rule.value,
                    "enabled": rule.enabled
                }
                for rule in security_rules
            ],
            "users": [
                {
                    "username": user.username,
                    "email": user.email,
                    "hashed_password": user.hashed_password,
                    "is_active": user.is_active,
                    "is_admin": user.is_admin
                }
                for user in users
            ],
            "backup_time": datetime.now().isoformat(),
            "version": "1.0"  # 备份文件版本
        }
        
        # 创建临时文件
        backup_file = tempfile.NamedTemporaryFile(delete=False)
        backup_file.write(json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8'))
        backup_path = backup_file.name
        backup_file.close()
        
        # 添加删除临时文件的后台任务
        def remove_file(path: str):
            try:
                os.unlink(path)
                logger.info(f"临时文件已删除: {path}")
            except Exception as e:
                logger.error(f"删除临时文件失败: {e}")
                
        background_tasks.add_task(remove_file, backup_path)
        
        # 生成备份文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mcp_hub_backup_{timestamp}.json"
        
        # 返回文件响应
        return FileResponse(
            path=backup_path,
            filename=filename,
            media_type="application/json"
        )
        
    except Exception as e:
        logger.error(f"备份数据库时出错: {e}")
        # 返回错误消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": db.query(MCPTool).all(),
                "security_logs": [],
                "settings": settings,
                "messages": [{"type": "danger", "text": f"备份失败: {str(e)}"}]
            }
        )

@router.post("/security/restore")
async def restore_database(
    request: Request,
    backupFile: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """从备份文件恢复数据库"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    try:
        # 读取上传的文件
        content = await backupFile.read()
        data = json.loads(content)
        
        # 验证备份文件格式
        if not all(key in data for key in ["mcp_tools", "security_rules", "users", "backup_time"]):
            raise ValueError("无效的备份文件格式")
        
        # 不需要手动开始事务
        # db.begin()
        
        # 清除现有数据
        db.query(SecurityRule).delete()
        db.query(MCPTool).delete()
        
        # 不删除用户表，防止锁定自己
        # db.query(User).delete()
        
        # 恢复工具数据
        for tool_data in data["mcp_tools"]:
            # 创建新工具记录
            tool = MCPTool(
                name=tool_data["name"],
                description=tool_data.get("description"),
                module_path=tool_data["module_path"],
                enabled=tool_data["enabled"],
                port=tool_data["port"],
                config=tool_data.get("config"),
                usage_examples=tool_data.get("usage_examples"),
                is_uvicorn=tool_data.get("is_uvicorn", True),
                worker=tool_data.get("worker", 2)
            )
            db.add(tool)
        
        # 刷新数据库以获取工具ID
        db.flush()
        
        # 获取新旧工具ID映射关系
        old_to_new_id = {}
        for tool_data in data["mcp_tools"]:
            old_id = tool_data["id"]
            new_tool = db.query(MCPTool).filter(MCPTool.name == tool_data["name"]).first()
            if new_tool:
                old_to_new_id[old_id] = new_tool.id
        
        # 恢复安全规则数据
        for rule_data in data["security_rules"]:
            # 获取对应的新工具ID
            old_tool_id = rule_data["mcp_tool_id"]
            new_tool_id = old_to_new_id.get(old_tool_id)
            
            if new_tool_id:
                # 创建新规则记录
                rule = SecurityRule(
                    mcp_tool_id=new_tool_id,
                    name=rule_data["name"],
                    rule_type=rule_data["rule_type"],
                    value=rule_data["value"],
                    enabled=rule_data["enabled"]
                )
                db.add(rule)
        
        # 可选：恢复用户数据，但保留当前管理员账户
        # 这里仅更新非管理员账户，以确保不会锁定自己
        '''
        current_admin_usernames = [user.username for user in db.query(User).filter(User.is_admin == True).all()]
        
        for user_data in data["users"]:
            if user_data["username"] not in current_admin_usernames:
                existing_user = db.query(User).filter(User.username == user_data["username"]).first()
                
                if existing_user:
                    # 更新现有用户
                    existing_user.email = user_data["email"]
                    existing_user.hashed_password = user_data["hashed_password"]
                    existing_user.is_active = user_data["is_active"]
                    existing_user.is_admin = user_data["is_admin"]
                else:
                    # 创建新用户
                    user = User(
                        username=user_data["username"],
                        email=user_data["email"],
                        hashed_password=user_data["hashed_password"],
                        is_active=user_data["is_active"],
                        is_admin=user_data["is_admin"]
                    )
                    db.add(user)
        '''
        
        # 提交事务
        db.commit()
        
        # 返回成功消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": db.query(MCPTool).all(),
                "security_logs": [],
                "settings": settings,
                "messages": [{"type": "success", "text": "成功从备份文件恢复数据"}]
            }
        )
        
    except Exception as e:
        # 回滚事务
        db.rollback()
        
        logger.error(f"恢复数据库时出错: {e}")
        # 返回错误消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": db.query(MCPTool).all(),
                "security_logs": [],
                "settings": settings,
                "messages": [{"type": "danger", "text": f"恢复失败: {str(e)}"}]
            }
        )

@router.post("/security/password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    currentPassword: str = Form(...),
    newPassword: str = Form(...),
    confirmPassword: str = Form(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """处理修改密码请求"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有MCP工具（用于渲染页面）
    tools = MCPToolService.get_all_tools(db)
    
    # 模拟安全日志数据
    security_logs = [
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "info",
            "user": "admin",
            "ip": "127.0.0.1",
            "details": "成功登录"
        },
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "warning",
            "user": "未知",
            "ip": "192.168.1.100",
            "details": "无效的登录尝试"
        }
    ]
    
    # 验证当前密码
    is_valid = AuthService.verify_password(currentPassword, current_user.hashed_password)
    if not is_valid:
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "danger", "text": "当前密码不正确"}]
            }
        )
    
    # 检查新密码和确认密码是否匹配
    if newPassword != confirmPassword:
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "danger", "text": "两次输入的新密码不匹配"}]
            }
        )
    
    # 检查新密码长度
    if len(newPassword) < 6:
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "danger", "text": "新密码长度不能少于6个字符"}]
            }
        )
    
    try:
        # 生成新密码哈希
        hashed_password = AuthService.get_password_hash(newPassword)
        
        # 更新用户密码
        user = db.query(User).filter(User.id == current_user.id).first()
        user.hashed_password = hashed_password
        db.commit()
        
        logger.info(f"用户 {current_user.username} 已成功修改密码")
        
        # 返回成功消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "success", "text": "密码修改成功"}]
            }
        )
    except Exception as e:
        logger.error(f"修改密码失败: {e}")
        db.rollback()
        
        # 返回错误消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "danger", "text": f"修改密码失败: {str(e)}"}]
            }
        )

@router.post("/security/global", response_class=HTMLResponse)
async def update_global_security(
    request: Request,
    allowOrigins: str = Form(...),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """更新全局安全设置"""
    # 检查用户是否已登录，未登录则重定向到登录页面
    if not current_user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        return RedirectResponse("/", status_code=HTTP_303_SEE_OTHER)
    
    # 获取所有MCP工具（用于渲染页面）
    tools = MCPToolService.get_all_tools(db)
    
    # 模拟安全日志数据
    security_logs = [
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "info",
            "user": "admin",
            "ip": "127.0.0.1",
            "details": "成功登录"
        },
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "warning",
            "user": "未知",
            "ip": "192.168.1.100",
            "details": "无效的登录尝试"
        }
    ]
    
    try:
        # 获取.env文件路径
        env_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), ".env")
        
        # 检查.env文件是否存在
        if not os.path.exists(env_file_path):
            raise FileNotFoundError(f"找不到.env文件: {env_file_path}")
        
        # 读取.env文件内容
        with open(env_file_path, "r", encoding="utf-8") as f:
            env_content = f.read()
        
        # 更新或添加ACCESS_CONTROL_ALLOW_ORIGINS设置
        if "ACCESS_CONTROL_ALLOW_ORIGINS=" in env_content:
            # 如果设置已存在，则更新它
            env_lines = env_content.splitlines()
            updated_lines = []
            for line in env_lines:
                if line.startswith("ACCESS_CONTROL_ALLOW_ORIGINS="):
                    updated_lines.append(f"ACCESS_CONTROL_ALLOW_ORIGINS={allowOrigins}")
                else:
                    updated_lines.append(line)
            updated_env_content = "\n".join(updated_lines)
        else:
            # 如果设置不存在，则添加它
            updated_env_content = env_content.rstrip() + f"\nACCESS_CONTROL_ALLOW_ORIGINS={allowOrigins}\n"
        
        # 写回.env文件
        with open(env_file_path, "w", encoding="utf-8") as f:
            f.write(updated_env_content)
        
        # 更新运行时设置
        settings.ACCESS_CONTROL_ALLOW_ORIGINS = allowOrigins
        
        logger.info(f"用户 {current_user.username} 已更新CORS设置: {allowOrigins}")
        
        # 返回成功消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "success", "text": "全局安全设置已更新，将在应用重启后生效"}]
            }
        )
    except Exception as e:
        logger.error(f"更新全局安全设置失败: {e}")
        
        # 返回错误消息
        return templates.TemplateResponse(
            "security.html",
            {
                "request": request,
                "current_user": current_user,
                "active_page": "security",
                "tools": tools,
                "security_logs": security_logs,
                "settings": settings,
                "messages": [{"type": "danger", "text": f"更新设置失败: {str(e)}"}]
            }
        )

@router.post("/security/restart")
async def restart_application(
    request: Request,
    current_user: Optional[User] = Depends(get_optional_user)
):
    """重启应用"""
    # 检查用户是否已登录，未登录则返回错误
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未授权操作"
        )
    
    # 检查用户是否为管理员
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要管理员权限"
        )
    
    try:
        logger.info(f"管理员 {current_user.username} 请求重启应用")
        
        # 获取所有运行中的MCP工具
        tools = MCPToolService.get_all_tools(db=next(get_db()))
        
        # 先停止所有运行中的MCP工具
        for tool in tools:
            try:
                status_info = MCPToolService.get_tool_status(tool.id, db=next(get_db()))
                if status_info["status"] == "running":
                    logger.info(f"正在停止MCP工具: {tool.name} (ID: {tool.id})")
                    MCPToolService.stop_tool(tool.id)
            except Exception as e:
                logger.error(f"停止MCP工具 {tool.name} 时出错: {e}")
        
        # 注册一个后台任务，延迟2秒后重启应用
        # 这是异步的，因此响应会立即返回给客户端
        def restart_app():
            logger.info("等待2秒后重启应用...")
            time.sleep(2)
            logger.info("正在重启应用...")
            
            # 在Windows上使用不同的重启方法
            if os.name == 'nt':
                import subprocess
                # 获取当前Python解释器路径
                python = sys.executable
                # 获取应用入口文件路径
                main_app_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "main.py"
                )
                # 创建重启命令
                cmd = f'"{python}" "{main_app_path}"'
                # 使用subprocess在后台启动新进程
                subprocess.Popen(
                    cmd, 
                    shell=True, 
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    close_fds=True
                )
            else:
                # Linux/Unix系统使用os.execv进行原地重启
                os.execv(sys.executable, [sys.executable] + sys.argv)
            
            # 退出当前进程
            os._exit(0)
        
        # 启动重启线程
        threading.Thread(target=restart_app, daemon=True).start()
        
        return JSONResponse(content={"status": "restarting"})
    
    except Exception as e:
        logger.error(f"重启应用时发生错误: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"重启应用失败: {str(e)}"
        ) 