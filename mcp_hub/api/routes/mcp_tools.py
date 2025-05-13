from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...db.base import get_db
from ...db.models import User
from ...models.mcp_tool import MCPTool, MCPToolCreate, MCPToolUpdate, SecurityRuleCreate
from ...services.mcp_tool_service import MCPToolService
from ..deps import get_current_active_admin, get_current_user

router = APIRouter()


@router.get("/", response_model=List[MCPTool])
async def get_mcp_tools(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100
):
    """获取所有MCP工具"""
    tools = MCPToolService.get_all_tools(db)
    return tools


@router.get("/{tool_id}", response_model=MCPTool)
async def get_mcp_tool(
    tool_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取指定的MCP工具"""
    tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    return tool


@router.post("/", response_model=MCPTool, status_code=status.HTTP_201_CREATED)
async def create_mcp_tool(
    tool: MCPToolCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """创建新的MCP工具"""
    # 检查工具名称是否已存在
    existing_tool = MCPToolService.get_tool_by_name(db, tool.name)
    if existing_tool:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"名称为'{tool.name}'的MCP工具已存在"
        )
    
    # 创建新工具
    return MCPToolService.create_tool(db, tool)


@router.put("/{tool_id}", response_model=MCPTool)
async def update_mcp_tool(
    tool_id: int,
    tool: MCPToolUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """更新MCP工具"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 如果更新名称，检查新名称是否已存在
    if tool.name and tool.name != db_tool.name:
        existing_tool = MCPToolService.get_tool_by_name(db, tool.name)
        if existing_tool:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"名称为'{tool.name}'的MCP工具已存在"
            )
    
    # 更新工具
    updated_tool = MCPToolService.update_tool(db, tool_id, tool)
    return updated_tool


@router.delete("/{tool_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_tool(
    tool_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """删除MCP工具"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 停止工具（如果正在运行）
    MCPToolService.stop_tool(tool_id)
    
    # 删除工具
    MCPToolService.delete_tool(db, tool_id)
    return None


@router.post("/{tool_id}/security_rules", status_code=status.HTTP_201_CREATED)
async def add_security_rule(
    tool_id: int,
    rule: SecurityRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """为MCP工具添加安全规则"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 添加安全规则
    return MCPToolService.add_security_rule(db, tool_id, rule)


@router.delete("/security_rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_security_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """删除安全规则"""
    result = MCPToolService.delete_security_rule(db, rule_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{rule_id}的安全规则"
        )
    return None


@router.post("/{tool_id}/start", status_code=status.HTTP_200_OK)
async def start_mcp_tool(
    tool_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """启动MCP工具"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 启动工具
    result = MCPToolService.start_tool(tool_id, db)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"启动MCP工具失败"
        )
    
    return {"status": "success", "message": f"MCP工具 '{db_tool.name}' 已启动"}


@router.post("/{tool_id}/stop", status_code=status.HTTP_200_OK)
async def stop_mcp_tool(
    tool_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """停止MCP工具"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 停止工具
    result = MCPToolService.stop_tool(tool_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"停止MCP工具失败"
        )
    
    return {"status": "success", "message": f"MCP工具 '{db_tool.name}' 已停止"}


@router.get("/{tool_id}/status", status_code=status.HTTP_200_OK)
async def get_mcp_tool_status(
    tool_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取MCP工具状态"""
    # 检查工具是否存在
    db_tool = MCPToolService.get_tool_by_id(db, tool_id)
    if not db_tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"找不到ID为{tool_id}的MCP工具"
        )
    
    # 获取工具状态
    status_info = MCPToolService.get_tool_status(tool_id, db)
    status_info["name"] = db_tool.name
    status_info["enabled"] = db_tool.enabled
    
    return status_info 