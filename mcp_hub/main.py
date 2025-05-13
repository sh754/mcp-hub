import uvicorn
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
import asyncio
import sys
import os
import warnings
import threading
import time
from pathlib import Path

warnings.filterwarnings(
    "ignore", 
    message="Field \"model_type\" has conflict with protected namespace \"model_\"",
    module="pydantic"
)
warnings.filterwarnings(
    "ignore",
    message="Valid config keys have changed in V2",
    module="pydantic"
)

sys.path.append(str(Path(__file__).resolve().parent.parent))

from mcp_hub.api import api_router
from mcp_hub.api.routes.web import router as web_router
from mcp_hub.core.config import settings
from mcp_hub.core.logging import get_logger
from mcp_hub.db.base import init_db, get_db
from mcp_hub.services.mcp_tool_service import MCPToolService
from mcp_hub.db.models import MCPTool

logger = get_logger("main")

app = FastAPI(
    title=settings.APP_NAME,
    description="基于FastMCP框架的MCP服务实现",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory="mcp_hub/static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_PREFIX)

app.include_router(web_router)


@app.get("/")
async def root():
    """根路径重定向到登录页面"""
    return RedirectResponse(url="/login")


@app.on_event("startup")
async def startup_event():
    """应用启动时执行"""
    logger.info(f"{settings.APP_NAME} 应用启动，准备自动启动工具...")
    
    db = next(get_db())
    try:
        auto_start_tools = db.query(MCPTool).filter(
            MCPTool.auto_start == True,
            MCPTool.enabled == True
        ).all()
        
        if not auto_start_tools:
            logger.info("没有找到需要自动启动的工具")
            return
        
        logger.info(f"找到 {len(auto_start_tools)} 个需要自动启动的工具")
        
        for tool in auto_start_tools:
            try:
                logger.info(f"自动启动工具: {tool.name} (ID: {tool.id})")
                success = MCPToolService.start_tool(tool.id, db)
                if success:
                    logger.info(f"工具 {tool.name} 自动启动成功")
                else:
                    logger.error(f"工具 {tool.name} 自动启动失败")
            except Exception as e:
                logger.error(f"启动工具 {tool.name} 时出错: {e}")
        
        logger.info("自动启动工具完成")
        
        monitor_thread = threading.Thread(
            target=monitor_mcp_tools,
            daemon=True,
            name="MCP-Tools-Monitor"
        )
        monitor_thread.start()
        logger.info(f"MCP工具监控线程已启动 (线程ID: {monitor_thread.ident})")
        
    except Exception as e:
        logger.error(f"自动启动工具过程中出错: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        db.close()

def monitor_mcp_tools():
    """监控MCP工具状态并重启已停止的自动启动工具"""
    logger.info("MCP工具监控线程开始运行...")
    monitor_count = 0
    
    while True:
        monitor_count += 1
        logger.info(f"第 {monitor_count} 次运行MCP工具监控检查...")
        
        try:
            db = next(get_db())
            
            auto_start_tools = db.query(MCPTool).filter(
                MCPTool.auto_start == True,
                MCPTool.enabled == True
            ).all()
            
            if auto_start_tools:
                logger.info(f"找到 {len(auto_start_tools)} 个自动启动工具需要监控")
            else:
                logger.info("没有找到需要监控的自动启动工具")
                
            for tool in auto_start_tools:
                try:
                    status = MCPToolService.get_tool_status(tool.id, db)
                    logger.info(f"工具 {tool.name} 当前状态: {status['status']}")
                    
                    if status["status"] != "running":
                        logger.warning(f"检测到工具 {tool.name} (ID: {tool.id}) 未运行，正在尝试重启...")
                        success = MCPToolService.start_tool(tool.id, db)
                        if success:
                            logger.info(f"工具 {tool.name} 重启成功")
                        else:
                            logger.error(f"工具 {tool.name} 重启失败")
                except Exception as e:
                    logger.error(f"监控工具 {tool.name} 时出错: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
            
            db.close()
            
        except Exception as e:
            logger.error(f"MCP工具监控任务出错: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        logger.info(f"监控检查完成，等待60秒后进行下一次检查...")
        time.sleep(60)


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时执行"""
    logger.info(f"{settings.APP_NAME} 应用关闭")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", settings.APP_PORT))
    uvicorn.run(
        "mcp_hub.main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    ) 