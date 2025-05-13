#!/usr/bin/env python

import sys
import os
from pathlib import Path
import time

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

import asyncio
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import pymysql
from urllib.parse import urlparse
import importlib.util

from mcp_hub.db.base import engine, SessionLocal
from mcp_hub.db.models import Base, User, MCPTool, SecurityRule
from mcp_hub.core.config import settings
from mcp_hub.core.logging import get_logger

logger = get_logger("init_db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MCP_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent / "mcp_tools"

def create_database():
    """创建数据库（如果不存在）"""
    logger.info("检查数据库是否存在...")
    
    parsed_uri = urlparse(settings.SQLALCHEMY_DATABASE_URI)
    db_name = parsed_uri.path.lstrip('/')
    
    host = settings.DB_HOST
    port = settings.DB_PORT
    user = settings.DB_USER
    password = settings.DB_PASSWORD
    db_name = settings.DB_NAME
    
    logger.info(f"尝试连接MySQL: {host}:{port} 用户: {user} 数据库: {db_name}")
    
    is_docker = getattr(settings, 'IS_DOCKER', False)
    if is_docker:
        logger.info("检测到Docker环境，使用适应性连接策略")
    
    max_retries = 10 if is_docker else 3
    retry_delay = 5
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            conn = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                connect_timeout=30
            )
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '{db_name}'")
            result = cursor.fetchone()
            
            if not result:
                cursor.execute(f"CREATE DATABASE {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                logger.info(f"创建数据库 {db_name} 成功")
                cursor.close()
                conn.close()
                return False 
            else:
                logger.info(f"数据库 {db_name} 已存在")
                cursor.close()
                conn.close()
                return True
        except Exception as e:
            retry_count += 1
            logger.warning(f"连接MySQL失败 (尝试 {retry_count}/{max_retries}): {e}")
            
            if retry_count < max_retries:
                logger.info(f"等待 {retry_delay} 秒后重试...")
                time.sleep(retry_delay)
            else:
                logger.error(f"创建数据库失败: {e}")
                raise


def create_admin_user(db: Session):
    """创建管理员用户"""
    admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
    if admin:
        logger.info(f"管理员用户 {settings.ADMIN_USERNAME} 已存在")
        return

    hashed_password = pwd_context.hash(settings.ADMIN_PASSWORD)
    db_user = User(
        username=settings.ADMIN_USERNAME,
        email=settings.ADMIN_EMAIL,
        hashed_password=hashed_password,
        is_active=True,
        is_admin=True
    )
    db.add(db_user)
    db.commit()
    logger.info(f"创建管理员用户: {settings.ADMIN_USERNAME}")


def init_tool_databases(db: Session):
    """
    初始化每个MCP工具的特定数据
    该函数会自动发现并执行每个工具目录下的init_db.py脚本
    """
    logger.info("初始化工具数据库...")
    
    tools_dir = Path(MCP_TOOLS_DIR)
    if not tools_dir.exists():
        logger.warning(f"工具目录 {tools_dir} 不存在，跳过工具数据库初始化。")
        return
    
    for tool_dir in tools_dir.iterdir():
        if not tool_dir.is_dir():
            continue
            
        tool_name = tool_dir.name
        init_script = tool_dir / "init_db.py"
        
        if not init_script.exists():
            logger.info(f"工具 {tool_name} 没有初始化脚本，跳过。")
            continue
            
        logger.info(f"发现工具 {tool_name} 的初始化脚本，开始执行...")
        
        try:
            spec = importlib.util.spec_from_file_location(f"{tool_name}_init_db", init_script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if hasattr(module, "init"):
                module.init(db)
                logger.info(f"工具 {tool_name} 数据初始化完成。")
            else:
                logger.warning(f"工具 {tool_name} 的初始化脚本中未找到init函数，跳过。")
        except Exception as e:
            logger.error(f"初始化工具 {tool_name} 数据时出错: {e}")
    
    logger.info("所有工具数据库初始化完成。")


def check_tables_exist():
    """检查核心表是否已存在"""
    try:
        db = SessionLocal()
        try:
            db.execute("SELECT 1 FROM users LIMIT 1")
            db.execute("SELECT 1 FROM mcp_tools LIMIT 1")
            logger.info("核心表已存在")
            return True
        except Exception as e:
            logger.info(f"核心表不存在: {e}")
            return False
        finally:
            db.close()
    except Exception as e:
        logger.error(f"检查表失败: {e}")
        return False

def init():
    """初始化数据库"""
    logger.info("开始初始化数据库...")
    
    db_exists = create_database()
    tables_exist = False
    
    if db_exists:
        tables_exist = check_tables_exist()
    
    if not db_exists or not tables_exist:
        try:
            logger.info("创建表结构...")
            Base.metadata.create_all(bind=engine)
            logger.info("数据库表创建完成")
        except Exception as e:
            logger.error(f"创建表失败: {e}")
            raise
    else:
        logger.info("数据库和表结构已存在，跳过表创建")
    
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if not admin:
            logger.info(f"管理员用户 {settings.ADMIN_USERNAME} 不存在，开始创建...")
            create_admin_user(db)
        else:
            logger.info(f"管理员用户 {settings.ADMIN_USERNAME} 已存在")
        
        if not db_exists:
            logger.info("全新数据库，执行工具初始化...")
            init_tool_databases(db)
            logger.info("完整数据库初始化完成")
        else:
            logger.info("数据库已存在，跳过工具数据初始化以防止覆盖现有数据")
    except Exception as e:
        logger.error(f"数据初始化失败: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init() 