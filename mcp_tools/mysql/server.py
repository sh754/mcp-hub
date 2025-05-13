#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MySQL服务器MCP工具
提供基于FastMCP的MySQL操作服务
"""

import argparse
import json
import os
import sys
import logging
import traceback
import time
import re
import itertools
from typing import Dict, List, Any, Optional, Tuple, Union
from functools import wraps
from pathlib import Path
import distutils.util

try:
    from mcp_hub.core.logging import get_logger
    logger = get_logger("mysql_server")
    logger.info("MCP Hub 核心模块导入成功 (顶层)")
except ImportError as e:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("mysql_server_fallback")
    logger.error(f"无法在顶层导入 MCP Hub 核心模块: {e}. PYTHONPATH={os.environ.get('PYTHONPATH','')}")

try:
    import aiomysql
except ImportError:
    if logger:
        logger.error("缺少aiomysql库，请安装: pip install aiomysql")
    else: 
        logging.error("缺少aiomysql库，请安装: pip install aiomysql")
    sys.exit(1)

from fastmcp import FastMCP

query_cache = {}

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="MySQL MCP服务")
    parser.add_argument("--port", type=int, default=5001, help="服务端口号")
    parser.add_argument("--host", type=str, help="MySQL服务器地址")
    parser.add_argument("--database", type=str, help="默认数据库名称")
    parser.add_argument("--username", type=str, help="MySQL用户名")
    parser.add_argument("--password", type=str, help="MySQL密码")
    parser.add_argument("--sqlport", type=int, default=3306, help="MySQL数据库端口")
    parser.add_argument("--charset", type=str, default="utf8mb4", help="MySQL字符集")
    parser.add_argument("--cache-enabled", type=str, default="true", help="是否启用查询缓存")
    parser.add_argument("--cache-ttl", type=int, default=300, help="缓存过期时间(秒)")
    parser.add_argument("--connect-timeout", type=int, default=10, help="连接超时时间(秒)")
    parser.add_argument("--read-timeout", type=int, default=30, help="读取超时时间(秒)")
    parser.add_argument("--only-select", type=str, default="0", help="是否只允许查询(SELECT)操作，1、yes、true表示是，0、no、false表示否")
    parser.add_argument("--security-rules", type=str, help="安全规则JSON字符串")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="是否使用Uvicorn启动，true/false")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker进程数量")
    parser.add_argument("--tool-worker", type=str, help="MCP工具worker标识")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    args = parser.parse_args()
    return args

def args_to_env(args):
    """将命令行参数转换为环境变量"""
    if args.host:
        os.environ["MYSQL_HOST"] = args.host
    if args.database:
        os.environ["MYSQL_DATABASE"] = args.database
    if args.username:
        os.environ["MYSQL_USERNAME"] = args.username
    if args.password:
        os.environ["MYSQL_PASSWORD"] = args.password
    if args.sqlport:
        os.environ["MYSQL_PORT"] = str(args.sqlport)
    if args.charset:
        os.environ["MYSQL_CHARSET"] = args.charset
    if args.cache_enabled:
        os.environ["MYSQL_CACHE_ENABLED"] = args.cache_enabled
    if args.cache_ttl:
        os.environ["MYSQL_CACHE_TTL"] = str(args.cache_ttl)
    if args.connect_timeout:
        os.environ["MYSQL_CONNECT_TIMEOUT"] = str(args.connect_timeout)
    if args.read_timeout:
        os.environ["MYSQL_READ_TIMEOUT"] = str(args.read_timeout)
    
    # 处理only_select参数，将各种形式的布尔值转换为0或1
    only_select_value = "0"
    if args.only_select:
        try:
            # 尝试将字符串转换为布尔值
            if args.only_select.lower() in ("1", "true", "yes", "y", "t"):
                only_select_value = "1"
        except:
            pass
    os.environ["MYSQL_ONLY_SELECT"] = only_select_value
    
    # 安全规则从命令行参数或指定的环境变量获取
    if args.security_rules:
        # 直接从命令行获取规则
        os.environ["MYSQL_SECURITY_RULES"] = args.security_rules
        logger.info(f"从命令行参数获取安全规则: {args.security_rules[:100]}..." if len(args.security_rules) > 100 else args.security_rules)
    elif args.security_rules_env and args.security_rules_env in os.environ:
        # 从指定的环境变量读取规则，并复制到标准环境变量
        security_rules = os.environ[args.security_rules_env]
        os.environ["MYSQL_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过命令行或指定环境变量提供安全规则，检查是否已有 MYSQL_SECURITY_RULES={os.environ.get('MYSQL_SECURITY_RULES', '未设置')}")
    
    # 设置Uvicorn和worker相关环境变量
    if hasattr(args, 'tool_worker') and args.tool_worker:
        os.environ["MCP_TOOL_WORKER"] = args.tool_worker
    
    if hasattr(args, 'workers'):
        os.environ["MCP_TOOL_WORKERS"] = str(args.workers)
        
    # 从指定的环境变量前缀读取FastMCP配置
    if hasattr(args, 'fastmcp_env_prefix') and args.fastmcp_env_prefix:
        prefix = args.fastmcp_env_prefix
        logger.info(f"从环境变量前缀 {prefix} 读取FastMCP配置")
        
        # 将带前缀的环境变量映射到FastMCP需要的标准名称
        env_mappings = {
            f"{prefix}_TRANSPORT": "FASTMCP_TRANSPORT",
            f"{prefix}_PORT": "FASTMCP_PORT",
            f"{prefix}_HOST": "FASTMCP_HOST",
            f"{prefix}_WORKERS": "FASTMCP_WORKERS",
            f"{prefix}_LOG_LEVEL": "FASTMCP_LOG_LEVEL",
            f"{prefix}_TIMEOUT_KEEP_ALIVE": "FASTMCP_TIMEOUT_KEEP_ALIVE"
        }
        
        # 复制环境变量
        for src_key, dest_key in env_mappings.items():
            if src_key in os.environ:
                os.environ[dest_key] = os.environ[src_key]
                logger.info(f"设置 {dest_key}={os.environ[src_key]} (从 {src_key})")
    else:
        logger.info("未提供FastMCP环境变量前缀，将使用默认环境变量")

def get_config() -> Dict[str, Any]:
    """获取配置，直接使用环境变量和默认值"""
    # 获取默认配置
    config = get_default_config()
    
    # 输出最终使用的配置（屏蔽敏感信息）
    safe_config = config.copy()
    if "password" in safe_config:
        safe_config["password"] = "******"
    logger.info(f"最终使用配置: {safe_config}")
    
    return config

def get_default_config() -> Dict[str, Any]:
    """获取默认配置，从环境变量中读取"""
    # 处理MYSQL_CACHE_ENABLED环境变量
    cache_enabled_str = os.environ.get("MYSQL_CACHE_ENABLED", "true").lower()
    cache_enabled = cache_enabled_str in ("true", "yes", "y", "t", "1")
    
    # 处理MYSQL_ONLY_SELECT环境变量
    only_select_str = os.environ.get("MYSQL_ONLY_SELECT", "0").lower()
    only_select = only_select_str in ("1", "true", "yes", "y", "t")
    
    return {
        "host": os.environ.get("MYSQL_HOST", ""),
        "database": os.environ.get("MYSQL_DATABASE", ""),
        "username": os.environ.get("MYSQL_USERNAME", ""),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "sqlport": int(os.environ.get("MYSQL_PORT", "3306")),
        "charset": os.environ.get("MYSQL_CHARSET", "utf8mb4"),
        "cache_enabled": cache_enabled,
        "cache_ttl": int(os.environ.get("MYSQL_CACHE_TTL", "300")),
        "connect_timeout": int(os.environ.get("MYSQL_CONNECT_TIMEOUT", "10")),
        "read_timeout": int(os.environ.get("MYSQL_READ_TIMEOUT", "30")),
        "only_select": only_select
    }

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("MYSQL_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 MYSQL_SECURITY_RULES 未设置或为空，所有请求将被允许")
        return []
    
    try:
        logger.info(f"【安全规则】尝试解析安全规则 JSON: {security_rules_json}")
        security_rules = json.loads(security_rules_json)
        
        # 验证结果是否为列表
        if not isinstance(security_rules, list):
            logger.error(f"【安全规则】解析结果不是列表，而是 {type(security_rules).__name__}")
            return []
            
        logger.info(f"【安全规则】成功解析安全规则，共{len(security_rules)}条")
        
        # 验证每条规则的格式
        valid_rules = []
        for i, rule in enumerate(security_rules):
            if not isinstance(rule, dict):
                logger.warning(f"【安全规则】规则#{i+1}不是字典格式，已跳过")
                continue
                
            # 检查必要字段
            if 'type' not in rule or 'value' not in rule:
                logger.warning(f"【安全规则】规则#{i+1}缺少必要字段，已跳过: {rule}")
                continue
                
            logger.info(f"【安全规则】添加有效规则#{i+1}: 类型={rule['type']}, 值={rule['value']}")
            valid_rules.append(rule)
            
        if len(valid_rules) < len(security_rules):
            logger.warning(f"【安全规则】部分规则无效: 有效{len(valid_rules)}/总共{len(security_rules)}")
        elif len(valid_rules) > 0:
            logger.info(f"【安全规则】所有{len(valid_rules)}条规则有效")
        
        return valid_rules
    except json.JSONDecodeError as e:
        logger.error(f"【安全规则】JSON解析失败: {e}")
        logger.error(f"【安全规则】JSON内容: {security_rules_json}")
        return []
    except Exception as e:
        logger.error(f"【安全规则】处理时发生意外错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return []

def check_security(request_info: Dict[str, Any]) -> bool:
    """
    检查请求是否符合安全规则
    
    Args:
        request_info: 请求信息，包含IP地址等
    
    Returns:
        bool: 如果请求符合安全规则则返回True，否则返回False
    """
    rules = get_security_rules()
    
    # 如果没有安全规则，允许所有请求
    if not rules:
        logger.info("未找到安全规则，允许所有请求")
        return True
    
    client_ip = request_info.get("ip", "")
    if not client_ip:
        logger.warning("请求中未包含IP地址信息，拒绝请求")
        return False
    
    for rule in rules:
        rule_type = rule.get("type", "")
        rule_value = rule.get("value", "")
        
        # 简单的规则匹配
        if rule_type == "all" and rule_value == "0.0.0.0/0":
            logger.info("匹配全部放通规则")
            return True
        elif rule_type == "single_ip" and client_ip == rule_value:
            logger.info(f"IP {client_ip} 匹配单IP规则 {rule_value}")
            return True
        elif rule_type == "ip_range":
            # 处理IP范围
            try:
                start_ip, end_ip = rule_value.split("-")
                if is_ip_in_range(client_ip, start_ip.strip(), end_ip.strip()):
                    logger.info(f"IP {client_ip} 匹配IP范围规则 {rule_value}")
                    return True
            except Exception as e:
                logger.error(f"处理IP范围规则时出错: {e}")
        elif rule_type == "subnet":
            # 处理子网
            try:
                if is_ip_in_subnet(client_ip, rule_value):
                    logger.info(f"IP {client_ip} 匹配子网规则 {rule_value}")
                    return True
            except Exception as e:
                logger.error(f"处理子网规则时出错: {e}")
    
    logger.warning(f"IP {client_ip} 不匹配任何安全规则，拒绝请求")
    return False

def is_ip_in_range(ip: str, start_ip: str, end_ip: str) -> bool:
    """检查IP是否在指定范围内"""
    try:
        def ip_to_int(ip_str):
            """将IP转换为整数"""
            return sum(int(octet) << (8 * i) for i, octet in enumerate(reversed(ip_str.split('.'))))
        
        ip_int = ip_to_int(ip)
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        
        return start_int <= ip_int <= end_int
    except Exception as e:
        logger.error(f"检查IP范围时出错: {e}")
        return False

def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    """检查IP是否在指定子网内"""
    try:
        import ipaddress
        network = ipaddress.IPv4Network(subnet, strict=False)
        address = ipaddress.IPv4Address(ip)
        return address in network
    except Exception as e:
        logger.error(f"检查子网时出错: {e}")
        return False
    except ImportError:
        logger.error("缺少ipaddress模块，无法检查子网")
        return False

# 将安全检查装饰器修改为支持异步
def security_check(func):
    """
    安全检查装饰器，用于验证请求是否符合安全规则
    
    Args:
        func: 被装饰的函数
    
    Returns:
        装饰后的函数
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # 记录函数调用信息，用于调试
        func_name = func.__name__
        logger.info(f"【安全检查】执行工具函数: {func_name}")
        logger.info(f"【请求参数】: {kwargs}")
        
        # 获取并记录安全规则
        rules = get_security_rules()
        if not rules:
            logger.info("【安全检查】未找到安全规则，将允许所有请求")
        else:
            logger.info(f"【安全检查】找到{len(rules)}条安全规则")
            # 详细记录每条规则
            for i, rule in enumerate(rules):
                logger.info(f"【安全规则#{i+1}】类型: {rule.get('type', '未知')}, 值: {rule.get('value', '未知')}")
        
        # 由于无法获取客户端IP，我们假定所有请求都通过安全检查
        logger.info("【安全检查】FastMCP SSE连接不提供客户端IP信息，假定请求通过安全检查")
        
        # 调用原函数
        return await func(*args, **kwargs)
    
    return wrapper

def is_select_query(sql: str) -> bool:
    """
    判断SQL是否是只读查询
    
    Args:
        sql: SQL查询语句
    
    Returns:
        bool: 如果是只读查询返回True，否则返回False
    """
    sql = re.sub(r'--.*?$', '', sql, flags=re.MULTILINE)
    sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    
    normalized_sql = sql.strip().lower()
    
    # 检查SQL语句是否以SELECT开头或是其他只读操作
    readonly_prefixes = [
        'select', 'show', 'desc', 'describe', 'explain'
    ]
    
    for prefix in readonly_prefixes:
        if normalized_sql.startswith(prefix):
            return True
    
    # 检查是否包含修改数据的关键字
    modification_keywords = [
        'insert', 'update', 'delete', 'drop', 'create', 
        'alter', 'truncate', 'replace', 'call', 'optimize', 
        'analyze', 'repair', 'grant', 'revoke', 'flush'
    ]
    
    for keyword in modification_keywords:
        pattern = r'\b' + keyword + r'\b'
        if re.search(pattern, normalized_sql):
            return False
    
    # 默认返回True，宁可错误拒绝也不要错误允许
    return True

async def execute_query(config: Dict[str, Any], query: str, params: Optional[List[Any]] = None, database: Optional[str] = None, fetch_all: bool = True) -> Tuple[bool, Any, Optional[str]]:
    """
    异步执行SQL查询
    
    Args:
        config: 数据库配置
        query: SQL查询语句
        params: 查询参数
        database: 要使用的数据库，如果提供则覆盖配置中的数据库
        fetch_all: 是否获取所有结果

    Returns:
        成功标志，结果和错误信息
    """
    conn = None
    try:
        connection_params = {
            "host": config["host"],
            "user": config["username"],
            "password": config["password"],
            "port": config["sqlport"],
            "charset": config["charset"],
            "connect_timeout": config["connect_timeout"],
            "db": database or config["database"],
            "cursorclass": aiomysql.cursors.DictCursor
        }
        
        if not connection_params["db"]:
            del connection_params["db"]
            
        conn = await aiomysql.connect(**connection_params)
        
        async with conn.cursor() as cur:
            # 执行查询
            await cur.execute(query, params or ())
            
            if fetch_all:
                # 获取所有结果
                results = await cur.fetchall()
                
                # 处理特殊类型的数据
                processed_results = []
                for row in results:
                    processed_row = {}
                    for key, value in row.items():
                        # 处理二进制数据
                        if isinstance(value, bytes):
                            value = value.hex()
                        # 处理日期时间对象
                        elif hasattr(value, 'isoformat'):
                            value = value.isoformat()
                        processed_row[key] = value
                    processed_results.append(processed_row)
                
                await conn.commit()
                return True, processed_results, None
            else:
                # 对于非查询操作
                affected_rows = cur.rowcount
                await conn.commit()
                return True, affected_rows, None
    
    except Exception as e:
        logger.error(f"执行查询时出错: {e}")
        traceback.print_exc()
        
        # 尝试回滚事务 (aiomysql的rollback是异步的)
        if conn and conn.get_transaction_status(): # 检查是否有活动事务
            try:
                await conn.rollback()
            except Exception as rb_exc:
                logger.error(f"回滚事务时出错: {rb_exc}")
            
        return False, None, str(e)
    
    finally:
        if conn:
            conn.close()

def register_mysql_tools(app):
    """
    向FastMCP应用注册MySQL工具函数
    
    Args:
        app: FastMCP应用实例
    """
    logger.info("注册MySQL工具函数...")
    
    @app.tool("execute_sql")
    @security_check
    async def execute_sql_tool(sql: str, params: Optional[List[Any]] = None, 
                          database: Optional[str] = None, fetch_all: bool = True) -> Dict[str, Any]:
        """
        执行SQL查询
        
        Args:
            sql: SQL查询语句
            params: 查询参数列表
            database: 数据库名称，如果不提供则使用默认数据库
            fetch_all: 是否获取所有结果
            
        Returns:
            Dict: 包含查询结果和执行信息
        """
        start_time = time.time()
        
        # 获取配置
        config = get_config()
        
        # 参数验证
        if not sql:
            return {"error": {"code": 400, "message": "请提供SQL查询语句"}}
            
        if not config["host"]:
            return {"error": {"code": 400, "message": "未配置MySQL服务器地址"}}
        
        # 检查是否启用了只读模式
        if config.get("only_select", False):
            # 检查SQL是否是只读查询
            if not is_select_query(sql):
                logger.warning(f"尝试执行非查询操作，但服务启用了只读模式: {sql}")
                return {"error": {"code": 403, "message": "拒绝执行：当前服务配置为只读模式，只允许执行SELECT等查询操作"}}
        
        # 检查查询缓存
        cache_key = None
        if config["cache_enabled"] and fetch_all:
            # 使用SQL查询和参数作为缓存键
            cache_key = f"{database or config['database']}:{sql}:{json.dumps(params or [], default=str)}"
            
            if cache_key in query_cache:
                cache_time, cache_data = query_cache[cache_key]
                if time.time() - cache_time < config["cache_ttl"]:
                    logger.info(f"使用缓存数据，键: {cache_key}")
                    return {
                        "data": cache_data,
                        "from_cache": True,
                        "execution_time": time.time() - start_time
                    }
        
        # 执行查询
        success, result, error = await execute_query(config, sql, params, database, fetch_all)
        
        if success:
            # 构建响应
            response_data = {
                "result": result,
                "affected_rows": len(result) if isinstance(result, list) else result,
                "execution_time": time.time() - start_time
            }
            
            # 更新缓存
            if config["cache_enabled"] and fetch_all and cache_key:
                query_cache[cache_key] = (time.time(), response_data)
                
                # 清理过期缓存
                current_time = time.time()
                expired_keys = [k for k, (t, _) in query_cache.items() if current_time - t > config["cache_ttl"]]
                for k in expired_keys:
                    del query_cache[k]
                    
            return {"data": response_data}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"查询执行失败: {error}"}}
    
    @app.tool("list_databases")
    @security_check
    async def list_databases_tool() -> Dict[str, Any]:
        """
        列出所有数据库
        
        Returns:
            Dict: 包含数据库列表
        """
        # 获取配置
        config = get_config()
        
        if not config["host"]:
            return {"error": {"code": 400, "message": "未配置MySQL服务器地址"}}
        
        # 执行查询
        sql = "SHOW DATABASES"
        success, result, error = await execute_query(config, sql)
        
        if success:
            # 提取数据库名称
            databases = [item["Database"] for item in result]
            return {"data": {"databases": databases}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"获取数据库列表失败: {error}"}}
    
    @app.tool("list_tables")
    @security_check
    async def list_tables_tool(database: str) -> Dict[str, Any]:
        """
        列出指定数据库中的所有表
        
        Args:
            database: 数据库名称
            
        Returns:
            Dict: 包含表列表
        """
        # 获取配置
        config = get_config()
        
        if not database:
            return {"error": {"code": 400, "message": "请提供数据库名称"}}
            
        if not config["host"]:
            return {"error": {"code": 400, "message": "未配置MySQL服务器地址"}}
        
        # 执行查询
        sql = "SHOW TABLES"
        success, result, error = await execute_query(config, sql, database=database)
        
        if success:
            # 获取表名列的键名
            table_key = f"Tables_in_{database}"
            
            # 提取表名
            tables = [item[table_key] for item in result]
            return {"data": {"database": database, "tables": tables}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"获取表列表失败: {error}"}}
    
    @app.tool("describe_table")
    @security_check
    async def describe_table_tool(database: str, table: str) -> Dict[str, Any]:
        """
        描述表结构
        
        Args:
            database: 数据库名称
            table: 表名
            
        Returns:
            Dict: 包含表结构信息
        """
        # 获取配置
        config = get_config()
        
        if not database:
            return {"error": {"code": 400, "message": "请提供数据库名称"}}
            
        if not table:
            return {"error": {"code": 400, "message": "请提供表名"}}
            
        if not config["host"]:
            return {"error": {"code": 400, "message": "未配置MySQL服务器地址"}}
        
        # 执行查询获取表结构
        sql = f"DESCRIBE `{table}`"
        success, result, error = await execute_query(config, sql, database=database)
        
        if success:
            # 获取表的外键信息
            fk_sql = """
            SELECT 
                COLUMN_NAME, 
                REFERENCED_TABLE_NAME, 
                REFERENCED_COLUMN_NAME
            FROM 
                INFORMATION_SCHEMA.KEY_COLUMN_USAGE
            WHERE 
                TABLE_SCHEMA = %s 
                AND TABLE_NAME = %s 
                AND REFERENCED_TABLE_NAME IS NOT NULL
            """
            fk_success, fk_result, fk_error = await execute_query(config, fk_sql, [database, table])
            
            # 创建外键字典，键为列名
            foreign_keys = {}
            if fk_success:
                for fk in fk_result:
                    foreign_keys[fk["COLUMN_NAME"]] = {
                        "table": fk["REFERENCED_TABLE_NAME"],
                        "column": fk["REFERENCED_COLUMN_NAME"]
                    }
            
            # 处理列信息
            columns = []
            for col in result:
                column = {
                    "name": col["Field"],
                    "type": col["Type"],
                    "nullable": col["Null"] == "YES",
                    "is_primary_key": col["Key"] == "PRI",
                    "default": col["Default"],
                    "extra": col["Extra"]
                }
                
                # 添加外键信息
                if col["Field"] in foreign_keys:
                    column["references"] = foreign_keys[col["Field"]]
                    
                columns.append(column)
            
            return {"data": {"database": database, "table": table, "columns": columns}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"获取表结构失败: {error}"}}
    
    @app.tool("run_procedure")
    @security_check
    async def run_procedure_tool(procedure: str, params: Optional[List[Any]] = None, 
                            database: Optional[str] = None) -> Dict[str, Any]:
        """
        执行存储过程
        
        Args:
            procedure: 存储过程名称
            params: 存储过程参数列表
            database: 数据库名称
            
        Returns:
            Dict: 包含存储过程执行结果
        """
        start_time = time.time()
        
        # 获取配置
        config = get_config()
        params = params or []
        
        if not procedure:
            return {"error": {"code": 400, "message": "请提供存储过程名称"}}
            
        if not config["host"]:
            return {"error": {"code": 400, "message": "未配置MySQL服务器地址"}}
        
        # 检查是否启用了只读模式
        if config.get("only_select", False):
            logger.warning(f"尝试执行存储过程，但服务启用了只读模式: {procedure}")
            return {"error": {"code": 403, "message": "拒绝执行：当前服务配置为只读模式，不允许执行存储过程"}}
            
        # 构建SQL调用语句
        placeholders = ", ".join(["%s"] * len(params))
        sql = f"CALL `{procedure}`({placeholders})"
        
        # 执行存储过程
        success, result, error = await execute_query(config, sql, params, database)
        
        if success:
            # 构建响应
            return {"data": {"result": result, "execution_time": time.time() - start_time}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"存储过程执行失败: {error}"}}

def main():
    """启动MySQL MCP服务，支持传统单进程模式和Uvicorn模式"""
    # 确保全局logger已正确初始化
    global logger
    if logger is None:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger = logging.getLogger("mysql_server_fallback")
    
    # 解析命令行参数
    args = parse_args()
    args_to_env(args)
    
    # 检查是否使用Uvicorn启动
    use_uvicorn = str(args.uvicorn).lower() in ('true', 'yes', 'y', '1', 't')
    workers = max(1, args.workers)
    port = args.port
    
    # 记录启动信息
    if use_uvicorn:
        logger.info(f"使用Uvicorn启动MySQL MCP服务，端口: {port}，Worker数: {workers}")
    else:
        logger.info(f"使用传统模式启动MySQL MCP服务，端口: {port}")
    
    # 获取配置
    config = get_config()
    
    # 设置基本环境变量
    os.environ["FASTMCP_PORT"] = str(port)
    os.environ["FASTMCP_HOST"] = "0.0.0.0"
    os.environ["FASTMCP_TRANSPORT"] = "sse"
    
    if use_uvicorn and workers > 1:
        os.environ["FASTMCP_WORKERS"] = str(workers)
        logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
    
    try:
        # 创建FastMCP应用实例
        app_instance = FastMCP()
        
        # 注册工具函数
        register_mysql_tools(app_instance)
        
        logger.info(f"MySQL服务器地址: {config['host']}，数据库: {config['database']}")
        logger.info(f"只读模式: {'已启用' if config.get('only_select', False) else '已禁用'}")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{port}/sse")
        
        app_instance.run("sse", port=port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 