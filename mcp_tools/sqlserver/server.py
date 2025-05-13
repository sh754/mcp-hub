#!/usr/bin/env python

"""
SQL Server MCP服务
提供连接和查询SQL Server数据库的能力
"""

import argparse
import json
import os
import sys
import logging
import traceback
import time
import re
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps
from pathlib import Path

try:
    # 尝试导入pyodbc库
    import pyodbc
except ImportError:
    logging.error("缺少pyodbc库，请安装: pip install pyodbc")
    sys.exit(1)

try:
    # 尝试导入MCP Hub核心模块
    from mcp_hub.core.logging import get_logger
    logger = get_logger("sqlserver_server")
except ImportError:
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("sqlserver_server")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")

from fastmcp import FastMCP

# 请求缓存
query_cache = {}

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="SQL Server MCP服务")
    parser.add_argument("--port", type=int, default=5005, help="服务端口号")
    parser.add_argument("--mcp-tool-id", type=int, help="MCP工具ID")
    parser.add_argument("--server", type=str, help="SQL Server服务器地址")
    parser.add_argument("--database", type=str, help="默认数据库名称")
    parser.add_argument("--username", type=str, help="SQL Server用户名")
    parser.add_argument("--password", type=str, help="SQL Server密码")
    parser.add_argument("--driver", type=str, help="ODBC驱动名称")
    parser.add_argument("--sqlport", type=int, help="SQL Server数据库端口")
    parser.add_argument("--encrypt", type=str, choices=["yes", "no"], help="是否加密连接")
    parser.add_argument("--trust-server-certificate", type=str, choices=["yes", "no"], help="是否信任服务器证书")
    parser.add_argument("--cache-enabled", type=str, default="true", help="是否启用查询缓存")
    parser.add_argument("--cache-ttl", type=int, default=300, help="缓存过期时间(秒)")
    parser.add_argument("--timeout", type=int, default=30, help="查询超时时间(秒)")
    parser.add_argument("--only-select", type=str, default="0", help="是否只允许查询(SELECT)操作，1、yes、true表示是，0、no、false表示否")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="是否使用Uvicorn启动，true/false")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker进程数量")
    parser.add_argument("--tool-worker", type=str, help="MCP工具worker标识")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    return parser.parse_args()

def args_to_env(args):
    """将命令行参数转换为环境变量"""
    if args.server:
        os.environ["SQLSERVER_SERVER"] = args.server
    if args.database:
        os.environ["SQLSERVER_DATABASE"] = args.database
    if args.username:
        os.environ["SQLSERVER_USERNAME"] = args.username
    if args.password:
        os.environ["SQLSERVER_PASSWORD"] = args.password
    if args.driver:
        os.environ["SQLSERVER_DRIVER"] = args.driver
    if args.sqlport:
        os.environ["SQLSERVER_SQLPORT"] = str(args.sqlport)
    if args.encrypt:
        os.environ["SQLSERVER_ENCRYPT"] = args.encrypt
    if args.trust_server_certificate:
        os.environ["SQLSERVER_TRUST_SERVER_CERTIFICATE"] = args.trust_server_certificate
    if args.cache_enabled:
        os.environ["SQLSERVER_CACHE_ENABLED"] = args.cache_enabled
    if args.cache_ttl:
        os.environ["SQLSERVER_CACHE_TTL"] = str(args.cache_ttl)
    if args.timeout:
        os.environ["SQLSERVER_TIMEOUT"] = str(args.timeout)
    
    # 处理only_select参数，将各种形式的布尔值转换为0或1
    only_select_value = "0"
    if args.only_select:
        try:
            # 尝试将字符串转换为布尔值
            if args.only_select.lower() in ("1", "true", "yes", "y", "t"):
                only_select_value = "1"
        except:
            pass
    os.environ["SQLSERVER_ONLY_SELECT"] = only_select_value
    
    # 安全规则从指定的环境变量获取
    if args.security_rules_env and args.security_rules_env in os.environ:
        # 从指定的环境变量读取规则，并复制到标准环境变量
        security_rules = os.environ[args.security_rules_env]
        os.environ["SQLSERVER_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过环境变量提供安全规则，检查是否已有 SQLSERVER_SECURITY_RULES={os.environ.get('SQLSERVER_SECURITY_RULES', '未设置')}")
    
    # 从指定的环境变量前缀读取FastMCP配置
    if args.fastmcp_env_prefix:
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
    
    # 设置Uvicorn和worker相关环境变量
    if hasattr(args, 'tool_worker') and args.tool_worker:
        os.environ["MCP_TOOL_WORKER"] = args.tool_worker
    
    if hasattr(args, 'workers'):
        os.environ["MCP_TOOL_WORKERS"] = str(args.workers)
    
    # 使用工具ID构建环境变量名，从环境变量获取配置
    if args.mcp_tool_id:
        tool_id = args.mcp_tool_id
        logger.info(f"使用MCP工具ID: {tool_id} 构建环境变量名")
        
        # 构建安全规则环境变量名
        security_rules_env_name = f"MCP_TOOL_{tool_id}_SECURITY_RULES"
        if security_rules_env_name in os.environ:
            security_rules = os.environ[security_rules_env_name]
            os.environ["SQLSERVER_SECURITY_RULES"] = security_rules
            logger.info(f"从环境变量 {security_rules_env_name} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
        else:
            logger.info(f"环境变量 {security_rules_env_name} 不存在，没有安全规则")
        
        # 构建FastMCP配置环境变量前缀
        fastmcp_env_prefix = f"MCP_TOOL_{tool_id}_FASTMCP"
        
        # 映射FastMCP环境变量
        env_mappings = {
            f"{fastmcp_env_prefix}_TRANSPORT": "FASTMCP_TRANSPORT",
            f"{fastmcp_env_prefix}_PORT": "FASTMCP_PORT",
            f"{fastmcp_env_prefix}_HOST": "FASTMCP_HOST",
            f"{fastmcp_env_prefix}_WORKERS": "FASTMCP_WORKERS",
            f"{fastmcp_env_prefix}_LOG_LEVEL": "FASTMCP_LOG_LEVEL",
            f"{fastmcp_env_prefix}_TIMEOUT_KEEP_ALIVE": "FASTMCP_TIMEOUT_KEEP_ALIVE"
        }
        
        # 复制环境变量
        for src_key, dest_key in env_mappings.items():
            if src_key in os.environ:
                os.environ[dest_key] = os.environ[src_key]
                logger.info(f"设置 {dest_key}={os.environ[src_key]} (从 {src_key})")

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
    # 处理SQLSERVER_CACHE_ENABLED环境变量
    cache_enabled_str = os.environ.get("SQLSERVER_CACHE_ENABLED", "true").lower()
    cache_enabled = cache_enabled_str in ("true", "yes", "y", "t", "1")
    
    # 处理SQLSERVER_ONLY_SELECT环境变量
    only_select_str = os.environ.get("SQLSERVER_ONLY_SELECT", "0").lower()
    only_select = only_select_str in ("1", "true", "yes", "y", "t")
    
    return {
        "server": os.environ.get("SQLSERVER_SERVER", ""),
        "database": os.environ.get("SQLSERVER_DATABASE", ""),
        "username": os.environ.get("SQLSERVER_USERNAME", ""),
        "password": os.environ.get("SQLSERVER_PASSWORD", ""),
        "driver": os.environ.get("SQLSERVER_DRIVER", "ODBC Driver 17 for SQL Server"),
        "sqlport": int(os.environ.get("SQLSERVER_SQLPORT", "1433")),
        "encrypt": os.environ.get("SQLSERVER_ENCRYPT", "yes") == "yes",
        "trust_server_certificate": os.environ.get("SQLSERVER_TRUST_SERVER_CERTIFICATE", "yes") == "yes",
        "cache_enabled": cache_enabled,
        "cache_ttl": int(os.environ.get("SQLSERVER_CACHE_TTL", "300")),
        "timeout": int(os.environ.get("SQLSERVER_TIMEOUT", "30")),
        "only_select": only_select
    }

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("SQLSERVER_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 SQLSERVER_SECURITY_RULES 未设置或为空，所有请求将被允许")
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
        logger.info(f"执行工具函数: {func.__name__}，参数: {kwargs}")
        
        rules = get_security_rules()
        if not rules:
            logger.warning("未找到安全规则，将允许所有请求")
        else:
            logger.info(f"找到{len(rules)}条安全规则")
            
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
    
    # 去除空白字符并转换为小写
    normalized_sql = sql.strip().lower()
    
    # 检查SQL语句是否以SELECT开头或是其他只读操作
    readonly_prefixes = [
        'select', 'with', 'declare', 'exec sp_help', 
        'exec sp_columns', 'exec sp_stored_procedures', 
        'print'
    ]
    
    for prefix in readonly_prefixes:
        if normalized_sql.startswith(prefix):
            return True
    
    modification_keywords = [
        'insert', 'update', 'delete', 'drop', 'create', 
        'alter', 'truncate', 'exec', 'execute', 'sp_'
    ]
    
    for keyword in modification_keywords:
        pattern = r'\b' + keyword + r'\b'
        if re.search(pattern, normalized_sql):
            return False
    
    return True

def build_connection_string(config: Dict[str, Any], database: Optional[str] = None) -> str:
    """构建SQL Server连接字符串"""
    params = {
        "Driver": config["driver"],
        "Server": config["server"],
        "Database": database or config["database"],
        "UID": config["username"],
        "PWD": config["password"],
        "Port": config.get("sqlport", 1433), 
        "Encrypt": "yes" if config["encrypt"] else "no",
        "TrustServerCertificate": "yes" if config["trust_server_certificate"] else "no",
        "Timeout": config["timeout"]
    }
    
    parts = []
    for key, value in params.items():
        if value: 
            if key == "Driver":
                parts.append(f"{key}={{{value}}}")
            else:
                parts.append(f"{key}={value}")
                
    conn_str = ";".join(parts)
    
    # 日志中隐藏密码
    log_conn_str = conn_str.replace(config["password"], "********") if config["password"] else conn_str
    logger.info(f"构建连接字符串: {log_conn_str}")
    
    return conn_str

def execute_query(conn_str: str, query: str, params: Optional[List[Any]] = None, fetch_all: bool = True) -> Tuple[bool, Any, Optional[str]]:
    """
    执行SQL查询
    
    Args:
        conn_str: 连接字符串
        query: SQL查询语句
        params: 查询参数
        fetch_all: 是否获取所有结果

    Returns:
        成功标志，结果和错误信息
    """
    try:
        # 连接数据库
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        # 执行查询
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
            
        # 获取结果
        if fetch_all:
            # 获取列名
            columns = [column[0] for column in cursor.description] if cursor.description else []
            
            # 获取所有行
            rows = cursor.fetchall()
            
            # 转换为字典列表
            results = []
            for row in rows:
                row_dict = {}
                for i, value in enumerate(row):
                    # 处理特殊类型如日期时间和Decimal
                    if isinstance(value, (time.struct_time, )):
                        value = time.strftime("%Y-%m-%d %H:%M:%S", value)
                    elif hasattr(value, 'isoformat'): 
                        value = value.isoformat()
                    elif hasattr(value, '__str__'): 
                        value = str(value)
                    row_dict[columns[i]] = value
                results.append(row_dict)
                
            conn.commit()
            cursor.close()
            conn.close()
            
            return True, results, None
        else:
            affected_rows = cursor.rowcount
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True, affected_rows, None
    
    except Exception as e:
        logger.error(f"执行查询时出错: {e}")
        traceback.print_exc()
        
        # 尝试关闭连接
        try:
            if 'cursor' in locals() and cursor:
                cursor.close()
            if 'conn' in locals() and conn:
                conn.close()
        except:
            pass
            
        return False, None, str(e)

def is_ip_in_range(ip: str, start_ip: str, end_ip: str) -> bool:
    """
    检查IP地址是否在指定的IP范围内
    
    Args:
        ip: 要检查的IP地址
        start_ip: 范围起始IP
        end_ip: 范围结束IP
        
    Returns:
        bool: 如果IP在范围内则返回True，否则返回False
    """
    try:
        # 将IP转换为整数进行比较
        def ip_to_int(ip_addr):
            parts = ip_addr.split('.')
            if len(parts) != 4:
                raise ValueError(f"无效的IP地址格式: {ip_addr}")
            
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        
        ip_int = ip_to_int(ip)
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        
        return start_int <= ip_int <= end_int
    except Exception as e:
        logger.error(f"检查IP范围时出错: {e}")
        return False

def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    """
    检查IP地址是否在指定的子网内
    
    Args:
        ip: 要检查的IP地址
        subnet: 子网，格式为CIDR表示法(如192.168.1.0/24)
        
    Returns:
        bool: 如果IP在子网内则返回True，否则返回False
    """
    try:
        # 解析CIDR格式的子网
        if '/' not in subnet:
            logger.error(f"无效的子网格式，缺少掩码: {subnet}")
            return False
            
        net_addr, mask_bits = subnet.split('/')
        mask_bits = int(mask_bits)
        
        if mask_bits < 0 or mask_bits > 32:
            logger.error(f"无效的掩码位数: {mask_bits}")
            return False
        
        # 计算子网掩码
        mask = ((1 << 32) - 1) - ((1 << (32 - mask_bits)) - 1)
        
        # 将IP转换为整数
        def ip_to_int(ip_addr):
            parts = ip_addr.split('.')
            if len(parts) != 4:
                raise ValueError(f"无效的IP地址格式: {ip_addr}")
            
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        
        ip_int = ip_to_int(ip)
        net_int = ip_to_int(net_addr)
        
        # 检查IP是否在子网内
        return (ip_int & mask) == (net_int & mask)
    except Exception as e:
        logger.error(f"检查子网时出错: {e}")
        return False

# 注册SQL Server工具函数
def register_sqlserver_tools(app):
    """
    向FastMCP应用注册SQL Server工具函数
    
    Args:
        app: FastMCP应用实例
    """
    logger.info("注册SQL Server工具函数...")

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
            
        if not config["server"]:
            return {"error": {"code": 400, "message": "未配置SQL Server服务器地址"}}
        
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
        
        # 构建连接字符串
        conn_str = build_connection_string(config, database)
        
        # 执行查询
        success, result, error = execute_query(conn_str, sql, params, fetch_all)
        
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
        
        if not config["server"]:
            return {"error": {"code": 400, "message": "未配置SQL Server服务器地址"}}
        
        # 构建连接字符串，使用master数据库
        conn_str = build_connection_string(config, "master")
        
        # 执行查询
        sql = "SELECT name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb') ORDER BY name"
        success, result, error = execute_query(conn_str, sql)
        
        if success:
            # 提取数据库名称
            databases = [item["name"] for item in result]
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
            
        if not config["server"]:
            return {"error": {"code": 400, "message": "未配置SQL Server服务器地址"}}
        
        # 构建连接字符串
        conn_str = build_connection_string(config, database)
        
        # 执行查询
        sql = """
        SELECT 
            t.name AS table_name,
            s.name AS schema_name
        FROM 
            sys.tables t
        INNER JOIN 
            sys.schemas s ON t.schema_id = s.schema_id
        ORDER BY 
            s.name, t.name
        """
        success, result, error = execute_query(conn_str, sql)
        
        if success:
            # 构建结果
            tables = [{"schema": item["schema_name"], "name": item["table_name"]} for item in result]
            return {"data": {"database": database, "tables": tables}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"获取表列表失败: {error}"}}
    
    @app.tool("describe_table")
    @security_check
    async def describe_table_tool(database: str, table: str, schema: str = "dbo") -> Dict[str, Any]:
        """
        描述表结构
        
        Args:
            database: 数据库名称
            table: 表名
            schema: 架构名，默认为dbo
            
        Returns:
            Dict: 包含表结构信息
        """
        # 获取配置
        config = get_config()
        
        if not database:
            return {"error": {"code": 400, "message": "请提供数据库名称"}}
            
        if not table:
            return {"error": {"code": 400, "message": "请提供表名"}}
            
        if not config["server"]:
            return {"error": {"code": 400, "message": "未配置SQL Server服务器地址"}}
        
        # 构建连接字符串
        conn_str = build_connection_string(config, database)
        
        # 执行查询
        sql = """
        SELECT 
            c.name AS column_name,
            t.name AS data_type,
            c.max_length,
            c.precision,
            c.scale,
            c.is_nullable,
            CASE WHEN pk.column_id IS NOT NULL THEN 1 ELSE 0 END AS is_primary_key,
            CASE WHEN fk.parent_column_id IS NOT NULL THEN 1 ELSE 0 END AS is_foreign_key,
            OBJECT_NAME(fk.referenced_object_id) AS referenced_table,
            COL_NAME(fk.referenced_object_id, fk.referenced_column_id) AS referenced_column
        FROM 
            sys.columns c
        INNER JOIN 
            sys.types t ON c.user_type_id = t.user_type_id
        INNER JOIN 
            sys.tables tbl ON c.object_id = tbl.object_id
        INNER JOIN 
            sys.schemas s ON tbl.schema_id = s.schema_id
        LEFT JOIN 
            sys.index_columns ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
        LEFT JOIN 
            sys.indexes pk ON pk.object_id = c.object_id AND pk.is_primary_key = 1 AND pk.index_id = ic.index_id
        LEFT JOIN 
            sys.foreign_key_columns fk ON fk.parent_object_id = c.object_id AND fk.parent_column_id = c.column_id
        WHERE 
            tbl.name = ? AND s.name = ?
        ORDER BY 
            c.column_id
        """
        success, result, error = execute_query(conn_str, sql, [table, schema])
        
        if success:
            # 处理结果
            columns = []
            for item in result:
                column = {
                    "name": item["column_name"],
                    "type": item["data_type"],
                    "nullable": bool(item["is_nullable"]),
                    "is_primary_key": bool(item["is_primary_key"]),
                    "is_foreign_key": bool(item["is_foreign_key"])
                }
                
                # 添加类型特定的信息
                if item["data_type"] in ["varchar", "nvarchar", "char", "nchar"]:
                    max_length = item["max_length"]
                    # nvarchar和nchar存储为Unicode，每个字符占用2字节
                    if item["data_type"].startswith("n"):
                        max_length = max_length // 2
                    column["length"] = max_length
                elif item["data_type"] in ["decimal", "numeric"]:
                    column["precision"] = item["precision"]
                    column["scale"] = item["scale"]
                
                # 添加外键信息
                if item["is_foreign_key"]:
                    column["references"] = {
                        "table": item["referenced_table"],
                        "column": item["referenced_column"]
                    }
                
                columns.append(column)
            
            return {"data": {"database": database, "schema": schema, "table": table, "columns": columns}}
        else:
            # 返回错误
            return {"error": {"code": 500, "message": f"获取表结构失败: {error}"}}

def main():
    """主函数，启动SQL Server MCP服务"""
    # 解析命令行参数
    args = parse_args()
    args_to_env(args)
    
    # 获取配置
    config = get_config()
    
    # 获取服务端口和SQL Server端口
    service_port = args.port  # 服务端口
    sqlserver_port = config.get("sqlport", 1433)  # SQL Server数据库端口
    
    # 检查是否使用Uvicorn启动
    use_uvicorn = str(os.environ.get("FASTMCP_TRANSPORT", "")).lower() == "sse"
    workers = int(os.environ.get("FASTMCP_WORKERS", "1"))
    
    # 记录启动信息
    if use_uvicorn:
        logger.info(f"使用Uvicorn启动SQL Server MCP服务，端口: {service_port}，Worker数: {workers}")
    else:
        logger.info(f"使用传统模式启动SQL Server MCP服务，端口: {service_port}")
    
    # 设置基本环境变量
    os.environ["FASTMCP_PORT"] = str(service_port)
    os.environ["FASTMCP_HOST"] = "0.0.0.0"
    os.environ["FASTMCP_TRANSPORT"] = "sse"
    
    # 如果使用Uvicorn且有多个workers，设置相应环境变量
    if use_uvicorn and workers > 1:
        os.environ["FASTMCP_WORKERS"] = str(workers)
        logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
    
    logger.info(f"SQL Server地址: {config['server']}，数据库: {config['database']}，数据库端口: {sqlserver_port}")
    logger.info(f"只读模式: {'已启用' if config.get('only_select', False) else '已禁用'}")
    
    # 创建FastMCP应用实例
    app = FastMCP()
    
    # 注册工具函数
    register_sqlserver_tools(app)
    
    try:
        # 使用FastMCP的run方法，它会根据环境变量决定如何启动
        logger.info(f"启动SQL Server MCP服务，服务端口: {service_port}...")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{service_port}/sse")
        
        app.run("sse", port=service_port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 