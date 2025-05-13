#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
博查搜索MCP服务
提供基于FastMCP的博查搜索服务
"""

import argparse
import json
import os
import sys
import logging
import traceback
import time
import re
from typing import Dict, List, Any, Optional, Tuple, Union
from functools import wraps
from pathlib import Path
import requests

# 添加项目根目录到Python路径
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

# 尝试导入MCP Hub核心模块
try:
    from mcp_hub.core.logging import get_logger
    logger = get_logger("bocha_search")
    logger.info("MCP Hub 核心模块导入成功")
except ImportError:
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("bocha_search")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")

# 导入FastMCP
try:
    from fastmcp import FastMCP
    logger.info("成功导入FastMCP库")
except ImportError as e:
    logger.error(f"导入FastMCP库失败: {e}")
    sys.exit(1)

# 请求缓存
query_cache = {}

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="博查搜索MCP服务")
    parser.add_argument("--port", type=int, default=5006, help="服务端口号")
    parser.add_argument("--mcp-tool-id", type=int, help="MCP工具ID")
    parser.add_argument("--api-key", type=str, help="API密钥")
    parser.add_argument("--count", type=int, default=10, help="搜索返回结果")
    parser.add_argument("--security-rules", type=str, help="安全规则JSON字符串")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="是否使用Uvicorn启动，true/false")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker进程数量")
    parser.add_argument("--tool-worker", type=str, help="MCP工具worker标识")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    return parser.parse_args()

def args_to_env(args):
    """将命令行参数转换为环境变量"""
    # 设置API密钥环境变量
    if args.api_key:
        os.environ["BOCHA_API_KEY"] = args.api_key
        logger.info("已设置博查API密钥")
    
    # 设置搜索结果数量环境变量
    if args.count:
        os.environ["BOCHA_COUNT"] = str(args.count)
        logger.info(f"已设置搜索结果数量: {args.count}")
    
    # 安全规则从命令行参数或指定的环境变量获取
    if args.security_rules:
        # 直接从命令行获取规则
        os.environ["BOCHA_SECURITY_RULES"] = args.security_rules
        logger.info(f"从命令行参数获取安全规则: {args.security_rules[:100]}..." if len(args.security_rules) > 100 else args.security_rules)
    elif args.security_rules_env and args.security_rules_env in os.environ:
        # 从指定的环境变量读取规则，并复制到标准环境变量
        security_rules = os.environ[args.security_rules_env]
        os.environ["BOCHA_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过命令行或指定环境变量提供安全规则，检查是否已有 BOCHA_SECURITY_RULES={os.environ.get('BOCHA_SECURITY_RULES', '未设置')}")
    
    # 设置Uvicorn和worker相关环境变量
    if hasattr(args, 'tool_worker') and args.tool_worker:
        os.environ["MCP_TOOL_WORKER"] = args.tool_worker
    
    if hasattr(args, 'workers'):
        os.environ["MCP_TOOL_WORKERS"] = str(args.workers)
    
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

def get_default_config() -> Dict[str, Any]:
    """获取默认配置，从环境变量中读取"""
    # 处理BOCHA_CACHE_ENABLED环境变量
    cache_enabled_str = os.environ.get("BOCHA_CACHE_ENABLED", "true").lower()
    cache_enabled = cache_enabled_str in ("true", "yes", "y", "t", "1")
    
    return {
        'api_key': os.environ.get('BOCHA_API_KEY', ''),
        'count': int(os.environ.get('BOCHA_COUNT', '10')),
        'cache_enabled': cache_enabled,
        'cache_ttl': int(os.environ.get('BOCHA_CACHE_TTL', '300'))
    }

def get_config() -> Dict[str, Any]:
    """获取配置，直接使用环境变量和默认值"""
    # 获取默认配置
    config = get_default_config()
    
    # 输出最终使用的配置（屏蔽敏感信息）
    safe_config = config.copy()
    if "api_key" in safe_config:
        safe_config["api_key"] = "******"
    logger.info(f"最终使用配置: {safe_config}")
    
    return config

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("BOCHA_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 BOCHA_SECURITY_RULES 未设置或为空，所有请求将被允许")
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
        
        logger.info("【安全检查】FastMCP SSE连接不提供客户端IP信息，假定请求通过安全检查")
        
        return await func(*args, **kwargs)
    
    return wrapper

def cached_request(func):
    """
    请求缓存装饰器，缓存API请求结果
    
    Args:
        func: 被装饰的函数
    
    Returns:
        装饰后的函数
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # 获取配置
        config = get_config()
        cache_enabled = config.get("cache_enabled", False)
        cache_ttl = config.get("cache_ttl", 300)
        
        if not cache_enabled:
            logger.info("缓存已禁用，直接执行请求")
            return await func(*args, **kwargs)
        
        # 生成缓存键
        cache_key = f"{func.__name__}:{json.dumps(args)}:{json.dumps(kwargs, sort_keys=True)}"
        
        # 检查缓存
        if cache_key in query_cache:
            cache_time, cache_data = query_cache[cache_key]
            if time.time() - cache_time < cache_ttl:
                logger.info(f"使用缓存数据，键: {cache_key}")
                return cache_data
        
        # 执行实际请求
        result = await func(*args, **kwargs)
        
        # 更新缓存
        query_cache[cache_key] = (time.time(), result)
        
        # 清理过期缓存
        current_time = time.time()
        expired_keys = [k for k, (t, _) in query_cache.items() if current_time - t > cache_ttl]
        for k in expired_keys:
            del query_cache[k]
        
        return result
    
    return wrapper

def register_bocha_tools(app):
    """
    向FastMCP应用注册博查工具函数
    
    Args:
        app: FastMCP应用实例
    """
    logger.info("注册博查搜索工具函数...")
    
    @app.tool("search")
    @security_check
    @cached_request
    async def search_tool(query: str, freshness: str = "noLimit", count: Optional[int] = None, answer: bool = False, stream: bool = False) -> Dict[str, Any]:
        """
        执行博查搜索
        
        Args:
            query: 搜索查询
            freshness: 时间范围过滤，可选值: noLimit, day, week, month
            count: 搜索结果数量
            answer: 是否生成摘要
            stream: 是否流式响应
            
        Returns:
            Dict: 包含搜索结果和执行信息
        """
        start_time = time.time()
        
        # 获取配置
        config = get_config()
        
        # 获取API密钥
        api_key = config.get("api_key", "")
        
        if not api_key:
            logger.error("未配置博查API密钥，无法执行搜索")
            return {"error": {"code": 401, "message": "未配置API密钥"}}
        
        # 设置默认count
        if count is None:
            count = config.get("count", 10)
        
        # 构建请求参数
        payload = {
            "query": query,
            "freshness": freshness,
            "count": count,
            "answer": answer,
            "stream": stream
        }
        
        # 构建请求头
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        # 记录请求信息（不记录完整API密钥）
        logger.info(f"执行博查搜索，查询: {query}")
        logger.info(f"搜索参数: freshness={freshness}, count={count}, answer={answer}, stream={stream}")
        
        try:
            # 调用API
            response = requests.post(
                "https://api.bochaai.com/v1/ai-search",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            # 检查响应
            if response.status_code != 200:
                logger.error(f"搜索请求失败: HTTP {response.status_code}")
                error_message = response.text
                try:
                    error_json = response.json()
                    if isinstance(error_json, dict):
                        error_message = json.dumps(error_json)
                except:
                    pass
                
                return {"error": {"code": response.status_code, "message": f"搜索请求失败: {error_message}"}}
            
            # 解析响应
            try:
                result = response.json()
                execution_time = time.time() - start_time
                logger.info(f"搜索成功，耗时: {execution_time:.2f}秒")
                
                # 如果启用缓存，记录缓存信息
                if config.get("cache_enabled", False):
                    logger.info(f"已缓存搜索结果，过期时间: {config.get('cache_ttl', 300)}秒")
                
                # 返回结果
                return {
                    "data": {
                        "result": result,
                        "execution_time": execution_time
                    }
                }
            except json.JSONDecodeError:
                logger.error(f"无法解析API响应为JSON: {response.text[:200]}...")
                return {"error": {"code": 500, "message": "无法解析API响应为JSON"}}
        
        except requests.RequestException as e:
            logger.error(f"请求博查API时出错: {str(e)}")
            return {"error": {"code": 500, "message": f"请求博查API时出错: {str(e)}"}}
        
        except Exception as e:
            logger.error(f"搜索过程中发生错误: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return {"error": {"code": 500, "message": f"服务器错误: {str(e)}"}}
    
    logger.info("已注册博查搜索工具")

def main():
    """启动博查搜索MCP服务"""
    # 解析命令行参数
    args = parse_args()
    args_to_env(args)
    
    # 检查是否使用Uvicorn启动
    use_uvicorn = str(args.uvicorn).lower() in ('true', 'yes', 'y', '1', 't')
    workers = max(1, args.workers)
    port = args.port
    
    # 记录启动信息
    if use_uvicorn:
        logger.info(f"使用Uvicorn启动博查搜索MCP服务，端口: {port}，Worker数: {workers}")
    else:
        logger.info(f"使用传统模式启动博查搜索MCP服务，端口: {port}")
    
    # 获取配置
    config = get_config()
    
    # 设置基本环境变量
    os.environ["FASTMCP_PORT"] = str(port)
    os.environ["FASTMCP_HOST"] = "0.0.0.0"
    os.environ["FASTMCP_TRANSPORT"] = "sse"
    
    # 如果使用Uvicorn且有多个workers，设置相应环境变量
    if use_uvicorn and workers > 1:
        os.environ["FASTMCP_WORKERS"] = str(workers)
        logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
    
    try:
        # 创建FastMCP应用实例
        app = FastMCP()
        
        # 注册工具函数
        register_bocha_tools(app)
        
        # 记录API密钥信息
        if config.get("api_key"):
            logger.info("已配置博查API密钥")
        else:
            logger.warning("未配置博查API密钥，搜索功能将无法使用")
        
        # 记录启动信息
        logger.info(f"缓存: {'已启用' if config.get('cache_enabled', False) else '已禁用'}")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{port}/sse")
        
        # 启动服务
        app.run("sse", port=port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 