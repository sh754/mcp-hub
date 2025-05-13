#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
百度AI搜索MCP服务
提供通过百度AI搜索接口进行搜索的功能
"""

import os
import sys
import argparse
import json
import logging
import requests
import sseclient
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from functools import wraps
import asyncio

project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

try:
    from mcp_hub.core.logging import get_logger
    logger = get_logger("baidu_searcher")
    logger.info("MCP Hub 核心模块导入成功")
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("baidu_searcher")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")

try:
    from fastmcp import FastMCP
    logger.info("成功导入FastMCP库")
except ImportError as e:
    logger.error(f"导入FastMCP库失败: {e}")
    sys.exit(1)

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="百度AI搜索MCP服务")
    parser.add_argument("--port", type=int, default=5003, help="服务端口号")
    parser.add_argument("--mcp-tool-id", type=int, help="MCP工具ID")
    parser.add_argument("--api-key", type=str, help="百度API密钥")
    parser.add_argument("--security-rules", type=str, help="安全规则JSON字符串")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="是否使用Uvicorn启动，true/false")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker进程数量")
    parser.add_argument("--tool-worker", type=str, help="MCP工具worker标识")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    return parser.parse_args()

def args_to_env(args):
    """将命令行参数转换为环境变量"""
    if args.api_key:
        os.environ["BAIDU_API_KEY"] = args.api_key
        logger.info("已设置百度API密钥")
    
    if args.security_rules:
        os.environ["BAIDU_SECURITY_RULES"] = args.security_rules
        logger.info(f"从命令行参数获取安全规则: {args.security_rules[:100]}..." if len(args.security_rules) > 100 else args.security_rules)
    elif args.security_rules_env and args.security_rules_env in os.environ:
        security_rules = os.environ[args.security_rules_env]
        os.environ["BAIDU_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过命令行或指定环境变量提供安全规则，检查是否已有 BAIDU_SECURITY_RULES={os.environ.get('BAIDU_SECURITY_RULES', '未设置')}")
    
    if hasattr(args, 'tool_worker') and args.tool_worker:
        os.environ["MCP_TOOL_WORKER"] = args.tool_worker
    
    if hasattr(args, 'workers'):
        os.environ["MCP_TOOL_WORKERS"] = str(args.workers)
    
    if args.fastmcp_env_prefix:
        prefix = args.fastmcp_env_prefix
        logger.info(f"从环境变量前缀 {prefix} 读取FastMCP配置")
        
        env_mappings = {
            f"{prefix}_TRANSPORT": "FASTMCP_TRANSPORT",
            f"{prefix}_PORT": "FASTMCP_PORT",
            f"{prefix}_HOST": "FASTMCP_HOST",
            f"{prefix}_WORKERS": "FASTMCP_WORKERS",
            f"{prefix}_LOG_LEVEL": "FASTMCP_LOG_LEVEL",
            f"{prefix}_TIMEOUT_KEEP_ALIVE": "FASTMCP_TIMEOUT_KEEP_ALIVE"
        }
        
        for src_key, dest_key in env_mappings.items():
            if src_key in os.environ:
                os.environ[dest_key] = os.environ[src_key]
                logger.info(f"设置 {dest_key}={os.environ[src_key]} (从 {src_key})")
    else:
        logger.info("未提供FastMCP环境变量前缀，将使用默认环境变量")
        
    # 使用工具ID构建环境变量名，从环境变量获取配置
    if args.mcp_tool_id:
        tool_id = args.mcp_tool_id
        logger.info(f"使用MCP工具ID: {tool_id} 构建环境变量名")
        
        # 构建安全规则环境变量名
        security_rules_env_name = f"MCP_TOOL_{tool_id}_SECURITY_RULES"
        if security_rules_env_name in os.environ:
            security_rules = os.environ[security_rules_env_name]
            os.environ["BAIDU_SECURITY_RULES"] = security_rules
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

def get_default_config() -> Dict[str, Any]:
    """获取默认配置，从环境变量中读取"""
    return {
        "api_key": os.environ.get("BAIDU_API_KEY", ""),
    }

def get_config() -> Dict[str, Any]:
    """获取配置，直接使用环境变量和默认值"""
    # 获取默认配置
    config = get_default_config()
    
    # 输出最终使用的配置（隐藏敏感信息）
    if config.get("api_key"):
        logger.info(f"已配置百度API密钥")
    else:
        logger.warning("未配置百度API密钥，无法进行搜索")
    
    return config

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("BAIDU_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 BAIDU_SECURITY_RULES 未设置或为空，所有请求将被允许")
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
        
        if rule_type == "all" and rule_value == "0.0.0.0/0":
            logger.info("匹配全部放通规则")
            return True
        elif rule_type == "single_ip" and client_ip == rule_value:
            logger.info(f"IP {client_ip} 匹配单IP规则 {rule_value}")
            return True
        elif rule_type == "ip_range":
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

def security_check(func):
    """
    安全检查装饰器，用于验证请求是否符合安全规则
    
    Args:
        func: 被装饰的函数
    
    Returns:
        装饰后的函数
    """
    @wraps(func)
    def wrapper(req, resp, *args, **kwargs):
        request_info = {
            "ip": req.get("_client_ip", ""),
            "time": time.time(),
            "path": req.get("_path", ""),
            "method": req.get("_method", ""),
            "headers": req.get("_headers", {})
        }
        
        # 记录请求信息
        logger.info(f"收到请求: {request_info}")
        
        # 尝试获取安全规则并进行检查
        rules = get_security_rules()
        if not rules:
            logger.info("未找到安全规则，将允许所有请求")
        else:
            logger.info(f"找到{len(rules)}条安全规则")
            
            # 检查安全规则
            if not check_security(request_info):
                logger.warning(f"安全检查未通过，拒绝请求: {request_info}")
                resp["error"] = {
                    "code": 403,
                    "message": "拒绝访问：您的IP不在允许列表中"
                }
                return resp
        
        # 安全检查通过，调用原函数
        return func(req, resp, *args, **kwargs)
    
    return wrapper

async def process_sse_events(url, headers):
    """
    处理SSE事件流
    
    Args:
        url: SSE服务URL
        headers: 请求头

    Returns:
        dict: 处理后的结果
    """
    logger.info(f"连接到SSE服务: {url}")
    
    try:
        # 发送请求连接到SSE服务
        response = requests.get(url, headers=headers, stream=True)
        response.raise_for_status()

        # 使用sseclient处理事件流
        client = sseclient.SSEClient(response)
        
        results = []
        for event in client.events():
            if event.event == "message":
                try:
                    data = json.loads(event.data)
                    logger.debug(f"收到SSE事件: {data}")
                    
                    # 处理搜索结果事件
                    if "result" in data and "results" in data["result"]:
                        for result in data["result"]["results"]:
                            results.append(result)
                        
                except json.JSONDecodeError:
                    logger.warning(f"无法解析SSE事件数据: {event.data}")
                except Exception as e:
                    logger.error(f"处理SSE事件时出错: {str(e)}")
            
            elif event.event == "error":
                logger.error(f"SSE服务返回错误: {event.data}")
                return {"status": "error", "message": event.data}
            
            elif event.event == "end":
                logger.info("SSE事件流结束")
                break
        
        return {
            "status": "success",
            "results": results,
            "total": len(results)
        }
    
    except requests.exceptions.RequestException as e:
        logger.error(f"请求SSE服务时出错: {str(e)}")
        return {"status": "error", "message": f"连接服务失败: {str(e)}"}
    except Exception as e:
        logger.error(f"处理SSE事件流时出错: {str(e)}")
        return {"status": "error", "message": f"处理失败: {str(e)}"}

@security_check
def ai_search(req, resp):
    """
    执行百度AI搜索
    
    Args:
        req: 请求对象
        resp: 响应对象
    
    Returns:
        响应对象
    """
    try:
        query = req.get("query", "")
        if not query:
            resp["error"] = {
                "code": 400,
                "message": "请提供搜索查询内容"
            }
            return resp
            
        model = req.get("model", "")
        instruction = req.get("instruction", "")
        temperature = req.get("temperature", 1e-10)
        top_p = req.get("top_p", 1e-10)
        search_domain_filter = req.get("search_domain_filter", [])
        resource_type_filter = req.get("resource_type_filter", [{"type": "web", "top_k": 10}])
        enable_deep_search = req.get("enable_deep_search", True)
        
        config = get_config()
        api_key = config.get('api_key')
        
        if not api_key:
            logger.error("未配置百度API密钥，无法进行搜索")
            resp["error"] = {
                "code": 401,
                "message": "未配置百度API密钥"
            }
            return resp
        
        # 这里我参考的官方: https://cloud.baidu.com/doc/AppBuilder/s/wm88pf14e
        payload = {
            "messages": [
                {
                    "content": query,
                    "role": "user"
                }
            ],
            "stream": False,
            "model": model or "ernie-3.5-8k",
            "enable_corner_markers": True,
            "enable_deep_search": True
        }
        
        if instruction:
            payload["instruction"] = instruction
        if temperature != 1e-10:
            payload["temperature"] = temperature
        if top_p != 1e-10:
            payload["top_p"] = top_p
        if resource_type_filter:
            payload["resource_type_filter"] = resource_type_filter
        if search_domain_filter:
            payload["search_domain_filter"] = search_domain_filter
        payload["enable_deep_search"] = enable_deep_search
            
        url = "https://qianfan.baidubce.com/v2/ai_search/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        masked_api_key = f"{api_key[:4]}****" if len(api_key) > 4 else "****"
        logger.info(f"发送搜索请求到: {url} (API密钥: {masked_api_key})")
        logger.info(f"搜索参数: {json.dumps(payload, ensure_ascii=False)}")
        
        try:
            session = requests.Session()
            response = session.post(
                url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"搜索请求失败: HTTP {response.status_code}")
                error_message = response.text
                try:
                    error_json = response.json()
                    if isinstance(error_json, dict):
                        error_message = json.dumps(error_json)
                except:
                    pass
                resp["error"] = {
                    "code": response.status_code,
                    "message": f"搜索请求失败: {error_message}"
                }
                return resp
            
            # 处理响应
            try:
                result_json = response.json()
                logger.info(f"搜索成功，API返回: {json.dumps(result_json, ensure_ascii=False)[:200]}...")
                
                # 提取搜索结果
                search_results = []
                
                # 如果返回了搜索结果
                if "search_results" in result_json:
                    search_results = result_json["search_results"]
                    logger.info(f"成功获取搜索结果，共 {len(search_results)} 条")
                else:
                    # 尝试从选择的文档中提取结果
                    if "chosen_documents" in result_json:
                        for doc in result_json["chosen_documents"]:
                            search_results.append({
                                "title": doc.get("title", ""),
                                "url": doc.get("url", ""),
                                "snippet": doc.get("content", ""),
                                "source": "chosen_documents"
                            })
                        logger.info(f"从chosen_documents获取搜索结果，共 {len(search_results)} 条")
                
                # 构建响应
                resp["data"] = {
                    "status": "success",
                    "results": search_results,
                    "total": len(search_results),
                    "raw_response": result_json  # 包含原始响应以便客户端处理
                }
                return resp
                
            except json.JSONDecodeError:
                logger.error(f"无法解析API响应为JSON: {response.text[:200]}...")
                resp["error"] = {
                    "code": 500,
                    "message": "无法解析API响应"
                }
                return resp
        
        except Exception as e:
            logger.error(f"执行AI搜索时出错: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            resp["error"] = {
                "code": 500,
                "message": f"服务器错误: {str(e)}"
            }
            return resp
        
    except Exception as e:
        logger.error(f"执行AI搜索时出错: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        resp["error"] = {
            "code": 500,
            "message": f"服务器错误: {str(e)}"
        }
        return resp

def main():
    """主函数，启动百度AI搜索MCP服务"""
    args = parse_args()
    args_to_env(args)
    
    config = get_config()
    
    service_port = args.port
    
    use_uvicorn = str(os.environ.get("FASTMCP_TRANSPORT", "")).lower() == "sse"
    workers = int(os.environ.get("FASTMCP_WORKERS", "1"))
    
    if use_uvicorn:
        logger.info(f"使用Uvicorn启动百度AI搜索MCP服务，端口: {service_port}，Worker数: {workers}")
    else:
        logger.info(f"使用传统模式启动百度AI搜索MCP服务，端口: {service_port}")
    
    os.environ["FASTMCP_PORT"] = str(service_port)
    os.environ["FASTMCP_HOST"] = "0.0.0.0"
    os.environ["FASTMCP_TRANSPORT"] = "sse"
    
    # 如果使用Uvicorn且有多个workers，设置相应环境变量
    if use_uvicorn and workers > 1:
        os.environ["FASTMCP_WORKERS"] = str(workers)
        logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
    
    try:
        # 创建MCP服务器实例
        logger.info("正在创建MCP服务器实例...")
        
        app = FastMCP()
        
        logger.info("注册工具函数...")
        
        @app.tool("AIsearch")
        async def ai_search_tool(query, model="ernie-3.5-8k", instruction="", temperature=0.7, 
                          top_p=0.9, search_domain_filter=None, 
                          resource_type_filter=None, enable_deep_search=True):
            """
            执行百度搜索
            
            Args:
                query: 搜索查询关键词或短语
                model: 指定大语言模型，默认为"ernie-3.5-8k"
                instruction: 控制搜索结果输出风格和格式的指令参数
                temperature: 控制模型输出随机性的采样参数，默认0.7
                top_p: 控制模型输出多样性的核采样参数，默认0.9
                search_domain_filter: 用于限制搜索结果来源的域名过滤列表
                resource_type_filter: 指定搜索资源的类型和每种类型返回的结果数量
                enable_deep_search: 是否启用深度搜索，默认True
            
            Returns:
                搜索结果
            """
            req = {
                "query": query,
                "model": model,
                "instruction": instruction,
                "temperature": temperature,
                "top_p": top_p,
                "search_domain_filter": search_domain_filter or [],
                "resource_type_filter": resource_type_filter or [{"type": "web", "top_k": 10}],
                "enable_deep_search": enable_deep_search,
                "_client_ip": "127.0.0.1", 
                "_path": "/sse",
                "_method": "POST",
                "_headers": {}
            }
            resp = {}
            
            request_info = {
                "ip": req.get("_client_ip", ""),
                "time": time.time(),
                "path": req.get("_path", ""),
                "method": req.get("_method", ""),
                "headers": req.get("_headers", {})
            }
            
            # 记录请求信息
            logger.info(f"收到搜索请求: {query}")
            
            # 如果有安全规则，进行检查
            rules = get_security_rules()
            if rules and not check_security(request_info):
                logger.warning(f"安全检查未通过，拒绝请求")
                return {"status": "error", "message": "拒绝访问：安全检查未通过"}
            
            # 调用实际的处理函数
            result = ai_search(req, resp)
            
            # 如果有错误，抛出异常
            if "error" in result:
                logger.error(f"搜索失败: {result['error']}")
                return {"status": "error", "message": result["error"].get("message", "未知错误")}
            
            # 返回数据部分
            if "data" in result:
                return result["data"]
            
            return {"status": "error", "message": "处理失败"}
        
        logger.info(f"启动百度AI搜索MCP服务，服务端口: {service_port}...")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{service_port}/sse")
        
        app.run("sse", port=service_port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 