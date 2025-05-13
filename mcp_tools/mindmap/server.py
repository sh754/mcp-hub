#!/usr/bin/env python

"""
Markdown思维导图MCP服务
将Markdown文本转换为思维导图HTML
基于已安装的mindmap-mcp-server库实现
"""

import os
import sys
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from functools import wraps
import time

project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

try:
    from mcp_hub.core.logging import get_logger
    logger = get_logger("mindmap_server")
    logger.info("MCP Hub 核心模块导入成功")
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("mindmap_server")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")

try:
    from mindmap_mcp_server.server import FastMCP, convert_markdown_to_mindmap as _convert_markdown_to_mindmap
    logger.info("成功导入mindmap-mcp-server库")
except ImportError as e:
    logger.error(f"导入mindmap-mcp-server库失败: {e}")
    from fastmcp import FastMCP

# 全局配置
RETURN_TYPE = "html"

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Markdown思维导图MCP服务")
    parser.add_argument("--port", type=int, default=5004, help="服务端口号")
    parser.add_argument("--mcp-tool-id", type=str, help="MCP工具ID")
    parser.add_argument("--return-type", choices=["html", "filePath"], default="html", help="返回类型")
    parser.add_argument("--security-rules", type=str, help="安全规则JSON")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则JSON的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="使用Uvicorn启动")
    parser.add_argument("--workers", type=int, default=1, help="Worker数量")
    parser.add_argument("--tool-worker", type=str, help="当前进程是工具worker")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    # 调试日志
    logger.info(f"解析命令行参数: {sys.argv}")
    
    return parser.parse_args()

def args_to_env(args):
    """将命令行参数转换为环境变量"""
    # 设置返回类型环境变量
    os.environ["MINDMAP_RETURN_TYPE"] = args.return_type
    
    # 设置全局变量
    global RETURN_TYPE
    RETURN_TYPE = args.return_type
    
    # 安全规则从命令行参数或指定的环境变量获取
    if args.security_rules:
        # 直接从命令行获取规则
        os.environ["MINDMAP_SECURITY_RULES"] = args.security_rules
        logger.info(f"从命令行参数获取安全规则: {args.security_rules[:100]}..." if len(args.security_rules) > 100 else args.security_rules)
    elif args.security_rules_env and args.security_rules_env in os.environ:
        # 从指定的环境变量读取规则，并复制到标准环境变量
        security_rules = os.environ[args.security_rules_env]
        os.environ["MINDMAP_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过命令行或指定环境变量提供安全规则，检查是否已有 MINDMAP_SECURITY_RULES={os.environ.get('MINDMAP_SECURITY_RULES', '未设置')}")
    
    # 设置MCP工具ID
    if hasattr(args, 'mcp_tool_id') and args.mcp_tool_id:
        os.environ["MCP_TOOL_ID"] = str(args.mcp_tool_id)
    
    # 设置Uvicorn和worker相关环境变量
    if hasattr(args, 'tool_worker') and args.tool_worker:
        if isinstance(args.tool_worker, bool):
            os.environ["MCP_TOOL_WORKER"] = "true" if args.tool_worker else "false"
        else:
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
    
    # 处理uvicorn参数
    if hasattr(args, 'uvicorn'):
        if isinstance(args.uvicorn, bool):
            use_uvicorn = args.uvicorn
        else:
            use_uvicorn = str(args.uvicorn).lower() in ('true', 'yes', 'y', '1', 't')
        
        if use_uvicorn:
            os.environ["FASTMCP_TRANSPORT"] = "sse"
            logger.info("设置FASTMCP_TRANSPORT=sse用于Uvicorn")
    
    return True

def get_default_config() -> Dict[str, Any]:
    """获取默认配置，从环境变量中读取"""
    return {
        "return_type": os.environ.get("MINDMAP_RETURN_TYPE", "html"),
    }

def get_config() -> Dict[str, Any]:
    """获取配置，直接使用环境变量和默认值"""
    # 获取默认配置
    config = get_default_config()
    
    # 输出最终使用的配置
    logger.info(f"最终使用配置: {config}")
    
    return config

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("MINDMAP_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 MINDMAP_SECURITY_RULES 未设置或为空，所有请求将被允许")
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

@security_check
def markdown_to_mindmap(req, resp):
    """
    将Markdown文本转换为思维导图
    
    Args:
        req: 请求对象，包含Markdown文本
        resp: 响应对象
    
    Returns:
        响应对象，包含思维导图HTML或文件路径
    """
    try:
        # 获取Markdown内容
        markdown_content = req.get("markdown_content", "")
        if not markdown_content:
            resp["error"] = {
                "code": 400,
                "message": "请提供Markdown内容"
            }
            return resp
        
        # 获取配置
        config = get_config()
        return_type = req.get("return_type", config.get("return_type", RETURN_TYPE))
        
        # 调用mindmap-mcp-server库的转换函数
        try:
            # 直接使用库中的转换函数
            if '_convert_markdown_to_mindmap' in globals():
                import asyncio
                # 调用库中的转换函数
                result = asyncio.run(_convert_markdown_to_mindmap(markdown_content=markdown_content))
                
                # 根据返回类型处理结果
                if return_type == "html":
                    resp["data"] = {
                        "html": result,
                        "mime_type": "text/html"
                    }
                else:
                    # 使用filePath模式返回路径
                    # 由于原始库返回HTML内容，我们需要将其保存到临时文件
                    import tempfile
                    import os
                    
                    temp_dir = tempfile.mkdtemp(prefix="mindmap-")
                    output_file = os.path.join(temp_dir, "mindmap.html")
                    
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(result)
                    
                    resp["data"] = {
                        "file_path": output_file
                    }
                
                return resp
            else:
                # 如果无法导入转换函数，返回错误
                raise ImportError("未能成功导入mindmap-mcp-server库的转换函数")
                
        except Exception as lib_error:
            logger.error(f"使用mindmap-mcp-server库转换失败: {lib_error}")
            # 继续使用外部命令转换的方式
            resp["error"] = {
                "code": 500,
                "message": f"转换失败: {str(lib_error)}"
            }
            return resp
    
    except Exception as e:
        logger.error(f"转换Markdown到思维导图时出错: {e}")
        resp["error"] = {
            "code": 500,
            "message": f"服务器错误: {str(e)}"
        }
        return resp

def main():
    """主函数，启动Markdown思维导图MCP服务"""
    global RETURN_TYPE
    
    try:
        # 解析命令行参数
        args = parse_args()
        args_to_env(args)
        
        # 设置全局配置
        RETURN_TYPE = args.return_type
        
        # 获取配置
        config = get_config()
        
        # 获取服务端口
        service_port = args.port  # 服务端口
        
        # 检查是否使用Uvicorn启动
        use_uvicorn = str(args.uvicorn).lower() in ('true', 'yes', 'y', '1', 't')
        workers = max(1, args.workers)
        
        # 记录启动信息
        if use_uvicorn:
            logger.info(f"使用Uvicorn启动Markdown思维导图MCP服务，端口: {service_port}，Worker数: {workers}")
        else:
            logger.info(f"使用传统模式启动Markdown思维导图MCP服务，端口: {service_port}")
        
        # 设置基本环境变量
        os.environ["FASTMCP_PORT"] = str(service_port)
        os.environ["FASTMCP_HOST"] = "0.0.0.0"  # 明确设置监听所有网络接口
        os.environ["FASTMCP_TRANSPORT"] = "sse"
        
        # 如果使用Uvicorn且有多个workers，设置相应环境变量
        if use_uvicorn and workers > 1:
            os.environ["FASTMCP_WORKERS"] = str(workers)
            logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
        
        logger.info(f"返回类型: {RETURN_TYPE}")
        
        # 创建MCP服务器实例
        logger.info("正在创建MCP服务器实例...")
        
        # 创建FastMCP应用实例
        app = FastMCP()
        
        # 注册工具函数
        logger.info("注册工具函数...")
        
        @app.tool("markdown_to_mindmap")
        @security_check
        async def markdown_to_mindmap_tool(markdown_content, return_type=None):
            """
            将Markdown文本转换为思维导图
            
            Args:
                markdown_content: Markdown文本内容
                return_type: 返回类型，html或filePath
                
            Returns:
                思维导图HTML或文件路径
            """
            # 创建请求和响应对象
            req = {
                "markdown_content": markdown_content,
                "return_type": return_type or RETURN_TYPE,
                "_client_ip": "127.0.0.1",  # 内部调用默认IP
                "_path": "/sse",
                "_method": "POST",
                "_headers": {}
            }
            resp = {}
            
            # 调用实际处理函数
            result = markdown_to_mindmap(req, resp)
            
            # 如果有错误，抛出异常
            if "error" in result:
                logger.error(f"转换失败: {result['error']}")
                return {"status": "error", "message": result["error"].get("message", "未知错误")}
                
            # 返回数据部分
            if "data" in result:
                return {"status": "success", "data": result["data"]}
                
            return {"status": "error", "message": "处理失败"}
        
        logger.info(f"启动Markdown思维导图MCP服务，服务端口: {service_port}...")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{service_port}/sse")
        
        # 运行服务
        app.run("sse", port=service_port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 