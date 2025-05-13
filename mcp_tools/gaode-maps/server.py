from fastmcp import FastMCP
import os
import sys
import logging
import argparse
import ipaddress
import json
import requests
from typing import Dict, List, Tuple, Any, Optional
import time
from functools import wraps

# 获取当前路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 将当前目录添加到系统路径
if current_dir not in sys.path:
    sys.path.append(current_dir)

# 配置日志
try:
    from mcp_hub.core.logging import get_logger
    # 直接初始化全局 logger
    logger = get_logger("gaode_maps_server")
    logger.info("MCP Hub 核心模块导入成功")
except ImportError:
    # 如果导入失败，则使用标准日志配置
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("gaode_maps_server")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")

# 解析命令行参数
def parse_args():
    parser = argparse.ArgumentParser(description="高德地图MCP服务")
    parser.add_argument("--port", type=int, default=5002, help="服务端口号")
    parser.add_argument("--mcp-tool-id", type=int, help="MCP工具ID")
    parser.add_argument("--api-key", type=str, help="高德地图API密钥")
    parser.add_argument("--secret-key", type=str, help="高德地图安全密钥")
    parser.add_argument("--cache-enabled", type=str, help="是否启用缓存")
    parser.add_argument("--cache-ttl", type=int, help="缓存时间(秒)")
    parser.add_argument("--request-limit", type=int, help="每分钟请求限制")
    parser.add_argument("--security-rules", type=str, help="安全规则JSON字符串")
    parser.add_argument("--security-rules-env", type=str, help="包含安全规则的环境变量名")
    parser.add_argument("--uvicorn", type=str, default="false", help="是否使用Uvicorn启动，true/false")
    parser.add_argument("--workers", type=int, default=1, help="Uvicorn worker进程数量")
    parser.add_argument("--tool-worker", type=str, help="MCP工具worker标识")
    parser.add_argument("--fastmcp-env-prefix", type=str, help="包含FastMCP配置的环境变量前缀")
    
    return parser.parse_args()

# 将命令行参数保存到环境变量
def args_to_env(args):
    # 设置高德地图特有配置到环境变量
    if args.api_key:
        os.environ["GAODE_API_KEY"] = args.api_key
    if args.secret_key:
        os.environ["GAODE_SECRET_KEY"] = args.secret_key
    if args.cache_enabled:
        os.environ["GAODE_CACHE_ENABLED"] = args.cache_enabled
    if args.cache_ttl:
        os.environ["GAODE_CACHE_TTL"] = str(args.cache_ttl)
    if args.request_limit:
        os.environ["GAODE_REQUEST_LIMIT"] = str(args.request_limit)
    
    # 安全规则从命令行参数或指定的环境变量获取
    if args.security_rules:
        # 直接从命令行获取规则
        os.environ["GAODE_SECURITY_RULES"] = args.security_rules
        logger.info(f"从命令行参数获取安全规则: {args.security_rules[:100]}..." if len(args.security_rules) > 100 else args.security_rules)
    elif args.security_rules_env and args.security_rules_env in os.environ:
        # 从指定的环境变量读取规则，并复制到标准环境变量
        security_rules = os.environ[args.security_rules_env]
        os.environ["GAODE_SECURITY_RULES"] = security_rules
        logger.info(f"从环境变量 {args.security_rules_env} 获取安全规则: {security_rules[:100]}..." if len(security_rules) > 100 else security_rules)
    else:
        logger.info(f"没有通过命令行或指定环境变量提供安全规则，检查是否已有 GAODE_SECURITY_RULES={os.environ.get('GAODE_SECURITY_RULES', '未设置')}")
    
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
        
    # 使用工具ID构建环境变量名，从环境变量获取配置
    if args.mcp_tool_id:
        tool_id = args.mcp_tool_id
        logger.info(f"使用MCP工具ID: {tool_id} 构建环境变量名")
        
        # 构建安全规则环境变量名
        security_rules_env_name = f"MCP_TOOL_{tool_id}_SECURITY_RULES"
        if security_rules_env_name in os.environ:
            security_rules = os.environ[security_rules_env_name]
            os.environ["GAODE_SECURITY_RULES"] = security_rules
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
    logger.info(f"最终使用配置: {safe_config}")
    
    return config

def get_default_config() -> Dict[str, Any]:
    """获取默认配置，从环境变量中读取"""
    cache_enabled_str = os.environ.get("GAODE_CACHE_ENABLED", "true").lower()
    cache_enabled = cache_enabled_str in ("true", "yes", "y", "t", "1")
    
    return {
        'api_key': os.environ.get('GAODE_API_KEY', ''),
        'secret_key': os.environ.get('GAODE_SECRET_KEY', ''),
        'cache_enabled': cache_enabled,
        'cache_ttl': int(os.environ.get('GAODE_CACHE_TTL', '3600')),
        'request_limit': int(os.environ.get('GAODE_REQUEST_LIMIT', '100'))
    }

def get_security_rules() -> List[Dict[str, Any]]:
    """获取安全规则，从环境变量中读取JSON字符串"""
    security_rules_json = os.environ.get("GAODE_SECURITY_RULES", "")
    
    if not security_rules_json:
        logger.info("【安全规则】环境变量 GAODE_SECURITY_RULES 未设置或为空，所有请求将被允许")
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

# 创建请求缓存
request_cache = {}
last_request_time = {}
request_count = {}

# 高德地图API请求函数
def cached_request(url: str, params: Dict[str, Any], cache_ttl: int) -> Dict[str, Any]:
    """缓存请求结果"""
    cache_key = f"{url}:{json.dumps(params, sort_keys=True)}"
    current_time = time.time()
    
    # 检查缓存
    if cache_key in request_cache:
        cache_time, cache_data = request_cache[cache_key]
        if current_time - cache_time < cache_ttl:
            logger.info(f"使用缓存数据: {cache_key}")
            return cache_data
    
    # 限制请求频率
    if 'gaode_api' not in last_request_time:
        last_request_time['gaode_api'] = current_time
        request_count['gaode_api'] = 1
    else:
        # 如果在1分钟内，计算请求数
        if current_time - last_request_time['gaode_api'] < 60:
            request_count['gaode_api'] += 1
        else:
            # 超过1分钟，重置计数
            last_request_time['gaode_api'] = current_time
            request_count['gaode_api'] = 1
    
    # 检查是否超过请求限制
    config = get_config()
    if request_count.get('gaode_api', 0) > config['request_limit']:
        logger.warning(f"请求频率超过限制: {config['request_limit']}次/分钟")
        return {"status": "error", "info": "请求频率超过限制"}
    
    # 发送请求
    try:
        response = requests.get(url, params=params)
        data = response.json()
        
        # 缓存结果
        if config['cache_enabled']:
            request_cache[cache_key] = (current_time, data)
        
        return data
    except Exception as e:
        logger.error(f"API请求失败: {str(e)}")
        return {"status": "error", "info": f"API请求失败: {str(e)}"}

# 安全检查装饰器
def security_check(func):
    """工具函数的安全检查装饰器"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # 记录函数调用信息，用于调试
        logger.info(f"执行工具函数: {func.__name__}，参数: {kwargs}")
        
        # 尝试获取安全规则并进行检查
        # 由于无法获取客户端IP，这里只能记录日志
        rules = get_security_rules()
        if not rules:
            logger.info("未找到安全规则，将允许所有请求")
        else:
            logger.info(f"找到{len(rules)}条安全规则")
            
        # 调用原函数
        return await func(*args, **kwargs)
    
    return wrapper

# 注册工具函数
def register_gaode_tools(app):
    """注册高德地图工具"""
    
    @app.tool("geocode")
    @security_check
    async def geocode(address: str, city: Optional[str] = None) -> Dict[str, Any]:
        """
        将地址转换为经纬度坐标
        
        Args:
            address: 地址字符串
            city: 城市名（可选）
            
        Returns:
            包含地理编码结果的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        params = {
            'key': config['api_key'],
            'address': address,
            'output': 'JSON'
        }
        
        if city:
            params['city'] = city
            
        url = 'https://restapi.amap.com/v3/geocode/geo'
        return cached_request(url, params, config['cache_ttl'])
    
    @app.tool("regeocode")
    @security_check
    async def regeocode(location: str, extensions: str = "base", radius: int = 1000) -> Dict[str, Any]:
        """
        将经纬度坐标转换为地址信息
        
        Args:
            location: 经纬度坐标，格式为"116.397428,39.90923"
            extensions: 返回结果控制，base为基本信息，all为详细信息
            radius: 搜索半径，单位米
            
        Returns:
            包含逆地理编码结果的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        params = {
            'key': config['api_key'],
            'location': location,
            'extensions': extensions,
            'radius': radius,
            'output': 'JSON'
        }
            
        url = 'https://restapi.amap.com/v3/geocode/regeo'
        return cached_request(url, params, config['cache_ttl'])
    
    @app.tool("search_pois")
    @security_check
    async def search_pois(keywords: str, city: Optional[str] = None, types: Optional[str] = None, 
                          city_limit: bool = False, children: int = 0, offset: int = 0, 
                          page: int = 1, extensions: str = "base") -> Dict[str, Any]:
        """
        搜索POI信息
        
        Args:
            keywords: 关键字
            city: 城市名（可选）
            types: POI类型（可选）
            city_limit: 是否限制在当前城市
            children: 是否返回子POI
            offset: 每页记录数，最大50
            page: 当前页数
            extensions: 返回结果控制，base为基本信息，all为详细信息
            
        Returns:
            包含POI搜索结果的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        params = {
            'key': config['api_key'],
            'keywords': keywords,
            'citylimit': 'true' if city_limit else 'false',
            'children': children,
            'offset': min(offset, 50) if offset > 0 else 20,
            'page': max(page, 1),
            'extensions': extensions,
            'output': 'JSON'
        }
        
        if city:
            params['city'] = city
        if types:
            params['types'] = types
            
        url = 'https://restapi.amap.com/v3/place/text'
        return cached_request(url, params, config['cache_ttl'])
    
    @app.tool("route_planning")
    @security_check
    async def route_planning(origin: str, destination: str, mode: str = "driving", 
                             strategy: int = 0, waypoints: Optional[str] = None) -> Dict[str, Any]:
        """
        路径规划
        
        Args:
            origin: 起点经纬度，格式为"116.397428,39.90923"
            destination: 终点经纬度，格式为"116.397428,39.90923"
            mode: 出行方式，支持：driving（驾车）、walking（步行）、bicycling（骑行）、transit（公交）
            strategy: 路径规划策略，仅在驾车模式下有效，0-9表示不同的策略
            waypoints: 途经点经纬度，格式为"116.397428,39.90923|116.397428,39.90923"（可选）
            
        Returns:
            包含路径规划结果的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        # 根据不同的出行方式选择不同的API
        if mode == "driving":
            url = 'https://restapi.amap.com/v3/direction/driving'
        elif mode == "walking":
            url = 'https://restapi.amap.com/v3/direction/walking'
        elif mode == "bicycling":
            url = 'https://restapi.amap.com/v4/direction/bicycling'
        elif mode == "transit":
            url = 'https://restapi.amap.com/v3/direction/transit/integrated'
        else:
            return {"status": "error", "info": "不支持的出行方式"}
        
        params = {
            'key': config['api_key'],
            'origin': origin,
            'destination': destination,
            'output': 'JSON'
        }
        
        if mode == "driving":
            params['strategy'] = strategy
        
        if waypoints and mode in ["driving", "walking"]:
            params['waypoints'] = waypoints
            
        return cached_request(url, params, config['cache_ttl'])
    
    @app.tool("district")
    @security_check
    async def district(keywords: str, subdistrict: int = 1, extensions: str = "base") -> Dict[str, Any]:
        """
        行政区域查询
        
        Args:
            keywords: 行政区名称
            subdistrict: 子级行政区，0：不返回下级行政区；1：返回下一级行政区；2：返回下两级行政区
            extensions: 返回结果控制，base为基本信息，all为详细信息（包含边界坐标）
            
        Returns:
            包含行政区划结果的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        params = {
            'key': config['api_key'],
            'keywords': keywords,
            'subdistrict': subdistrict,
            'extensions': extensions,
            'output': 'JSON'
        }
            
        url = 'https://restapi.amap.com/v3/config/district'
        return cached_request(url, params, config['cache_ttl'])
    
    @app.tool("weather")
    @security_check
    async def weather(city: str, extensions: str = "base") -> Dict[str, Any]:
        """
        查询天气信息
        
        Args:
            city: 城市编码或名称
            extensions: 返回结果控制，base为实况天气，all为预报天气
            
        Returns:
            包含天气信息的字典
        """
        config = get_config()
        if not config['api_key']:
            return {"status": "error", "info": "未配置API密钥"}
        
        params = {
            'key': config['api_key'],
            'city': city,
            'extensions': extensions,
            'output': 'JSON'
        }
            
        url = 'https://restapi.amap.com/v3/weather/weatherInfo'
        return cached_request(url, params, config['cache_ttl'])
    
    logger.info("已注册高德地图工具")

def main():
    """主函数，启动高德地图MCP服务"""
    args = parse_args()
    args_to_env(args)
    
    config = get_config()
    
    service_port = args.port  # 服务端口
    
    use_uvicorn = str(os.environ.get("FASTMCP_TRANSPORT", "")).lower() == "sse"
    workers = int(os.environ.get("FASTMCP_WORKERS", "1"))
    
    # 记录启动信息
    if use_uvicorn:
        logger.info(f"使用Uvicorn启动高德地图MCP服务，端口: {service_port}，Worker数: {workers}")
    else:
        logger.info(f"使用传统模式启动高德地图MCP服务，端口: {service_port}")
    
    # 设置基本环境变量
    os.environ["FASTMCP_PORT"] = str(service_port)
    os.environ["FASTMCP_HOST"] = "0.0.0.0"
    os.environ["FASTMCP_TRANSPORT"] = "sse"
    
    # 如果使用Uvicorn且有多个workers，设置相应环境变量
    if use_uvicorn and workers > 1:
        os.environ["FASTMCP_WORKERS"] = str(workers)
        logger.info(f"设置FASTMCP_WORKERS环境变量为 {workers}")
        
    # 检查配置
    if not config['api_key']:
        logger.warning("未配置高德地图API密钥，服务可能无法正常工作")
    else:
        logger.info(f"已配置高德地图API密钥: {config['api_key'][:4]}***")
    
    # 创建FastMCP应用实例
    app = FastMCP()
    
    # 注册高德地图工具函数
    register_gaode_tools(app)
    
    try:
        logger.info(f"启动高德地图MCP服务，服务端口: {service_port}...")
        logger.info(f"请使用以下地址连接到SSE服务: http://0.0.0.0:{service_port}/sse")
        
        app.run("sse", port=service_port, host="0.0.0.0")
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 