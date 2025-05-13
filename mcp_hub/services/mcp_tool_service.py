import importlib
import subprocess
import sys
import os
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
import json
from pathlib import Path

from ..db.models import MCPTool as MCPToolModel
from ..db.models import SecurityRule as SecurityRuleModel
from ..models.mcp_tool import MCPToolCreate, MCPToolUpdate, SecurityRuleCreate
from ..core.logging import get_logger

logger = get_logger("mcp_tool_service")


class MCPToolService:
    """MCP工具服务"""
    
    @staticmethod
    def get_all_tools(db: Session) -> List[MCPToolModel]:
        """获取所有MCP工具"""
        return db.query(MCPToolModel).all()
    
    @staticmethod
    def get_tool_by_id(db: Session, tool_id: int) -> Optional[MCPToolModel]:
        """根据ID获取MCP工具"""
        return db.query(MCPToolModel).filter(MCPToolModel.id == tool_id).first()
    
    @staticmethod
    def get_tool_by_name(db: Session, name: str) -> Optional[MCPToolModel]:
        """根据名称获取MCP工具"""
        return db.query(MCPToolModel).filter(MCPToolModel.name == name).first()
    
    @staticmethod
    def create_tool(db: Session, tool: MCPToolCreate) -> MCPToolModel:
        """创建新的MCP工具"""
        db_tool = MCPToolModel(**tool.dict())
        db.add(db_tool)
        db.commit()
        db.refresh(db_tool)
        
        return db_tool
    
    @staticmethod
    def update_tool(db: Session, tool_id: int, tool: MCPToolUpdate) -> Optional[MCPToolModel]:
        """更新MCP工具"""
        db_tool = MCPToolService.get_tool_by_id(db, tool_id)
        if not db_tool:
            return None
        
        update_data = tool.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_tool, key, value)
        
        db.commit()
        db.refresh(db_tool)
        
        return db_tool
    
    @staticmethod
    def delete_tool(db: Session, tool_id: int) -> bool:
        """删除MCP工具"""
        db_tool = MCPToolService.get_tool_by_id(db, tool_id)
        if not db_tool:
            return False
        
        db.query(SecurityRuleModel).filter(SecurityRuleModel.mcp_tool_id == tool_id).delete()
        
        db.delete(db_tool)
        db.commit()
        
        return True
    
    @staticmethod
    def add_security_rule(db: Session, tool_id: int, rule: SecurityRuleCreate) -> Optional[SecurityRuleModel]:
        """为MCP工具添加安全规则"""
        db_tool = MCPToolService.get_tool_by_id(db, tool_id)
        if not db_tool:
            return None
        
        db_rule = SecurityRuleModel(**rule.dict(), mcp_tool_id=tool_id)
        db.add(db_rule)
        db.commit()
        db.refresh(db_rule)
        
        return db_rule
    
    @staticmethod
    def delete_security_rule(db: Session, rule_id: int) -> bool:
        """删除安全规则"""
        db_rule = db.query(SecurityRuleModel).filter(SecurityRuleModel.id == rule_id).first()
        if not db_rule:
            return False
        
        tool_id = db_rule.mcp_tool_id
        
        db.delete(db_rule)
        db.commit()
        
        logger.info(f"已删除安全规则 ID: {rule_id} (工具 ID: {tool_id})")
        
        return True
    
    @staticmethod
    def check_security(db: Session, tool_id: int, request_info: Dict[str, Any]) -> Tuple[bool, str]:
        """检查请求是否符合安全规则
        
        参数:
            tool_id: MCP工具ID
            request_info: 包含请求信息的字典(ip, method等)
        
        返回:
            (bool, str): (是否通过, 拒绝原因)
        """
        tool = MCPToolService.get_tool_by_id(db, tool_id)
        if not tool:
            logger.warning(f"MCP工具 (ID: {tool_id}) 不存在")
            return False, "MCP工具不存在"
        
        security_rules = tool.security_rules
        
        if not security_rules:
            logger.info(f"MCP工具 (ID: {tool_id}) 无安全规则，默认允许访问")
            return True, ""
        
        enabled_rules = [rule for rule in security_rules if rule.enabled]
        
        if not enabled_rules:
            logger.info(f"MCP工具 (ID: {tool_id}) 无启用的安全规则，默认允许访问")
            return True, ""
        
        client_ip = request_info.get("ip", "")
        if not client_ip:
            logger.warning("请求信息中未包含IP地址")
            return False, "请求信息不完整"
        
        logger.info(f"检查IP {client_ip} 是否符合MCP工具 (ID: {tool_id}) 的安全规则")
        
        for rule in enabled_rules:
            rule_type = rule.rule_type
            rule_value = rule.value or ""
            
            if rule_type == "all":
                logger.info(f"安全规则 '{rule.name}' 允许所有IP，放行请求")
                return True, ""
            
            elif rule_type == "single_ip" and rule_value == client_ip:
                logger.info(f"安全规则 '{rule.name}' 匹配单个IP {client_ip}，放行请求")
                return True, ""
            
            elif rule_type == "ip_range":
                try:
                    ip_range = rule_value.split("-")
                    if len(ip_range) == 2:
                        if MCPToolService.is_ip_in_range(client_ip, ip_range[0].strip(), ip_range[1].strip()):
                            logger.info(f"安全规则 '{rule.name}' 匹配IP范围 {rule_value}，放行请求")
                            return True, ""
                except Exception as e:
                    logger.error(f"检查IP范围时出错: {e}")
            
            elif rule_type == "subnet":
                try:
                    if MCPToolService.is_ip_in_subnet(client_ip, rule_value):
                        logger.info(f"安全规则 '{rule.name}' 匹配子网 {rule_value}，放行请求")
                        return True, ""
                except Exception as e:
                    logger.error(f"检查子网时出错: {e}")
        
        logger.warning(f"IP {client_ip} 不匹配任何安全规则，拒绝访问")
        return False, f"IP {client_ip} 不在允许访问的范围内"
    
    @staticmethod
    def is_ip_in_range(ip: str, start_ip: str, end_ip: str) -> bool:
        """检查IP是否在指定范围内"""
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            return start_int <= ip_int <= end_int
        except Exception as e:
            logger.error(f"IP范围检查失败: {e}")
            return False
    
    @staticmethod
    def is_ip_in_subnet(ip: str, subnet: str) -> bool:
        """检查IP是否在指定子网内"""
        try:
            return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet, strict=False)
        except Exception as e:
            logger.error(f"子网检查失败: {e}")
            return False
    
    _tool_pid_map = {}
    
    @staticmethod
    def start_tool(tool_id: int, db: Session) -> bool:
        """启动MCP工具服务"""
        tool = MCPToolService.get_tool_by_id(db, tool_id)
        if not tool or not tool.enabled:
            return False
        
        try:
            module_parts = tool.module_path.split('.')
            module_path = '.'.join(module_parts[:-1])
            module_name = module_parts[-1]
            
            logger.info(f"尝试启动MCP工具: {tool.name} (模块: {tool.module_path})")
            
            try:
                module = importlib.import_module(tool.module_path)
                logger.info(f"模块 {tool.module_path} 已找到")
            except ImportError as ie:
                logger.error(f"导入模块 {tool.module_path} 失败: {ie}")
                return False
            
            command = [
                sys.executable,
                "-m",
                tool.module_path,
                "--port",
                str(tool.port)
            ]
            
            config = {}
            if tool.config:
                if isinstance(tool.config, dict):
                    config = tool.config
                elif isinstance(tool.config, str):
                    try:
                        config = json.loads(tool.config)
                    except:
                        logger.warning(f"工具配置JSON解析失败: {tool.config}")
            
            for key, value in config.items():
                param_key = key.replace('_', '-')
                if value is None:
                    continue
                if isinstance(value, bool):
                    value = "true" if value else "false"
                command.extend([f"--{param_key}", str(value)])
            
            security_rules = []
            for rule in tool.security_rules:
                if rule.enabled:
                    if rule.rule_type == "all" and rule.value == "0.0.0.0/0":
                        security_rules = [{"type": "all", "value": "0.0.0.0/0"}]
                        break
                    security_rules.append({
                        "type": rule.rule_type,
                        "value": rule.value
                    })
            
            security_rules_json = ""
            if security_rules:
                security_rules_json = json.dumps(security_rules)
                security_rules_env_name = f"MCP_TOOL_{tool.id}_SECURITY_RULES"
                logger.info(f"工具启动时传递安全规则: {security_rules_json}")
            else:
                logger.info("工具没有启用的安全规则，将允许所有访问")
            
            logger.info(f"执行命令: {' '.join(command)}")

            env = os.environ.copy()
            
            if "DATABASE_URL" not in env and os.environ.get("DATABASE_URL"):
                env["DATABASE_URL"] = os.environ.get("DATABASE_URL")
                
            if security_rules_json:
                env[security_rules_env_name] = security_rules_json
                command.extend(["--security-rules-env", security_rules_env_name])
            
            if tool.is_uvicorn:
                fastmcp_env_prefix = f"MCP_TOOL_{tool.id}_FASTMCP"
                env[f"{fastmcp_env_prefix}_TRANSPORT"] = "sse"
                env[f"{fastmcp_env_prefix}_PORT"] = str(tool.port)
                env[f"{fastmcp_env_prefix}_HOST"] = "0.0.0.0"
                
                if tool.worker > 1:
                    env[f"{fastmcp_env_prefix}_WORKERS"] = str(tool.worker)
                    logger.info(f"设置 {fastmcp_env_prefix}_WORKERS 环境变量为 {tool.worker}")
                
                env[f"{fastmcp_env_prefix}_LOG_LEVEL"] = "INFO"
                env[f"{fastmcp_env_prefix}_TIMEOUT_KEEP_ALIVE"] = "120"
                
                command.extend(["--fastmcp-env-prefix", fastmcp_env_prefix])
                
                logger.info(f"传递Uvicorn环境变量前缀: {fastmcp_env_prefix}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env
            )
            
            import threading

            def log_stream(stream, stream_name):
                try:
                    for line in iter(stream.readline, ''):
                        if line:
                             log_prefix = f"MCPTool [{tool.name}/{process.pid}/{stream_name}]"
                             logger.info(f"{log_prefix}: {line.strip()}")
                except Exception as e:
                    logger.error(f"读取 {stream_name} 流时出错: {e}")
                finally:
                    stream.close()

            stdout_thread = threading.Thread(target=log_stream, args=(process.stdout, "stdout"), daemon=True)
            stderr_thread = threading.Thread(target=log_stream, args=(process.stderr, "stderr"), daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            import time
            import psutil

            time.sleep(3)

            try:
                p = psutil.Process(process.pid)
                if p.is_running():
                    MCPToolService._tool_pid_map[tool_id] = process.pid
                    logger.info(f"MCP工具 {tool.name} 进程已启动，PID: {process.pid}")

                    port_listening = False
                    check_start_time = time.time()
                    while time.time() - check_start_time < 10:
                        try:
                            for conn in psutil.net_connections(kind='inet'):
                                if conn.laddr.port == tool.port and conn.status == 'LISTEN':
                                    logger.info(f"端口 {tool.port} 已在监听状态")
                                    port_listening = True
                                    break
                            if port_listening:
                                break
                        except Exception as conn_e:
                             logger.warning(f"检查端口连接时出错: {conn_e}")
                        time.sleep(0.5)

                    if port_listening:
                         return True
                    else:
                         logger.warning(f"进程已启动，但端口 {tool.port} 在10秒内未进入监听状态")
                         return True
                else:
                    exit_code = process.poll()
                    logger.error(f"MCP工具 {tool.name} 进程启动后立即退出，退出代码: {exit_code}")
                    return False
            except psutil.NoSuchProcess:
                logger.error(f"MCP工具 {tool.name} 进程启动后立即退出 (NoSuchProcess)")
                return False

        except Exception as e:
            logger.error(f"启动MCP工具 {tool.name} 失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    @staticmethod
    def stop_tool(tool_id: int) -> bool:
        """停止MCP工具服务"""
        pid = MCPToolService._tool_pid_map.get(tool_id)
        if not pid:
            logger.warning(f"未找到MCP工具 (ID: {tool_id}) 的进程ID")
            return False
        
        try:
            import psutil
            process = psutil.Process(int(pid))
            process.terminate()
            
            process.wait(timeout=5)
            
            if tool_id in MCPToolService._tool_pid_map:
                del MCPToolService._tool_pid_map[tool_id]
            logger.info(f"MCP工具 (ID: {tool_id}) 已停止")
            
            return True
        
        except psutil.NoSuchProcess:
            if tool_id in MCPToolService._tool_pid_map:
                del MCPToolService._tool_pid_map[tool_id]
            logger.info(f"MCP工具 (ID: {tool_id}) 进程已不存在")
            return True
        
        except Exception as e:
            logger.error(f"停止MCP工具 (ID: {tool_id}) 失败: {e}")
            return False
    
    @staticmethod
    def get_tool_status(tool_id: int, db: Session) -> Dict[str, Any]:
        """获取MCP工具状态"""
        pid = MCPToolService._tool_pid_map.get(tool_id)
        if not pid:
            return {"status": "stopped", "pid": None}
        
        try:
            import psutil
            process = psutil.Process(int(pid))
            if process.is_running():
                if "python" not in process.name().lower():
                    logger.warning(f"进程 {pid} 不是Python进程，名称为: {process.name()}")
                    if tool_id in MCPToolService._tool_pid_map:
                        del MCPToolService._tool_pid_map[tool_id]
                    return {"status": "stopped", "pid": None}
                
                try:
                    tool = MCPToolService.get_tool_by_id(db, tool_id)
                    if tool:
                        tool_port = tool.port
                        port_listening = False
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.laddr.port == tool_port and conn.status == 'LISTEN':
                                port_listening = True
                                break
                        
                        if not port_listening:
                            logger.warning(f"进程 {pid} 存在，但端口 {tool_port} 未监听")
                            return {
                                "status": "starting",
                                "pid": pid,
                                "started": process.create_time()
                            }
                except Exception as e:
                    logger.error(f"检查端口监听状态失败: {e}")
                
                return {
                    "status": "running",
                    "pid": pid,
                    "started": process.create_time()
                }
            else:
                if tool_id in MCPToolService._tool_pid_map:
                    del MCPToolService._tool_pid_map[tool_id]
                return {"status": "stopped", "pid": None}
        
        except (psutil.NoSuchProcess, ValueError):
            if tool_id in MCPToolService._tool_pid_map:
                del MCPToolService._tool_pid_map[tool_id]
            return {"status": "stopped", "pid": None}
        
        except Exception as e:
            logger.error(f"获取MCP工具 (ID: {tool_id}) 状态失败: {e}")
            return {"status": "unknown", "error": str(e)}