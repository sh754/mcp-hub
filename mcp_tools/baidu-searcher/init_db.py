#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
百度AI搜索工具数据库初始化脚本
该脚本在主数据库初始化过程中被调用，用于初始化百度AI搜索工具所需的特定数据
"""
import sys
import os
from pathlib import Path
import json
from typing import Dict, Any

# 添加项目根目录到Python路径
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

from sqlalchemy.orm import Session
from mcp_hub.core.logging import get_logger
from mcp_hub.db.models import MCPTool, SecurityRule

logger = get_logger("baidu_search_init_db")

def init(db: Session) -> None:
    """
    初始化百度AI搜索工具的数据库配置
    
    Args:
        db: SQLAlchemy数据库会话
    """
    logger.info("开始初始化百度AI搜索工具数据...")
    
    try:
        # 查找百度搜索工具
        baidu_search_tool = db.query(MCPTool).filter(
            MCPTool.module_path == "mcp_tools.baidu-searcher"
        ).first()
        
        if not baidu_search_tool:
            # 创建工具配置
            default_config = {
                "api_key": "",
            }
            
            # 如果不存在则创建新的工具记录
            baidu_search_tool = MCPTool(
                name="百度AI搜索",
                description="基于百度AI搜索引擎的高级搜索服务，直接通过SSE连接到百度搜索服务",
                module_path="mcp_tools.baidu-searcher",
                enabled=True,
                port=5003,
                config=default_config,
                is_uvicorn=True,
                worker=2,
                auto_start=False,
                usage_examples="""#### 使用前请在百度开发者平台注册并获取API密钥
#### 注册地址: https://console.bce.baidu.com/ai_apaas/mcpServerCenter/mcp_server_appbuilder_ai_search/detail

#### 在你的LLM客户端中添加以下工具配置：

```json
{
  "type": "function",
  "function": {
    "name": "AIsearch",
    "description": "执行搜索",
    "parameters": {
      "type": "object",
      "properties": {
        "query": {
          "type": "string",
          "description": "搜索查询关键词或短语，用于指定需要搜索的内容。支持自然语言查询，可以包含多个关键词。"
        },
        "model": {
          "type": "string",
          "description": "指定大语言模型对搜索结果进行总结，如'ERNIE-3.5-8K'。默认为空不使用模型总结。"
        },
        "instruction": {
          "type": "string",
          "description": "控制搜索结果输出风格和格式的指令参数。"
        },
        "temperature": {
          "type": "number",
          "description": "控制模型输出随机性的采样参数，取值范围(0,1]。默认值为1e-10。"
        },
        "top_p": {
          "type": "number",
          "description": "控制模型输出多样性的核采样参数，默认值为1e-10。"
        },
        "search_domain_filter": {
          "type": "array",
          "description": "用于限制搜索结果来源的域名过滤列表。",
          "items": {
            "type": "string"
          }
        },
        "resource_type_filter": {
          "type": "array",
          "description": "指定搜索资源的类型和每种类型返回的结果数量，默认为[{\"type\": \"web\",\"top_k\": 10}]",
          "items": {
            "type": "object"
          }
        }
      },
      "required": ["query"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5003/sse"
  }
}
```

#### 亦或者可以简单一点
```json
{
  "mcpServers": {
    "AIsearch": {
      "url": "http://localhost:5003/sse"
    }
  }
}
```

#### 工作原理：
该工具通过直接连接到百度AI搜索SSE服务获取搜索结果，无需安装SDK，简化了依赖管理。
"""
            )
            db.add(baidu_search_tool)
            db.commit()
            logger.info("创建百度AI搜索工具配置")
            
            # 创建安全规则
            security_rule = SecurityRule(
                mcp_tool_id=baidu_search_tool.id,
                name="全部放通",
                rule_type="all",
                value="0.0.0.0/0",
                enabled=True
            )
            db.add(security_rule)
            db.commit()
            logger.info("创建默认安全规则: 全部放通")
        else:
            logger.info("百度AI搜索工具已存在，跳过创建")
            
    except Exception as e:
        logger.error(f"初始化百度AI搜索工具数据时出错: {e}")
        db.rollback()
        raise
    
    logger.info("百度AI搜索工具数据初始化完成")

if __name__ == "__main__":
    # 当脚本直接运行时，创建一个数据库会话并调用初始化函数
    from mcp_hub.db.base import SessionLocal
    
    db = SessionLocal()
    try:
        init(db)
    finally:
        db.close() 