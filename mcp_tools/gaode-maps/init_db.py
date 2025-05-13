#!/usr/bin/env python

"""
高德地图工具数据库初始化脚本
该脚本在主数据库初始化过程中被调用，用于初始化高德地图工具所需的特定数据
"""
import sys
import os
from pathlib import Path
import json
from typing import Dict, Any, Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

from sqlalchemy.orm import Session
from sqlalchemy import inspect
from mcp_hub.core.logging import get_logger
from mcp_hub.db.models import MCPTool, SecurityRule

logger = get_logger("gaode_maps_init_db")

def init(db: Session) -> None:
    """
    初始化高德地图工具的数据库配置
    
    Args:
        db: SQLAlchemy数据库会话
    """
    logger.info("开始初始化高德地图工具数据...")
    
    try:
        # 查找高德地图工具
        gaode_maps_tool = db.query(MCPTool).filter(
            MCPTool.module_path == "mcp_tools.gaode-maps"
        ).first()
        
        if not gaode_maps_tool:
            # 创建工具配置
            default_config = {
                "api_key": "",
                "secret_key": "",
                "cache_enabled": True,
                "cache_ttl": 3600,
                "request_limit": 100,
            }
            
            # 如果不存在则创建新的工具记录
            gaode_maps_tool = MCPTool(
                name="高德地图工具",
                description="提供高德地图API接口，包括地理编码、路径规划、POI搜索、天气查询等功能",
                module_path="mcp_tools.gaode-maps",
                enabled=True,
                port=5002,
                config=default_config,
                is_uvicorn=False,
                worker=2,
                auto_start=False,
                usage_examples="""#### 使用前请在高德开发者平台中注册并获取api-key（https://console.amap.com/）
#### 在你的LLM客户端中添加以下工具配置：

```json
{
  "type": "function",
  "function": {
    "name": "geocode",
    "description": "将地址转换为经纬度坐标",
    "parameters": {
      "type": "object",
      "properties": {
        "address": {
          "type": "string",
          "description": "地址字符串"
        },
        "city": {
          "type": "string",
          "description": "城市名（可选）"
        }
      },
      "required": ["address"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5002/sse"
  }
}
```

#### 亦或者可以简单一点
```json
{
  "mcpServers": {
    "gaode-maps-tool": {
      "url": "http://localhost:5002/sse"
    }
  }
}
```"""
            )
            db.add(gaode_maps_tool)
            db.commit()
            logger.info("创建高德地图工具配置")
            
            # 创建安全规则
            security_rule = SecurityRule(
                mcp_tool_id=gaode_maps_tool.id,
                name="全部放通",
                rule_type="all",
                value="0.0.0.0/0",
                enabled=True
            )
            db.add(security_rule)
            db.commit()
            logger.info("创建默认安全规则: 全部放通")
        else:
            logger.info("高德地图工具已存在，跳过创建")
            
    except Exception as e:
        logger.error(f"初始化高德地图工具数据时出错: {e}")
        db.rollback()
        raise
    
    logger.info("高德地图工具数据初始化完成")

if __name__ == "__main__":
    # 当脚本直接运行时，创建一个数据库会话并调用初始化函数
    from mcp_hub.db.base import SessionLocal
    
    db = SessionLocal()
    try:
        init(db)
    finally:
        db.close() 