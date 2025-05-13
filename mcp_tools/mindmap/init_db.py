#!/usr/bin/env python

"""
Markdown思维导图工具数据库初始化脚本
该脚本在主数据库初始化过程中被调用，用于初始化思维导图工具所需的特定数据
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

logger = get_logger("mindmap_init_db")

def init(db: Session) -> None:
    """
    初始化思维导图工具的数据库配置
    
    Args:
        db: SQLAlchemy数据库会话
    """
    logger.info("开始初始化Markdown思维导图工具数据...")
    
    try:
        # 查找思维导图工具
        mindmap_tool = db.query(MCPTool).filter(
            MCPTool.module_path == "mcp_tools.mindmap"
        ).first()
        
        if not mindmap_tool:
            # 创建工具配置
            default_config = {
                "return_type": "html"
            }
            
            # 如果不存在则创建新的工具记录
            mindmap_tool = MCPTool(
                name="Markdown思维导图工具",
                description="提供将Markdown文本转换为思维导图的功能，基于mindmap-mcp-server库实现",
                module_path="mcp_tools.mindmap",
                enabled=True,
                port=5004,
                config=default_config,
                is_uvicorn=False,
                worker=2,
                auto_start=False,
                usage_examples="""#### 使用示例

```markdown
# 示例Markdown

## 第一章
- 要点1
- 要点2
  - 子要点1
  - 子要点2

## 第二章
- 另一个要点
- 最后一个要点
```

#### 工具调用:

```json
{
  "type": "function",
  "function": {
    "name": "markdown_to_mindmap",
    "description": "将Markdown文本转换为思维导图",
    "parameters": {
      "type": "object",
      "properties": {
        "markdown_content": {
          "type": "string",
          "description": "要转换的Markdown文本内容"
        },
        "return_type": {
          "type": "string",
          "enum": ["html", "filePath"],
          "description": "返回结果类型，html表示返回HTML内容，filePath表示返回文件路径"
        }
      },
      "required": ["markdown_content"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5004/sse"
  }
}
```

#### 简单配置:
```json
{
  "mcpServers": {
    "mindmap-tool": {
      "url": "http://localhost:5004/sse"
    }
  }
}
```

**注意:** 此服务基于mindmap-mcp-server实现，使用markmap-cli将Markdown转换为思维导图。"""
            )
            db.add(mindmap_tool)
            db.commit()
            logger.info("创建Markdown思维导图工具配置")
            
            # 创建安全规则
            security_rule = SecurityRule(
                mcp_tool_id=mindmap_tool.id,
                name="全部放通",
                rule_type="all",
                value="0.0.0.0/0",
                enabled=True
            )
            db.add(security_rule)
            db.commit()
            logger.info("创建默认安全规则: 全部放通")
        else:
            logger.info("Markdown思维导图工具已存在，跳过创建")
            
    except Exception as e:
        logger.error(f"初始化Markdown思维导图工具数据时出错: {e}")
        db.rollback()
        raise
    
    logger.info("Markdown思维导图工具数据初始化完成")

if __name__ == "__main__":
    from mcp_hub.db.base import SessionLocal
    
    db = SessionLocal()
    try:
        init(db)
    finally:
        db.close() 
