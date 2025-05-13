#!/usr/bin/env python

"""
MySQL工具数据库初始化脚本
该脚本在主数据库初始化过程中被调用，用于初始化MySQL工具所需的特定数据
"""
import sys
import os
from pathlib import Path
import json
from typing import Dict, Any

project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

from sqlalchemy.orm import Session
from mcp_hub.core.logging import get_logger
from mcp_hub.db.models import MCPTool, SecurityRule

logger = get_logger("mysql_init_db")

def init(db: Session) -> None:
    """
    初始化MySQL工具的数据库配置
    
    Args:
        db: SQLAlchemy数据库会话
    """
    logger.info("开始初始化MySQL工具数据...")
    
    try:
        mysql_tool = db.query(MCPTool).filter(
            MCPTool.module_path == "mcp_tools.mysql"
        ).first()
        
        if not mysql_tool:
            default_config = {
                "host": "",
                "database": "",
                "username": "",
                "password": "",
                "sqlport": 3306,
                "charset": "utf8mb4",
                "cache_enabled": True,
                "cache_ttl": 300,
                "connect_timeout": 10,
                "read_timeout": 30,
                "only_select": True
            }
            
            mysql_tool = MCPTool(
                name="MySQL工具",
                description="提供与MySQL数据库交互的能力，包括执行SQL查询、获取数据库元数据等功能,only_select: true时是只读模式，false是增删改查都可以",
                module_path="mcp_tools.mysql",
                enabled=True,
                port=5001,
                config=default_config,
                is_uvicorn=True,
                worker=2,
                auto_start=False,
                usage_examples="""#### 使用示例

```sql
-- 执行查询示例
SELECT * FROM customers WHERE country = 'USA' LIMIT 10;

-- 插入数据示例
INSERT INTO products (name, price, category_id) 
VALUES ('新产品', 19.99, 1);

-- 更新数据示例
UPDATE products SET price = 29.99 WHERE id = 1;

-- 删除数据示例
DELETE FROM order_items WHERE order_id = 1001;
```

#### 工具调用:

```json
{
  "type": "function",
  "function": {
    "name": "execute_sql",
    "description": "执行SQL查询语句",
    "parameters": {
      "type": "object",
      "properties": {
        "sql": {
          "type": "string",
          "description": "SQL查询语句"
        },
        "params": {
          "type": "array",
          "description": "查询参数，用于替换SQL中的占位符"
        },
        "database": {
          "type": "string",
          "description": "要连接的数据库名称，如果不提供则使用默认数据库"
        },
        "fetch_all": {
          "type": "boolean",
          "description": "是否获取所有结果，对于SELECT查询为true，对于INSERT/UPDATE/DELETE为false"
        }
      },
      "required": ["sql"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5001/sse"
  }
}
```

#### 查看数据库信息:

```json
{
  "type": "function",
  "function": {
    "name": "list_databases",
    "description": "列出所有数据库",
    "parameters": {
      "type": "object",
      "properties": {}
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5001/sse"
  }
}
```

```json
{
  "type": "function",
  "function": {
    "name": "list_tables",
    "description": "列出指定数据库中的所有表",
    "parameters": {
      "type": "object",
      "properties": {
        "database": {
          "type": "string",
          "description": "数据库名称"
        }
      },
      "required": ["database"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5001/sse"
  }
}
```

```json
{
  "type": "function",
  "function": {
    "name": "describe_table",
    "description": "描述表结构",
    "parameters": {
      "type": "object",
      "properties": {
        "database": {
          "type": "string",
          "description": "数据库名称"
        },
        "table": {
          "type": "string",
          "description": "表名"
        }
      },
      "required": ["database", "table"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5001/sse"
  }
}
```

```json
{
  "type": "function",
  "function": {
    "name": "run_procedure",
    "description": "执行存储过程",
    "parameters": {
      "type": "object",
      "properties": {
        "procedure": {
          "type": "string",
          "description": "存储过程名称"
        },
        "params": {
          "type": "array",
          "description": "存储过程参数"
        },
        "database": {
          "type": "string",
          "description": "数据库名称"
        }
      },
      "required": ["procedure"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5001/sse"
  }
}
```

#### 简单配置:
```json
{
  "mcpServers": {
    "mysql-tool": {
      "url": "http://localhost:5001/sse"
    }
  }
}
```

**注意:** 如需开启只读模式(只允许查询)，可以将工具配置中的only_select设置为true，或在启动时添加--only-select 1参数。"""
            )
            db.add(mysql_tool)
            db.commit()
            logger.info("创建MySQL工具配置")
            
            # 创建安全规则
            security_rule = SecurityRule(
                mcp_tool_id=mysql_tool.id,
                name="全部放通",
                rule_type="all",
                value="0.0.0.0/0",
                enabled=True
            )
            db.add(security_rule)
            db.commit()
            logger.info("创建默认安全规则: 全部放通")
        else:
            logger.info("MySQL工具已存在，跳过创建")
            
    except Exception as e:
        logger.error(f"初始化MySQL工具数据时出错: {e}")
        db.rollback()
        raise
    
    logger.info("MySQL工具数据初始化完成")

if __name__ == "__main__":
    from mcp_hub.db.base import SessionLocal
    
    db = SessionLocal()
    try:
        init(db)
    finally:
        db.close() 