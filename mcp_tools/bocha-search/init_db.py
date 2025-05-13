"""
博查搜索MCP工具数据库初始化
将博查搜索工具注册到MCP Hub数据库中
"""

import os
import sys
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session
import logging

# 添加项目根目录到Python路径（修复导入错误）
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

try:
    # 尝试导入MCP Hub相关模块
    from mcp_hub.db.models import MCPTool, SecurityRule
    from mcp_hub.core.logging import get_logger
    logger = get_logger("bocha_search_init")
except ImportError:
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("bocha_search_init")
    logger.warning("无法导入MCP Hub核心模块，将使用本地日志配置")
    raise ImportError("无法导入MCP Hub模块。请确保PYTHONPATH包含MCP Hub路径。")

def init(db: Session) -> Optional[MCPTool]:
    """
    初始化博查搜索MCP工具
    
    Args:
        db: 数据库会话
    
    Returns:
        MCPTool: 创建的工具记录，如果已存在则返回现有记录
    """
    logger.info("初始化博查搜索MCP工具...")
    
    # 检查工具是否已存在
    existing_tool = db.query(MCPTool).filter(MCPTool.name == "博查搜索").first()
    if existing_tool:
        logger.info(f"博查搜索工具已存在，ID: {existing_tool.id}")
        return existing_tool
    
    # 创建新工具记录
    tool = MCPTool(
        name="博查搜索",
        description="提供博查搜索API的调用功能，支持搜索互联网内容",
        module_path="mcp_tools.bocha-search",
        port=5006,  # 使用端口5006
        is_uvicorn=True,  # 使用Uvicorn启动
        worker=1,  # 默认1个worker
        enabled=True,  # 默认启用
        auto_start=False,
        config={
            "api_key": os.environ.get("BOCHA_API_KEY", ""),  # 默认从环境变量获取API密钥
            "count": 10  # 默认返回10条结果
        },
        usage_examples="""#### 使用前请先获取博查搜索API密钥
#### 注册地址: https://bochaai.com/

#### 在你的LLM客户端中添加以下工具配置：

```json
{
  "type": "function",
  "function": {
    "name": "bochaSearch",
    "description": "使用博查搜索引擎查询互联网信息",
    "parameters": {
      "type": "object",
      "properties": {
        "query": {
          "type": "string",
          "description": "搜索查询关键词或短语，用于指定需要搜索的内容。支持自然语言查询。"
        },
        "freshness": {
          "type": "string",
          "description": "搜索结果的新鲜度要求，可选值：day（最近一天）、week（最近一周）、month（最近一个月）、year（最近一年）、all（所有时间），默认为all。"
        },
        "count": {
          "type": "integer",
          "description": "返回的搜索结果数量，默认为10条。"
        },
        "answer": {
          "type": "boolean",
          "description": "是否使用AI生成搜索结果摘要，默认为false。"
        },
        "stream": {
          "type": "boolean",
          "description": "是否使用流式返回结果，默认为false。"
        }
      },
      "required": ["query"]
    }
  },
  "transport": {
    "type": "sse",
    "url": "http://localhost:5006/sse"
  }
}
```

#### 亦或者可以简单一点
```json
{
  "mcpServers": {
    "bochaSearch": {
      "url": "http://localhost:5006/sse"
    }
  }
}
```

#### 工作原理：
该工具通过调用博查搜索API获取互联网搜索结果，支持通过SSE流式返回，可以获取最新的互联网信息，提高LLM回答的准确性和时效性。
"""
    )
    
    # 添加工具记录
    db.add(tool)
    db.flush()  # 刷新以获取ID
    
    # 获取工具ID
    tool_id = tool.id
    logger.info(f"已创建博查搜索工具，ID: {tool_id}")
    
    # 添加默认安全规则（允许所有IP访问）
    security_rule = SecurityRule(
        mcp_tool_id=tool_id,
        name="全部允许",
        rule_type="all",
        value="0.0.0.0/0",
        enabled=True
    )
    
    db.add(security_rule)
    logger.info("已添加默认安全规则: 允许所有IP访问")
    
    db.commit()
    logger.info("博查搜索MCP工具初始化完成")
    
    return tool

if __name__ == "__main__":
    try:
        from mcp_hub.db.base import SessionLocal
        
        db = SessionLocal()
        try:
            init(db)
        finally:
            db.close()
    except ImportError:
        logger.error("无法导入SessionLocal，请确保PYTHONPATH包含MCP Hub路径")
    except Exception as e:
        logger.error(f"初始化过程中出错: {e}")
        import traceback
        logger.error(traceback.format_exc()) 