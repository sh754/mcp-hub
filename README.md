# MCP HUB

基于FastMCP框架的MCP（Model Context Protocol）服务集成平台，使用MySQL 8.0作为数据库。

## 项目简介

本项目使用FastMCP框架集成各种MCP服务，为大语言模型提供上下文和工具。主要特点包括：

- 基于FastMCP框架的简洁实现
- 目前所有工具仅支持SSE协议
- MySQL 8.0数据库存储MCP工具模型和用户信息
- Redis缓存优化性能（已去掉）

## 系统架构

MCP Hub由以下几个主要部分组成：

1. **MCP Hub核心**：负责管理各种MCP工具，提供Web界面和API接口
2. **MCP工具集**：独立的MCP服务，每个服务提供特定的功能
3. **数据库**：MySQL用于存储配置信息

## 技术栈

- **FastMCP**: MCP服务器框架
- **FastAPI**: 后端API框架（FastMCP底层使用）

## 项目结构

```
mcp-hub/
├── mcp_hub/            # 主应用代码
│   ├── api/            # API 路由和端点
│   ├── core/           # 核心配置和工具
│   ├── db/             # 数据库模型和管理
│   ├── models/         # Pydantic 模型
│   ├── services/       # 服务逻辑
│   ├── templates/      # Web 界面模板
│   ├── static/         # 静态文件（CSS、JS等）
│   └── scripts/        # 脚本工具（初始化数据库等）
├── mcp_tools/          # MCP 工具实现目录
│   ├── mysql/          # MySQL查询工具
│   └── ...             # 其他工具
├── .env                # 环境变量（不包含在版本控制中）
├── requirements.txt    # 项目依赖
└── README.md           # 项目说明文档
```

## 快速开始
```bash
git clone https://github.com/sh754/mcp-hub.git
cd mcp-hub/docker
docker-compose up -d
```

## 环境配置

1. 克隆仓库：

```bash
git clone https://github.com/sh754/mcp-hub.git
cd mcp-hub
```

2. 创建并激活虚拟环境：

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 安装依赖：

```bash
pip install -r requirements.txt
```

4. 配置环境变量：

```bash
vim .env
```

5. 初始化数据库：

```bash
python -m init_db.py
```

## 运行服务

启动MCP Hub服务：

```bash
uvicorn mcp_hub.main:app --host 0.0.0.0 --port 5000 --reload
```

访问Web界面：http://localhost:5000

## 可用的MCP工具

目前，MCP Hub包含以下MCP工具：

1. **MySQL查询工具**：执行MySQL数据库查询的MCP工具

要添加更多工具，请参考`mcp_tools`目录下的示例。


## 安全管理

MCP Hub提供了灵活的安全管理机制：

- 支持IP地址限制（单IP、IP范围、子网掩码）# mcp-hub
