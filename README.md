# MCP HUB

基于FastMCP框架的MCP（Model Context Protocol）服务集成平台，使用MySQL 8.0作为数据库。

## 项目简介

本项目使用FastMCP框架集成各种MCP服务，为大语言模型提供上下文和工具。主要特点包括：

- 基于FastMCP框架的简洁实现
- 目前所有工具仅支持SSE协议
- MySQL 8.0数据库存储MCP工具模型和用户信息
- Redis缓存优化性能（已去掉）
- 所有服务在本地实现，不是代理，不联网的功能，如数据库等完全离线

## 系统架构

MCP Hub由以下几个主要部分组成：

1. **MCP Hub核心**：负责管理各种MCP工具，提供Web界面和API接口
2. **MCP工具集**：独立的MCP服务，每个服务提供特定的功能
3. **数据库**：MySQL用于存储配置信息

## 目前支持的MCP

MySQL、SQLServer、高德地图、百度搜索、博查搜索、Markdown转图表

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

默认用户名密码：admin/admin@2025

## 可用的MCP工具

目前，MCP Hub包含以下MCP工具：

1. **MySQL查询工具**：执行MySQL数据库查询的MCP工具

要添加更多工具，请参考`mcp_tools`目录下的示例。


## 安全管理

MCP-Hub支持对每一个MCP工具做不同的安全限制，提供了灵活的安全管理机制：

- 支持IP地址限制（单IP、IP范围、子网掩码）



## 其他说明

### mcp-hub说明

服务由mcp-hub发起，通过传递启动参数给子进程启动，所以只需要管每一个mcp_tool的主函数即可，工具下每个init_db.py格式都固定，在初始化的时候，脚本会对每一个mcp_tools下的工具文件的init_db.py进行初始化，工具参数以json格式解析

### mcp_tools文件夹内的组成

每一个mcp_tools的文件夹都要有这几个部分组成：
1. __init__.py
- 功能: 模块初始化文件，定义包的基本信息
- 内容: 包含模块的文档字符串和版本号(1.0.0)
- 作用: 使目录成为Python包，提供版本信息和包描述
- 示例：
```python
"""
高德地图MCP工具包
"""

__version__ = "1.0.0" 
```
2. __main__.py
- 功能: 模块的入口点，允许直接执行包(p如 ython -m mcp_tools.gaode-maps)
- 内容: 导入server模块中的main函数并执行
- 作用: 提供命令行执行入口，简化服务启动方式
- 示例：
```python
"""
高德地图MCP工具入口模块
"""

from .server import main

if __name__ == "__main__":
    main() 
```
3. server.py
- 功能: 核心服务实现文件
- 主要组件:
  - 命令行参数解析(parse_args): 处理端口、Redis连接等参数
  - 环境变量设置(args_to_env): 将命令行参数转换为环境变量
  - 配置获取(get_config): 从Redis或环境变量获取配置
  - 安全规则处理(get_security_rules): 获取并应用IP访问控制规则
  - 请求缓存机制(cached_request): 缓存API请求结果减少重复请求
  - 安全检查装饰器(security_check): 对工具函数进行安全验证
  - 主函数(main): 创建FastMCP实例并启动服务
  - 工具API函数: 注册多个工具函数，如gaode-maps、baidu-searcher、mysql等
- 运行机制:
  - 解析命令行参数并设置环境变量
  - 创建FastMCP实例
  - 加载安全规则
  - 注册地图工具函数
  - 启动SSE服务监听指定端口
4. init_db.py
- 功能: 数据库初始化脚本
- 主要组件:
  - init函数: 注册工具到MCP Hub数据库
  - 创建工具配置: 设置默认参数如API密钥、缓存设置等
  - 创建安全规则: 设置默认IP访问控制
- 运行机制:
  - 检查工具是否已存在于数据库
  - 不存在则创建工具记录，包含名称、描述、端口等信息
  - 添加默认安全规则(通常是全部放通)
  - 提交数据库事务
  - 如有端口需要设置，就设置为业务端口，比如数据库的，就使用sqlport，防止和mcp_tool的port参数冲突