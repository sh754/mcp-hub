#!/bin/bash
set -e

if [ -f "/app/.env" ]; then
  echo "加载 /app/.env 文件中的环境变量..."
  source /app/.env
else
  echo "警告: /app/.env 文件未找到，将依赖容器级别的环境变量"
fi

echo "检查必要的数据库环境变量..."
REQUIRED_VARS=("DB_HOST" "DB_PORT" "DB_USER" "DB_PASSWORD" "DB_NAME")
all_vars_set=true
for var_name in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var_name}" ]; then
    echo "错误: 环境变量 $var_name 未设置或为空！"
    all_vars_set=false
  else
    if [ "$var_name" = "DB_PASSWORD" ]; then
      echo "$var_name=****"
    else
      echo "$var_name=${!var_name}"
    fi
  fi
done

if [ "$all_vars_set" = false ]; then
  echo "请确保 /app/.env 文件存在且包含所有必要的数据库配置，或者通过Docker Compose环境变量传递。"
  exit 1
fi

# 检查DB_HOST是否为127.0.0.1
if [ "$DB_HOST" = "127.0.0.1" ]; then
  echo "错误: DB_HOST 配置为 127.0.0.1，这在Docker容器之间通常是错误的。"
  echo "应使用服务名 (例如 mcphub_sql)。请检查 /app/.env 文件。"
  exit 1
fi

echo "等待MySQL启动..."

# 首先等待30秒钟，让MySQL完全初始化
echo "先等待15秒，确保MySQL完全启动..."
sleep 15
max_tries=60
count=0

while [ $count -lt $max_tries ]; do
  echo "尝试连接 MySQL ($count/$max_tries)..."
  
  if MYSQL_PWD="$DB_PASSWORD" mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -e "SELECT 'MySQL连接测试成功'" 2>/tmp/mysql_error.log; then
    echo "MySQL连接成功 (方式1)！"
    echo "测试数据库 $DB_NAME 是否存在..."
    if MYSQL_PWD="$DB_PASSWORD" mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/tmp/mysql_error.log; then
      echo "数据库 $DB_NAME 已确认存在或已创建"
      break
    else
      echo "警告: 无法创建或访问数据库 $DB_NAME"
      cat /tmp/mysql_error.log
      exit 1
    fi
  fi
  
  cat /tmp/mysql_error.log
  echo "方式1失败，尝试方式2..."
  
  if mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 'MySQL连接测试成功'" 2>/tmp/mysql_error.log; then
    echo "MySQL连接成功 (方式2)！"
    echo "测试数据库 $DB_NAME 是否存在..."
    if mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/tmp/mysql_error.log; then
      echo "数据库 $DB_NAME 已确认存在或已创建"
      break
    else
      echo "警告: 无法创建或访问数据库 $DB_NAME"
      cat /tmp/mysql_error.log
      exit 1
    fi
  fi
  
  cat /tmp/mysql_error.log
  echo "连接失败，等待5秒后重试...尝试的连接字符串: mysql -h $DB_HOST -P $DB_PORT -u $DB_USER"
  sleep 5
  count=$((count+1))
done

if [ $count -eq $max_tries ]; then
  echo "MySQL连接超时，退出！"
  echo "请检查MySQL容器状态和网络连接"
  echo "尝试手动检查：docker exec mcphub_app mysql -h $DB_HOST -u $DB_USER -p"
  exit 1
fi

echo "MySQL连接成功，开始初始化数据库..."

echo "开始初始化数据库..."
python -m mcp_hub.scripts.init_db
echo "数据库初始化完成！"

echo "开始初始化工具数据库..."
for tool_dir in mcp_tools/*; do
  if [ -d "$tool_dir" ] && [ -f "$tool_dir/init_db.py" ]; then
    echo "初始化工具: $tool_dir"
    python "$tool_dir/init_db.py"
  fi
done
echo "工具数据库初始化完成！"

HOST=${UVICORN_HOST:-0.0.0.0}
PORT=${UVICORN_PORT:-5000}

# 启动应用，使用单worker
echo "使用单worker启动MCP Hub应用..."
exec uvicorn mcp_hub.main:app --host $HOST --port $PORT --log-level error --no-access-log