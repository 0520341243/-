# deploy.sh - 部署脚本
#!/bin/bash

echo "开始部署钉钉提醒系统..."

# 检查Docker是否安装
if ! command -v docker &> /dev/null; then
    echo "请先安装Docker"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "请先安装Docker Compose"
    exit 1
fi

# 创建必要目录
mkdir -p uploads logs ssl static

# 生成SSL证书（自签名，生产环境请使用真实证书）
if [ ! -f ssl/cert.pem ]; then
    echo "生成SSL证书..."
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
        -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"
fi

# 设置权限
chmod 600 ssl/key.pem
chmod 644 ssl/cert.pem

# 创建环境变量文件
if [ ! -f .env ]; then
    echo "创建环境变量文件..."
    cp .env.example .env
    echo "请编辑.env文件并填入实际配置值"
fi

# 构建并启动服务
echo "构建Docker镜像..."
docker-compose build

echo "启动服务..."
docker-compose up -d

# 等待服务启动
echo "等待服务启动..."
sleep 10

# 检查服务状态
echo "检查服务状态..."
docker-compose ps

# 显示访问信息
echo ""
echo "部署完成！"
echo "HTTP访问地址: http://localhost"
echo "HTTPS访问地址: https://localhost"
echo "API接口地址: https://localhost/api"
echo ""
echo "默认管理员账号:"
echo "用户名: guanliyuan"
echo "密码: admin"
echo ""
echo "查看日志: docker-compose logs -f app"
echo "停止服务: docker-compose down"
