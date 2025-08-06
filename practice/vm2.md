# VM2: 应用服务器完整配置指南

**服务器信息:**
- 主机名: devops-app
- IP地址: 192.168.1.11
- 配置: 2核CPU, 4GB内存, 40GB硬盘
- 角色: Node.js应用服务器 + 生产环境部署

## 第一步：系统初始化

### 1.1 安装Ubuntu系统
```bash
# 下载Ubuntu 22.04 LTS ISO
# https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso

# 安装选项：
# - 用户名: ubuntu
# - 密码: ubuntu123
# - 勾选 "Install OpenSSH server"
```

### 1.2 配置静态IP
```bash
# 编辑网络配置文件
sudo nano /etc/netplan/00-installer-config.yaml
```

**网络配置内容:**
```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.1.11/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

```bash
# 应用网络配置
sudo netplan apply

# 验证IP配置
ip addr show eth0

# 重启系统
sudo reboot
```

### 1.3 系统基础配置
```bash
# 更新系统软件包
sudo apt update && sudo apt upgrade -y

# 安装基础工具
sudo apt install -y curl wget git vim htop tree unzip net-tools build-essential

# 设置主机名
sudo hostnamectl set-hostname devops-app

# 配置hosts文件
sudo nano /etc/hosts
```

**添加hosts条目:**
```bash
127.0.0.1       localhost
192.168.1.10    devops-cicd
192.168.1.11    devops-app
192.168.1.12    devops-monitor

# 保存退出 (Ctrl+X, Y, Enter)
```

```bash
# 验证主机名设置
hostname
hostnamectl status

# 测试网络连通性
ping -c 4 devops-cicd
ping -c 4 devops-monitor
ping -c 4 8.8.8.8
```

## 第二步：安装Docker

### 2.1 卸载旧版本Docker
```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```

### 2.2 安装Docker依赖
```bash
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
```

### 2.3 添加Docker官方仓库
```bash
# 创建密钥目录
sudo mkdir -p /etc/apt/keyrings

# 下载并添加Docker的官方GPG密钥
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 设置Docker仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

### 2.4 安装Docker Engine
```bash
# 更新包索引
sudo apt-get update

# 安装Docker CE
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker

# 验证Docker安装
sudo docker version

# 添加当前用户到docker组
sudo usermod -aG docker ubuntu

# 注销并重新登录以生效
exit
# 重新SSH登录
ssh ubuntu@192.168.1.11
```

### 2.5 验证Docker安装
```bash
# 测试Docker（无需sudo）
docker version
docker info

# 运行hello-world测试
docker run hello-world
```

## 第三步：安装Node.js和NPM

### 3.1 安装Node.js 18.x
```bash
# 添加Node.js官方仓库
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

# 安装Node.js
sudo apt-get install -y nodejs

# 验证安装
node --version
npm --version

# 查看安装路径
which node
which npm
```

### 3.2 配置npm全局模块
```bash
# 创建全局模块目录（避免权限问题）
mkdir ~/.npm-global

# 配置npm使用新的目录路径
npm config set prefix '~/.npm-global'

# 将新路径添加到环境变量
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc

# 重新加载bashrc
source ~/.bashrc

# 验证配置
npm config get prefix
```

### 3.3 安装PM2进程管理器
```bash
# 安装PM2（全局）
npm install -g pm2

# 验证PM2安装
pm2 --version

# 配置PM2开机自启动
pm2 startup
# 按照输出的命令执行（通常是sudo命令）

# 保存当前PM2配置
pm2 save
```

## 第四步：安装和配置Nginx

### 4.1 安装Nginx
```bash
# 安装Nginx
sudo apt install -y nginx

# 启动Nginx服务
sudo systemctl start nginx
sudo systemctl enable nginx

# 检查Nginx状态
sudo systemctl status nginx

# 测试Nginx安装
curl http://localhost
```

### 4.2 创建应用目录结构
```bash
# 创建应用根目录
sudo mkdir -p /var/www/html

# 设置目录权限
sudo chown -R ubuntu:ubuntu /var/www/html

# 创建应用子目录
mkdir -p /var/www/html/demo-app
mkdir -p /var/www/html/logs
mkdir -p /var/www/html/static

# 验证目录结构
tree /var/www/html/
```

### 4.3 配置Nginx反向代理
```bash
# 备份默认配置
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup

# 创建新的Nginx配置
sudo nano /etc/nginx/sites-available/default
```

**Nginx配置内容（完全替换）:**
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name devops-app 192.168.1.11;
    
    # 日志配置
    access_log /var/log/nginx/app_access.log;
    error_log /var/log/nginx/app_error.log;
    
    # 主应用代理到Node.js
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # 静态文件服务
    location /static {
        alias /var/www/html/static;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
    
    # 健康检查端点
    location /nginx-health {
        return 200 "nginx OK\n";
        add_header Content-Type text/plain;
    }
    
    # 限制访问敏感文件
    location ~ /\. {
        deny all;
    }
    
    location ~ \.log$ {
        deny all;
    }
}
```

### 4.4 应用Nginx配置
```bash
# 测试Nginx配置语法
sudo nginx -t

# 如果测试通过，重启Nginx
sudo systemctl restart nginx

# 检查Nginx状态
sudo systemctl status nginx

# 查看Nginx进程
ps aux | grep nginx
```

## 第五步：创建示例Node.js应用

### 5.1 创建应用基础文件
```bash
# 进入应用目录
cd /var/www/html/demo-app

# 创建package.json
cat > package.json << 'EOF'
{
  "name": "devops-demo-app",
  "version": "1.0.0",
  "description": "DevOps Demo Application with Monitoring",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js",
    "test": "jest",
    "lint": "eslint ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "morgan": "^1.10.0",
    "prom-client": "^14.2.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.2",
    "eslint": "^8.45.0"
  },
  "keywords": ["devops", "nodejs", "demo"],
  "author": "DevOps Team",
  "license": "MIT"
}
EOF
```

### 5.2 创建主应用文件
```bash
# 创建应用主文件
cat > app.js << 'EOF'
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const promClient = require('prom-client');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
const port = process.env.PORT || 3000;

// Prometheus监控指标
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5]
});

const httpRequestCount = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

// 中间件
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static('public'));

// 监控中间件
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestDuration
      .labels(req.method, route, res.statusCode)
      .observe(duration);
    
    httpRequestCount
      .labels(req.method, route, res.statusCode)
      .inc();
  });
  
  next();
});

// 路由定义
app.get('/', (req, res) => {
  const uptime = process.uptime();
  const loadavg = os.loadavg();
  
  res.json({
    message: 'DevOps Demo Application',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    uptime: `${Math.floor(uptime / 60)}m ${Math.floor(uptime % 60)}s`,
    loadavg: loadavg,
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health', (req, res) => {
  const healthcheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    services: {
      database: 'connected',
      cache: 'connected',
      external_api: 'connected'
    }
  };
  
  res.json(healthcheck);
});

app.get('/metrics', (req, res) => {
  res.set('Content-Type', promClient.register.contentType);
  res.end(promClient.register.metrics());
});

app.get('/info', (req, res) => {
  res.json({
    app: 'devops-demo-app',
    version: '1.0.0',
    node_version: process.version,
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    memory: Math.round(os.totalmem() / 1024 / 1024) + ' MB',
    hostname: os.hostname(),
    pid: process.pid
  });
});

// API路由
app.get('/api/users', (req, res) => {
  const users = [
    { id: 1, name: 'Admin', role: 'admin' },
    { id: 2, name: 'Developer', role: 'developer' },
    { id: 3, name: 'User', role: 'user' }
  ];
  res.json(users);
});

app.post('/api/deploy', (req, res) => {
  const deployment = {
    id: Date.now(),
    status: 'success',
    timestamp: new Date().toISOString(),
    version: req.body.version || '1.0.0',
    environment: req.body.environment || 'production'
  };
  res.json(deployment);
});

// 错误处理
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    timestamp: new Date().toISOString()
  });
});

app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    timestamp: new Date().toISOString()
  });
});

// 启动服务器
app.listen(port, () => {
  console.log(`Demo app listening on port ${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
  console.log(`Metrics: http://localhost:${port}/metrics`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// 优雅关闭
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});
EOF
```

### 5.3 创建测试文件
```bash
# 创建简单测试文件
cat > test.js << 'EOF'
const request = require('supertest');
const app = require('./app');

describe('App endpoints', () => {
  test('GET /', async () => {
    const response = await request(app).get('/');
    expect(response.statusCode).toBe(200);
    expect(response.body.message).toBe('DevOps Demo Application');
  });

  test('GET /health', async () => {
    const response = await request(app).get('/health');
    expect(response.statusCode).toBe(200);
    expect(response.body.status).toBe('healthy');
  });
});
EOF
```

### 5.4 创建PM2配置文件
```bash
# 创建PM2配置文件
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'demo-app',
    script: 'app.js',
    instances: 1,
    exec_mode: 'cluster',
    watch: false,
    max_memory_restart: '100M',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    env_development: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    log_file: '/var/www/html/logs/app.log',
    out_file: '/var/www/html/logs/app-out.log',
    error_file: '/var/www/html/logs/app-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
EOF
```

### 5.5 安装应用依赖
```bash
# 安装依赖包
npm install

# 验证安装
ls node_modules/

# 检查package-lock.json
ls -la package-lock.json
```

## 第六步：安装Node Exporter

### 6.1 下载和安装Node Exporter
```bash
# 切换到临时目录
cd /tmp

# 下载Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz

# 解压文件
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz

# 移动可执行文件到系统路径
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

# 验证安装
/usr/local/bin/node_exporter --version

# 清理临时文件
rm -rf /tmp/node_exporter*
```

### 6.2 创建Node Exporter用户和服务
```bash
# 创建系统用户
sudo useradd --no-create-home --shell /bin/false node_exporter

# 设置可执行文件权限
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter

# 创建systemd服务文件
sudo nano /etc/systemd/system/node_exporter.service
```

**Node Exporter服务配置:**
```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
    --collector.systemd \
    --collector.processes \
    --collector.diskstats.ignored-devices="^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### 6.3 启动Node Exporter
```bash
# 重新加载systemd
sudo systemctl daemon-reload

# 启动Node Exporter
sudo systemctl start node_exporter
sudo systemctl enable node_exporter

# 检查服务状态
sudo systemctl status node_exporter

# 测试Node Exporter指标
curl http://localhost:9100/metrics | head -20

# 检查特定指标
curl http://localhost:9100/metrics | grep "node_load"
```

## 第七步：启动和配置应用服务

### 7.1 测试应用运行
```bash
# 进入应用目录
cd /var/www/html/demo-app

# 测试应用启动
node app.js &
APP_PID=$!

# 测试应用接口
sleep 5
curl http://localhost:3000
curl http://localhost:3000/health
curl http://localhost:3000/metrics

# 停止测试进程
kill $APP_PID
```

### 7.2 使用PM2管理应用
```bash
# 使用PM2启动应用
pm2 start ecosystem.config.js

# 查看应用状态
pm2 status
pm2 info demo-app

# 查看应用日志
pm2 logs demo-app --lines 20

# 保存PM2配置
pm2 save

# 测试应用重启
pm2 restart demo-app
pm2 status
```

### 7.3 验证应用和Nginx集成
```bash
# 测试Nginx代理
curl http://localhost
curl http://localhost/health
curl http://localhost/info

# 测试外部访问（从其他机器）
# curl http://192.168.1.11
# curl http://192.168.1.11/health

# 查看Nginx访问日志
sudo tail -f /var/log/nginx/access.log

# 查看Nginx错误日志
sudo tail -f /var/log/nginx/error.log
```

## 第八步：配置防火墙

### 8.1 配置UFW防火墙
```bash
# 启用UFW
sudo ufw --force enable

# 允许SSH访问
sudo ufw allow 22/tcp

# 允许HTTP访问
sudo ufw allow 80/tcp

# 允许应用直接访问（用于测试）
sudo ufw allow 3000/tcp

# 允许Node Exporter
sudo ufw allow 9100/tcp

# 查看防火墙状态
sudo ufw status numbered

# 查看详细状态
sudo ufw status verbose
```

### 8.2 测试防火墙配置
```bash
# 测试端口访问
sudo netstat -tlnp | grep -E ':(80|3000|9100)'

# 从外部测试访问
ping -c 4 192.168.1.11
```

## 第九步：配置SSH访问

### 9.1 配置SSH服务
```bash
# 检查SSH服务状态
sudo systemctl status ssh

# 查看SSH配置
sudo nano /etc/ssh/sshd_config

# 确保以下配置项正确：
# Port 22
# PermitRootLogin no
# PasswordAuthentication yes
# PubkeyAuthentication yes
```

### 9.2 准备接收SSH密钥
```bash
# 创建.ssh目录（如果不存在）
mkdir -p ~/.ssh

# 设置正确的权限
chmod 700 ~/.ssh

# 创建authorized_keys文件
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 查看当前SSH配置
ls -la ~/.ssh/
```

## 第十步：性能优化配置

### 10.1 配置系统参数
```bash
# 创建系统优化配置
sudo nano /etc/sysctl.d/99-devops-app.conf
```

**系统参数配置:**
```bash
# 网络优化
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# 文件描述符限制
fs.file-max = 65536

# 进程限制
kernel.pid_max = 65536
```

```bash
# 应用系统参数
sudo sysctl -p /etc/sysctl.d/99-devops-app.conf

# 验证参数设置
sysctl net.core.rmem_max
sysctl fs.file-max
```

### 10.2 配置用户限制
```bash
# 编辑limits配置
sudo nano /etc/security/limits.conf

# 添加以下内容到文件末尾
echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf
echo '* soft nproc 4096' | sudo tee -a /etc/security/limits.conf
echo '* hard nproc 4096' | sudo tee -a /etc/security/limits.conf

# 重新登录后生效
```

### 10.3 配置日志轮转
```bash
# 创建应用日志轮转配置
sudo nano /etc/logrotate.d/demo-app
```

**日志轮转配置:**
```bash
/var/www/html/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        pm2 reload demo-app
    endscript
}
```

```bash
# 测试日志轮转配置
sudo logrotate -d /etc/logrotate.d/demo-app
```

## 第十一步：监控和健康检查

### 11.1 创建健康检查脚本
```bash
# 创建监控脚本目录
sudo mkdir -p /opt/monitoring

# 创建应用健康检查脚本
sudo nano /opt/monitoring/app_health_check.sh
```

**健康检查脚本:**
```bash
#!/bin/bash

LOG_FILE="/var/log/app_health.log"
APP_URL="http://localhost:3000/health"
NODE_EXPORTER_URL="http://localhost:9100/metrics"

echo "=== App Health Check $(date) ===" >> $LOG_FILE

# 检查应用健康状态
if curl -s $APP_URL | grep -q "healthy"; then
    echo "✓ Application: Healthy" >> $LOG_FILE
else
    echo "✗ Application: Unhealthy" >> $LOG_FILE
fi

# 检查Node Exporter
if curl -s $NODE_EXPORTER_URL > /dev/null; then
    echo "✓ Node Exporter: Running" >> $LOG_FILE
else
    echo "✗ Node Exporter: Not running" >> $LOG_FILE
fi

# 检查PM2进程
if pm2 list | grep -q "demo-app.*online"; then
    echo "✓ PM2 Process: Running" >> $LOG_FILE
else
    echo "✗ PM2 Process: Not running" >> $LOG_FILE
fi

# 检查Nginx状态
if systemctl is-active --quiet nginx; then
    echo "✓ Nginx: Running" >> $LOG_FILE
else
    echo "✗ Nginx: Not running" >> $LOG_FILE
fi

# 检查磁盘使用率
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -lt 80 ]; then
    echo "✓ Disk Usage: ${DISK_USAGE}%" >> $LOG_FILE
else
    echo "⚠ Disk Usage: ${DISK_USAGE}% (High)" >> $LOG_FILE
fi

# 检查内存使用率
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3/$2*100}')
if [ $MEMORY_USAGE -lt 80 ]; then
    echo "✓ Memory Usage: ${MEMORY_USAGE}%" >> $LOG_FILE
else
    echo "⚠ Memory Usage: ${MEMORY_USAGE}% (High)" >> $LOG_FILE
fi

echo "" >> $LOG_FILE
```

```bash
# 设置脚本权限
sudo chmod +x /opt/monitoring/app_health_check.sh

# 运行健康检查
sudo /opt/monitoring/app_health_check.sh

# 查看健康检查结果
sudo cat /var/log/app_health.log
```

### 11.2 设置定时健康检查
```bash
# 添加到crontab
crontab -e

# 添加以下行（每5分钟检查一次）
*/5 * * * * /opt/monitoring/app_health_check.sh

# 验证crontab设置
crontab -l
```

## 第十二步：备份和恢复配置

### 12.1 创建备份脚本
```bash
# 创建备份目录
sudo mkdir -p /opt/backups

# 创建备份脚本
sudo nano /opt/backups/backup_app.sh
```

**备份脚本:**
```bash
#!/bin/bash

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
APP_DIR="/var/www/html/demo-app"

echo "Starting backup at $(date)"

# 创建今日备份目录
mkdir -p $BACKUP_DIR/$DATE

# 备份应用代码
tar -czf $BACKUP_DIR/$DATE/app_code.tar.gz -C /var/www/html demo-app

# 备份配置文件
cp /etc/nginx/sites-available/default $BACKUP_DIR/$DATE/nginx_config
cp /etc/systemd/system/node_exporter.service $BACKUP_DIR/$DATE/
cp /etc/netplan/00-installer-config.yaml $BACKUP_DIR/$DATE/

# 备份PM2配置
pm2 save --force
cp ~/.pm2/dump.pm2 $BACKUP_DIR/$DATE/

# 备份应用日志
cp -r /var/www/html/logs $BACKUP_DIR/$DATE/

# 删除7天前的备份
find $BACKUP_DIR -type d -name "*_*" -mtime +7 -exec rm -rf {} +

echo "Backup completed at $(date)"
echo "Backup saved to: $BACKUP_DIR/$DATE"
```

```bash
# 设置脚本权限
sudo chmod +x /opt/backups/backup_app.sh

# 运行备份测试
sudo /opt/backups/backup_app.sh

# 验证备份
ls -la /opt/backups/
```

### 12.2 创建系统信息脚本
```bash
# 创建系统信息脚本
sudo nano /opt/monitoring/system_info.sh
```

**系统信息脚本:**
```bash
#!/bin/bash

echo "=== DevOps Application Server System Info ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"
echo ""

echo "=== Service Status ==="
services=("nginx" "node_exporter" "ssh")

for service in "${services[@]}"; do
    echo -n "$service: "
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
    else
        echo "✗ Stopped"
    fi
done

echo ""
echo "=== PM2 Status ==="
pm2 status

echo ""
echo "=== Port Status ==="
netstat -tlnp | grep -E ':(80|3000|9100)' | awk '{print $4, $7}'

echo ""
echo "=== Disk Usage ==="
df -h

echo ""
echo "=== Memory Usage ==="
free -h

echo ""
echo "=== CPU Load ==="
cat /proc/loadavg

echo ""
echo "=== Top Processes ==="
ps aux --sort=-%cpu | head -10
```

```bash
# 设置脚本权限
sudo chmod +x /opt/monitoring/system_info.sh

# 运行系统信息脚本
sudo /opt/monitoring/system_info.sh
```

## 完成验证清单

**系统基础验证:**
- [ ] 网络配置正确，可以ping通其他VM
- [ ] SSH服务正常运行
- [ ] 防火墙规则配置正确
- [ ] 主机名和hosts配置正确

**Docker和Node.js验证:**
- [ ] Docker服务正常，可以运行容器
- [ ] Node.js和npm正常安装和工作
- [ ] PM2进程管理器正常工作

**应用验证:**
- [ ] 示例应用成功启动并运行
- [ ] Nginx反向代理正常工作
- [ ] 应用接口可以正常访问
- [ ] PM2可以管理应用进程

**监控验证:**
- [ ] Node Exporter正常运行并暴露指标
- [ ] 应用Prometheus指标正常暴露
- [ ] 健康检查脚本正常工作

**连通性验证:**
- [ ] 可以访问 http://192.168.1.11 (主应用)
- [ ] 可以访问 http://192.168.1.11/health (健康检查)
- [ ] 可以访问 http://192.168.1.11:9100/metrics (Node Exporter)
- [ ] SSH密钥准备就绪，等待CI/CD服务器连接

**运维功能验证:**
- [ ] 日志轮转配置正确
- [ ] 备份脚本可以正常执行
- [ ] 系统监控脚本工作正常
- [ ] 定时任务配置正确

## 故障排除指南

### 应用启动问题
```bash
# 检查Node.js版本
node --version
npm --version

# 检查应用日志
pm2 logs demo-app
cat /var/www/html/logs/app-error.log

# 检查端口占用
sudo netstat -tlnp | grep :3000

# 手动测试应用
cd /var/www/html/demo-app
node app.js
```

### Nginx问题
```bash
# 检查配置语法
sudo nginx -t

# 查看错误日志
sudo tail -f /var/log/nginx/error.log

# 重启Nginx
sudo systemctl restart nginx

# 检查Nginx进程
ps aux | grep nginx
```

### PM2问题
```bash
# PM2状态检查
pm2 status
pm2 info demo-app

# 重启PM2管理的进程
pm2 restart demo-app

# PM2日志
pm2 logs demo-app --lines 50

# 重置PM2
pm2 kill
pm2 start ecosystem.config.js
```

### 网络连接问题
```bash
# 检查端口监听
sudo netstat -tlnp

# 检查防火墙状态
sudo ufw status

# 测试网络连通性
ping 192.168.1.10
ping 192.168.1.12
```

VM2 应用服务器配置完成！