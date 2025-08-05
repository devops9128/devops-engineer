# 初级DevOps工程师完整学习指南

> 基于20年DevOps实战经验整理的系统性学习路径

## 📚 目录

- [学习路径概览](#学习路径概览)
- [阶段一：基础环境搭建](#阶段一基础环境搭建)
- [阶段二：工具基础掌握](#阶段二工具基础掌握)
- [阶段三：实践应用部署](#阶段三实践应用部署)
- [阶段四：部署运维自动化](#阶段四部署运维自动化)
- [阶段五：高级运维监控](#阶段五高级运维监控)
- [学习时间规划](#学习时间规划)
- [实践项目建议](#实践项目建议)

---

## 学习路径概览

### 优先级分级说明

| 优先级 | 阶段 | 内容 | 重要性 | 预估时间 |
|--------|------|------|--------|----------|
| **P1** | 基础环境 | 系统安装配置 | ⭐⭐⭐⭐⭐ | 1-2周 |
| **P2** | 工具基础 | 核心工具掌握 | ⭐⭐⭐⭐⭐ | 2-3周 |
| **P3** | 实践应用 | 应用部署验证 | ⭐⭐⭐⭐ | 2-3周 |
| **P4** | 部署运维 | 自动化流程 | ⭐⭐⭐⭐ | 3-4周 |
| **P5** | 高级运维 | 监控告警 | ⭐⭐⭐ | 2-3周 |

### 核心技能树

```
DevOps工程师
├── 基础技能
│   ├── Linux系统管理
│   ├── 网络配置
│   └── Shell脚本
├── 容器化技术
│   ├── Docker
│   ├── Kubernetes
│   └── Helm
├── CI/CD流程
│   ├── Jenkins
│   ├── GitLab CI
│   └── GitHub Actions
├── 监控运维
│   ├── Prometheus
│   ├── Grafana
│   └── ELK Stack
└── 自动化脚本
    ├── Bash
    ├── Python
    └── Ansible
```

---

## 阶段一：基础环境搭建

> **目标**: 搭建稳定的学习和实践环境
> **时间**: 1-2周
> **优先级**: P1 ⭐⭐⭐⭐⭐

### 1.1 推荐学习环境

#### 🖥️ 硬件配置要求

**最低配置:**
- CPU: 4核心
- 内存: 8GB RAM
- 存储: 100GB SSD
- 网络: 稳定互联网连接

**推荐配置:**
- CPU: 8核心
- 内存: 16GB+ RAM
- 存储: 250GB+ SSD
- 网络: 千兆网络

#### 🏗️ 虚拟化平台选择

**方案一: 本地虚拟机 (推荐初学者)**
```bash
# 虚拟化软件选择
VMware Workstation Pro    # 功能最全，性能最佳
VirtualBox (免费)         # 开源免费，功能够用
Hyper-V (Windows)         # Windows内置，集成度高
```

**方案二: 云平台 (推荐进阶学习)**
```bash
# 云服务商推荐
AWS Free Tier            # 12个月免费额度
Google Cloud Platform    # $300免费试用
Azure Student           # 学生免费账号
腾讯云/阿里云             # 国内访问速度快
```

#### 🏛️ 架构设计

**基础练习架构 (3节点):**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Master节点  │    │ Worker节点  │    │ Monitor节点 │
│ 192.168.1.10│    │ 192.168.1.11│    │ 192.168.1.12│
│             │    │             │    │             │
│ • K8s Master│    │ • K8s Worker│    │ • Prometheus│
│ • Jenkins   │    │ • Docker    │    │ • Grafana   │
│ • Git       │    │ • Apps      │    │ • ELK Stack │
└─────────────┘    └─────────────┘    └─────────────┘
```

### 1.2 操作系统安装流程

#### 📥 系统选择与下载

**推荐系统: Ubuntu Server 22.04 LTS**

```bash
# 下载链接
https://ubuntu.com/download/server

# 验证ISO文件
sha256sum ubuntu-22.04.3-live-server-amd64.iso
```

#### 🛠️ 详细安装步骤

**Step 1: 创建虚拟机**
```bash
# VMware配置
名称: devops-master
内存: 4GB (推荐8GB)
硬盘: 50GB (动态分配)
网络: 桥接模式
```

**Step 2: 启动安装程序**
```bash
1. 选择语言: English
2. 选择键盘布局: English (US)
3. 网络配置: 配置静态IP
   - IP: 192.168.1.10/24
   - Gateway: 192.168.1.1
   - DNS: 8.8.8.8, 1.1.1.1
```

**Step 3: 磁盘分区**
```bash
# 推荐分区方案
/         30GB  (根分区)
/var      15GB  (日志和数据)
/home     3GB   (用户目录)
swap      2GB   (交换分区)
```

**Step 4: 用户配置**
```bash
用户名: devops
密码: 设置强密码
服务: ✓ Install OpenSSH server
```

**Step 5: 软件包选择**
```bash
选择: Ubuntu Server (minimal)
# 基础安装，后续手动安装需要的软件
```

### 1.3 系统初始化配置

#### 🔐 基础安全配置

**更新系统:**
```bash
sudo apt update && sudo apt upgrade -y
```

**配置防火墙:**
```bash
# 启用UFW防火墙
sudo ufw enable

# 开放必要端口
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp  # Jenkins
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus

# 查看防火墙状态
sudo ufw status
```

**SSH安全配置:**
```bash
# 编辑SSH配置
sudo vim /etc/ssh/sshd_config

# 修改以下配置
PermitRootLogin no
PasswordAuthentication no  # 使用密钥认证
Port 22
MaxAuthTries 3

# 重启SSH服务
sudo systemctl restart ssh
```

**创建SSH密钥对:**
```bash
# 生成密钥对
ssh-keygen -t rsa -b 4096 -C "devops@company.com"

# 复制公钥到服务器
ssh-copy-id devops@192.168.1.10
```

#### 👤 用户权限配置

```bash
# 将用户加入sudo组
sudo usermod -aG sudo devops

# 配置sudo免密码
echo "devops ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/devops

# 创建工作目录
mkdir -p ~/devops-workspace/{projects,scripts,configs}
```

#### 🌐 网络和主机名配置

```bash
# 设置主机名
sudo hostnamectl set-hostname devops-master

# 配置hosts文件
sudo tee -a /etc/hosts << EOF
192.168.1.10 devops-master
192.168.1.11 devops-worker
192.168.1.12 devops-monitor
EOF

# 设置时区
sudo timedatectl set-timezone Asia/Shanghai

# 验证网络配置
ip addr show
ping -c 3 google.com
```

#### ✅ 阶段一检查清单

- [ ] 虚拟机创建完成
- [ ] Ubuntu Server 22.04 LTS安装成功
- [ ] 网络配置正确，能访问互联网
- [ ] SSH服务正常，密钥认证生效
- [ ] 防火墙配置完成
- [ ] 用户权限配置正确
- [ ] 主机名和hosts文件配置完成

---

## 阶段二：工具基础掌握

> **目标**: 安装和配置核心DevOps工具
> **时间**: 2-3周
> **优先级**: P2 ⭐⭐⭐⭐⭐

### 2.1 必要应用安装

#### 🐳 Docker容器平台

**安装Docker:**
```bash
# 卸载旧版本
sudo apt remove docker docker-engine docker.io containerd runc

# 更新包索引
sudo apt update

# 安装依赖
sudo apt install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  lsb-release

# 添加Docker官方GPG密钥
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 添加Docker仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker

# 将用户加入docker组
sudo usermod -aG docker $USER

# 重新登录使组权限生效
newgrp docker
```

**安装Docker Compose:**
```bash
# 下载Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# 添加执行权限
sudo chmod +x /usr/local/bin/docker-compose

# 验证安装
docker --version
docker-compose --version
```

#### ⚓ Kubernetes容器编排

**安装K3s (轻量级Kubernetes):**
```bash
# 安装K3s Master节点
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644

# 配置kubectl
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config

# 验证安装
kubectl get nodes
kubectl get pods --all-namespaces
```

**安装kubectl:**
```bash
# 下载kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# 安装kubectl
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# 验证安装
kubectl version --client
```

**安装Helm:**
```bash
# 下载Helm安装脚本
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# 验证安装
helm version
```

#### 🔧 版本控制和CI/CD工具

**安装Git:**
```bash
# 安装Git
sudo apt install -y git

# 配置Git用户信息
git config --global user.name "DevOps Engineer"
git config --global user.email "devops@company.com"
git config --global init.defaultBranch main

# 配置Git别名
git config --global alias.st status
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
```

**安装Jenkins:**
```bash
# 添加Jenkins仓库密钥
wget -q -O - https://pkg.jenkins.io/debian-stable/jenkins.io.key | sudo apt-key add -

# 添加Jenkins仓库
sudo sh -c 'echo deb https://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'

# 安装Java (Jenkins依赖)
sudo apt update
sudo apt install -y openjdk-11-jdk

# 安装Jenkins
sudo apt install -y jenkins

# 启动Jenkins服务
sudo systemctl start jenkins
sudo systemctl enable jenkins

# 获取初始管理员密码
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

#### 📊 监控和日志工具

**安装基础工具:**
```bash
# 安装系统工具
sudo apt install -y \
  curl wget vim htop tree jq unzip zip \
  net-tools nmap telnet tcpdump \
  python3-pip nodejs npm \
  software-properties-common

# 安装Node Exporter (Prometheus指标收集)
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xzf node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

# 创建node_exporter服务
sudo tee /etc/systemd/system/node_exporter.service << EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

# 创建用户并启动服务
sudo useradd --no-create-home --shell /bin/false node_exporter
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter
```

### 2.2 应用配置详解

#### 🐳 Docker高级配置

**配置Docker daemon:**
```bash
# 创建Docker配置文件
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn"
  ],
  "storage-driver": "overlay2",
  "data-root": "/var/lib/docker"
}
EOF

# 重启Docker服务
sudo systemctl restart docker

# 验证配置
docker info
```

**配置Docker网络:**
```bash
# 创建自定义网络
docker network create --driver bridge devops-network

# 查看网络列表
docker network ls

# 查看网络详情
docker network inspect devops-network
```

#### ⚓ Kubernetes集群配置

**配置K3s集群:**
```bash
# 在Master节点获取node token
sudo cat /var/lib/rancher/k3s/server/node-token

# 在Worker节点加入集群 (在devops-worker上执行)
curl -sfL https://get.k3s.io | K3S_URL=https://192.168.1.10:6443 K3S_TOKEN=<node-token> sh -

# 验证集群状态
kubectl get nodes -o wide
```

**配置Ingress Controller:**
```bash
# 安装Nginx Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# 等待Ingress Controller启动
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=120s
```

#### 🔧 Jenkins详细配置

**Jenkins初始化配置:**
```bash
# 1. 访问 http://192.168.1.10:8080
# 2. 输入初始密码
# 3. 选择 "Install suggested plugins"
# 4. 创建管理员用户

# 安装额外插件 (在Jenkins Web界面)
# - Docker Pipeline
# - Kubernetes
# - Git Parameter
# - Blue Ocean
# - Slack Notification
```

**配置Jenkins系统:**
```bash
# 将jenkins用户加入docker组
sudo usermod -aG docker jenkins

# 重启Jenkins服务
sudo systemctl restart jenkins

# 配置Jenkins工作目录权限
sudo chown -R jenkins:jenkins /var/lib/jenkins
```

#### ✅ 阶段二检查清单

- [ ] Docker安装成功，能正常运行容器
- [ ] Docker Compose安装成功
- [ ] K3s集群部署成功，kubectl能正常使用
- [ ] Helm安装成功
- [ ] Git配置完成
- [ ] Jenkins安装并完成初始配置
- [ ] Node Exporter正常运行
- [ ] 所有服务都设置为开机自启

---

## 阶段三：实践应用部署

> **目标**: 搭建完整的应用部署环境
> **时间**: 2-3周
> **优先级**: P3 ⭐⭐⭐⭐

### 3.1 应用搭建和交互流程

#### 🚀 创建示例应用

**准备项目结构:**
```bash
# 创建项目目录
mkdir -p ~/devops-workspace/demo-app/{app,docker,k8s,monitoring,scripts}
cd ~/devops-workspace/demo-app
```

**创建Node.js示例应用:**
```bash
# 创建package.json
cat > app/package.json << EOF
{
  "name": "devops-demo-app",
  "version": "1.0.0",
  "description": "DevOps Demo Application",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "express": "^4.18.2",
    "redis": "^4.6.7"
  }
}
EOF

# 创建主应用文件
cat > app/app.js << 'EOF'
const express = require('express');
const redis = require('redis');
const app = express();
const port = process.env.PORT || 3000;

// Redis配置
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379
});

redisClient.on('error', (err) => {
  console.log('Redis Client Error', err);
});

// 连接Redis
async function connectRedis() {
  try {
    await redisClient.connect();
    console.log('Connected to Redis');
  } catch (err) {
    console.log('Failed to connect to Redis:', err);
  }
}

connectRedis();

// 中间件
app.use(express.json());

// 路由
app.get('/', (req, res) => {
  res.json({
    message: 'Hello DevOps!',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    hostname: require('os').hostname()
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

app.get('/redis-test', async (req, res) => {
  try {
    await redisClient.set('test-key', 'Hello from Redis!');
    const value = await redisClient.get('test-key');
    res.json({
      status: 'success',
      value: value,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
});

// 启动服务器
app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
});

// 优雅关闭
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await redisClient.quit();
  process.exit(0);
});
EOF

# 创建Dockerfile
cat > docker/Dockerfile << 'EOF'
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制package文件
COPY app/package*.json ./

# 安装依赖
RUN npm install --only=production

# 复制应用代码
COPY app/ .

# 创建非root用户
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001
USER nextjs

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# 启动应用
CMD ["npm", "start"]
EOF
```

#### 🐳 Docker容器化部署

**构建和测试Docker镜像:**
```bash
# 构建镜像
docker build -t devops-demo-app:v1.0.0 -f docker/Dockerfile .

# 运行Redis容器
docker run -d \
  --name redis-server \
  --network devops-network \
  -p 6379:6379 \
  redis:alpine

# 运行应用容器
docker run -d \
  --name demo-app \
  --network devops-network \
  -p 3000:3000 \
  -e REDIS_HOST=redis-server \
  devops-demo-app:v1.0.0

# 测试应用
curl http://localhost:3000/
curl http://localhost:3000/health
curl http://localhost:3000/redis-test
```

**创建Docker Compose配置:**
```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - redis
    networks:
      - app-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - app-network
    restart: unless-stopped
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - app
    networks:
      - app-network
    restart: unless-stopped

networks:
  app-network:
    driver: bridge

volumes:
  redis-data:
EOF

# 创建Nginx配置文件
cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream app {
        server app:3000;
    }

    server {
        listen 80;
        server_name localhost;

        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /health {
            proxy_pass http://app/health;
            access_log off;
        }
    }
}
EOF
```

#### ⚓ Kubernetes部署配置

**创建Kubernetes资源清单:**
```bash
# 创建Namespace
cat > k8s/namespace.yaml << 'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: demo-app
  labels:
    name: demo-app
EOF

# 创建Redis部署
cat > k8s/redis.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: demo-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command: ["redis-server", "--appendonly", "yes"]
        volumeMounts:
        - name: redis-data
          mountPath: /data
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
      volumes:
      - name: redis-data
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: demo-app
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
  type: ClusterIP
EOF

# 创建应用部署
cat > k8s/app.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  namespace: demo-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: demo-app
  template:
    metadata:
      labels:
        app: demo-app
    spec:
      containers:
      - name: app
        image: devops-demo-app:v1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: REDIS_HOST
          value: "redis-service"
        - name: REDIS_PORT
          value: "6379"
        - name: NODE_ENV
          value: "production"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: demo-app-service
  namespace: demo-app
spec:
  selector:
    app: demo-app
  ports:
  - port: 80
    targetPort: 3000
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo-app-ingress
  namespace: demo-app
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: demo-app.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: demo-app-service
            port:
              number: 80
EOF
```

### 3.2 应用验证流程

#### 🔍 Docker环境验证

**验证脚本:**
```bash
#!/bin/bash
# scripts/verify-docker.sh

set -e

echo "=== Docker环境验证 ==="

# 验证Docker服务
echo "1. 检查Docker服务状态..."
if systemctl is-active --quiet docker; then
    echo "✅ Docker服务正常运行"
else
    echo "❌ Docker服务异常"
    exit 1
fi

# 验证Docker Compose
echo "2. 启动应用栈..."
docker-compose up -d

# 等待服务启动
echo "3. 等待服务启动..."
sleep 30

# 检查容器状态
echo "4. 检查容器状态..."
docker-compose ps

# 应用功能测试
echo "5. 应用功能测试..."
if curl -f http://localhost/ > /dev/null 2>&1; then
    echo "✅ 应用主页访问正常"
else
    echo "❌ 应用主页访问失败"
fi

if curl -f http://localhost/health > /dev/null 2>&1; then
    echo "✅ 健康检查正常"
else
    echo "❌ 健康检查失败"
fi

if curl -f http://localhost/redis-test > /dev/null 2>&1; then
    echo "✅ Redis连接正常"
else
    echo "❌ Redis连接失败"
fi

echo "=== Docker验证完成 ==="
```

#### ⚓ Kubernetes环境验证

**验证脚本:**
```bash
#!/bin/bash
# scripts/verify-k8s.sh

set -e

echo "=== Kubernetes环境验证 ==="

# 部署应用
echo "1. 部署应用到Kubernetes..."
kubectl apply -f k8s/

# 等待部署完成
echo "2. 等待部署完成..."
kubectl wait --for=condition=available --timeout=300s deployment/demo-app -n demo-app
kubectl wait --for=condition=available --timeout=300s deployment/redis -n demo-app

# 检查Pod状态
echo "3. 检查Pod状态..."
kubectl get pods -n demo-app

# 检查服务状态
echo "4. 检查服务状态..."
kubectl get services -n demo-app

# 端口转发测试
echo "5. 启动端口转发..."
kubectl port-forward service/demo-app-service 8080:80 -n demo-app &
PORT_FORWARD_PID=$!

# 等待端口转发生效
sleep 10

# 应用功能测试
echo "6. 应用功能测试..."
if curl -f http://localhost:8080/ > /dev/null 2>&1; then
    echo "✅ 应用主页访问正常"
else
    echo "❌ 应用主页访问失败"
fi

if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ 健康检查正常"
else
    echo "❌ 健康检查失败"
fi

# 清理端口转发
kill $PORT_FORWARD_PID

echo "=== Kubernetes验证完成 ==="
```

#### 📊 监控指标验证

**创建监控配置:**
```bash
# 为应用添加Prometheus监控
cat >> app/app.js << 'EOF'

// 添加Prometheus监控端点
const promClient = require('prom-client');

// 创建指标收集器
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();

// 自定义指标
const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status']
});

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route']
});

// 中间件：记录HTTP请求指标
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    httpRequestsTotal.inc({
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode
    });
    httpRequestDuration.observe({
      method: req.method,
      route: req.route?.path || req.path
    }, duration);
  });
  
  next();
});

// Prometheus指标端点
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', promClient.register.contentType);
  res.end(await promClient.register.metrics());
});
EOF
```

#### ✅ 阶段三检查清单

- [ ] 示例应用创建完成
- [ ] Docker镜像构建成功
- [ ] Docker Compose配置正确，能正常启动所有服务
- [ ] Kubernetes资源清单配置完成
- [ ] 应用部署到Kubernetes成功
- [ ] 所有验证脚本运行正常
- [ ] 应用功能测试通过
- [ ] 监控指标端点正常工作

---

## 阶段四：部署运维自动化

> **目标**: 实现完整的CI/CD自动化流程
> **时间**: 3-4周
> **优先级**: P4 ⭐⭐⭐⭐

### 4.1 应用部署策略

#### 🚀 多环境部署配置

**创建环境配置:**
```bash
# 创建环境目录
mkdir -p ~/devops-workspace/demo-app/environments/{dev,staging,prod}

# 开发环境配置
cat > environments/dev/docker-compose.override.yml << 'EOF'
version: '3.8'

services:
  app:
    build:
      context: ../..
      dockerfile: docker/Dockerfile
    environment:
      - NODE_ENV=development
      - DEBUG=true
    volumes:
      - ../../app:/app
    command: npm run dev
    
  redis:
    ports:
      - "6379:6379"
EOF

# 测试环境配置
cat > environments/staging/values.yaml << 'EOF'
app:
  name: demo-app-staging
  namespace: staging
  image:
    repository: devops-demo-app
    tag: staging
    pullPolicy: Always
  
  replicas: 2
  
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

  service:
    type: ClusterIP
    port: 80

  ingress:
    enabled: true
    host: staging.demo-app.local

redis:
  enabled: true
  persistence:
    enabled: false
EOF

# 生产环境配置
cat > environments/prod/values.yaml << 'EOF'
app:
  name: demo-app-prod
  namespace: production
  image:
    repository: devops-demo-app
    tag: v1.0.0
    pullPolicy: IfNotPresent
  
  replicas: 5
  
  resources:
    requests:
      memory: "256Mi"
      cpu: "200m"
    limits:
      memory: "512Mi"
      cpu: "500m"

  service:
    type: ClusterIP
    port: 80

  ingress:
    enabled: true
    host: demo-app.example.com
    tls:
      enabled: true

  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70

redis:
  enabled: true
  persistence:
    enabled: true
    size: 10Gi
  
  resources:
    requests:
      memory: "256Mi"
      cpu: "100m"
    limits:
      memory: "512Mi"
      cpu: "200m"
EOF
```

#### 📦 Helm Chart创建

**创建Helm Chart结构:**
```bash
# 创建Helm Chart
mkdir -p helm/demo-app/{templates,charts}

# Chart.yaml
cat > helm/demo-app/Chart.yaml << 'EOF'
apiVersion: v2
name: demo-app
description: A DevOps Demo Application Helm Chart
type: application
version: 1.0.0
appVersion: "1.0.0"

dependencies:
  - name: redis
    version: "17.11.3"
    repository: "https://charts.bitnami.com/bitnami"
    condition: redis.enabled
EOF

# values.yaml (默认配置)
cat > helm/demo-app/values.yaml << 'EOF'
app:
  name: demo-app
  namespace: default
  
  image:
    repository: devops-demo-app
    tag: latest
    pullPolicy: IfNotPresent
  
  replicas: 3
  
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

  service:
    type: ClusterIP
    port: 80
    targetPort: 3000

  ingress:
    enabled: false
    host: demo-app.local
    tls:
      enabled: false

  autoscaling:
    enabled: false
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 80

redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: false
  master:
    persistence:
      enabled: false
EOF

# Deployment模板
cat > helm/demo-app/templates/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.app.name }}
  namespace: {{ .Values.app.namespace }}
  labels:
    app: {{ .Values.app.name }}
    version: {{ .Values.app.image.tag }}
spec:
  replicas: {{ .Values.app.replicas }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: {{ .Values.app.name }}
  template:
    metadata:
      labels:
        app: {{ .Values.app.name }}
        version: {{ .Values.app.image.tag }}
    spec:
      containers:
      - name: {{ .Values.app.name }}
        image: "{{ .Values.app.image.repository }}:{{ .Values.app.image.tag }}"
        imagePullPolicy: {{ .Values.app.image.pullPolicy }}
        ports:
        - containerPort: {{ .Values.app.service.targetPort }}
        env:
        - name: NODE_ENV
          value: "production"
        {{- if .Values.redis.enabled }}
        - name: REDIS_HOST
          value: "{{ .Release.Name }}-redis-master"
        - name: REDIS_PORT
          value: "6379"
        {{- end }}
        livenessProbe:
          httpGet:
            path: /health
            port: {{ .Values.app.service.targetPort }}
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: {{ .Values.app.service.targetPort }}
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          {{- toYaml .Values.app.resources | nindent 10 }}
EOF

# Service模板
cat > helm/demo-app/templates/service.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.app.name }}-service
  namespace: {{ .Values.app.namespace }}
  labels:
    app: {{ .Values.app.name }}
spec:
  type: {{ .Values.app.service.type }}
  ports:
  - port: {{ .Values.app.service.port }}
    targetPort: {{ .Values.app.service.targetPort }}
    protocol: TCP
  selector:
    app: {{ .Values.app.name }}
EOF

# HPA模板
cat > helm/demo-app/templates/hpa.yaml << 'EOF'
{{- if .Values.app.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ .Values.app.name }}-hpa
  namespace: {{ .Values.app.namespace }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ .Values.app.name }}
  minReplicas: {{ .Values.app.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.app.autoscaling.maxReplicas }}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {{ .Values.app.autoscaling.targetCPUUtilizationPercentage }}
{{- end }}
EOF
```

#### 🎯 蓝绿部署实现

**蓝绿部署脚本:**
```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

set -e

NAMESPACE=${1:-production}
APP_NAME=${2:-demo-app}
NEW_VERSION=${3}
TIMEOUT=${4:-300}

if [ -z "$NEW_VERSION" ]; then
    echo "用法: $0 <namespace> <app-name> <new-version> [timeout]"
    echo "示例: $0 production demo-app v1.1.0 300"
    exit 1
fi

echo "=== 蓝绿部署开始 ==="
echo "命名空间: $NAMESPACE"
echo "应用名称: $APP_NAME"
echo "新版本: $NEW_VERSION"

# 获取当前活跃颜色
CURRENT_COLOR=$(kubectl get service $APP_NAME-service -n $NAMESPACE -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "blue")
NEW_COLOR=$([ "$CURRENT_COLOR" = "blue" ] && echo "green" || echo "blue")

echo "当前活跃版本: $CURRENT_COLOR"
echo "新版本部署到: $NEW_COLOR"

# 部署新版本
echo "1. 部署新版本到 $NEW_COLOR 环境..."
helm upgrade --install $APP_NAME-$NEW_COLOR ./helm/demo-app \
  --namespace $NAMESPACE \
  --set app.name=$APP_NAME-$NEW_COLOR \
  --set app.namespace=$NAMESPACE \
  --set app.image.tag=$NEW_VERSION \
  --set app.service.selector.color=$NEW_COLOR \
  --wait --timeout=${TIMEOUT}s

# 等待新版本就绪
echo "2. 等待新版本就绪..."
kubectl wait --for=condition=available \
  --timeout=${TIMEOUT}s \
  deployment/$APP_NAME-$NEW_COLOR \
  -n $NAMESPACE

# 健康检查
echo "3. 执行健康检查..."
kubectl port-forward service/$APP_NAME-$NEW_COLOR-service 9000:80 -n $NAMESPACE &
PORT_FORWARD_PID=$!
sleep 10

HEALTH_CHECK_PASSED=false
for i in {1..10}; do
    if curl -f http://localhost:9000/health > /dev/null 2>&1; then
        echo "✅ 健康检查通过 (尝试 $i/10)"
        HEALTH_CHECK_PASSED=true
        break
    else
        echo "⏳ 健康检查失败，重试中... (尝试 $i/10)"
        sleep 10
    fi
done

kill $PORT_FORWARD_PID 2>/dev/null || true

if [ "$HEALTH_CHECK_PASSED" = false ]; then
    echo "❌ 健康检查失败，回滚部署"
    helm uninstall $APP_NAME-$NEW_COLOR -n $NAMESPACE
    exit 1
fi

# 切换流量
echo "4. 切换流量到新版本..."
kubectl patch service $APP_NAME-service -n $NAMESPACE \
  -p '{"spec":{"selector":{"color":"'$NEW_COLOR'"}}}'

echo "5. 验证流量切换..."
sleep 30

# 清理旧版本
echo "6. 清理旧版本..."
helm uninstall $APP_NAME-$CURRENT_COLOR -n $NAMESPACE 2>/dev/null || true

echo "=== 蓝绿部署完成 ==="
echo "新版本 $NEW_VERSION 已成功部署到 $NEW_COLOR 环境"
```

### 4.2 CI/CD自动化流程

#### 🔄 Jenkins Pipeline配置

**创建Jenkinsfile:**
```bash
cat > Jenkinsfile << 'EOF'
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'localhost:5000'
        APP_NAME = 'devops-demo-app'
        DOCKER_IMAGE = "${DOCKER_REGISTRY}/${APP_NAME}"
        KUBECONFIG = credentials('kubeconfig')
        SLACK_CHANNEL = '#devops'
    }
    
    parameters {
        choice(
            name: 'DEPLOY_ENV',
            choices: ['staging', 'production'],
            description: '选择部署环境'
        )
        booleanParam(
            name: 'SKIP_TESTS',
            defaultValue: false,
            description: '跳过测试'
        )
        string(
            name: 'VERSION_TAG',
            defaultValue: '',
            description: '版本标签 (留空自动生成)'
        )
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.VERSION_TAG = params.VERSION_TAG ?: "v${BUILD_NUMBER}-${GIT_COMMIT.take(7)}"
                    env.IMAGE_TAG = "${DOCKER_IMAGE}:${env.VERSION_TAG}"
                }
            }
        }
        
        stage('Install Dependencies') {
            steps {
                dir('app') {
                    sh 'npm ci'
                }
            }
        }
        
        stage('Run Tests') {
            when {
                not { params.SKIP_TESTS }
            }
            steps {
                dir('app') {
                    sh 'npm test'
                    sh 'npm run lint || true'
                }
            }
            post {
                always {
                    publishTestResults testResultsPattern: 'app/test-results.xml'
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                dir('app') {
                    sh 'npm audit --audit-level moderate'
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    def image = docker.build(env.IMAGE_TAG, "-f docker/Dockerfile .")
                    image.push()
                    image.push("${DOCKER_IMAGE}:latest")
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                anyOf {
                    branch 'develop'
                    params.DEPLOY_ENV == 'staging'
                }
            }
            steps {
                script {
                    sh """
                        helm upgrade --install demo-app-staging ./helm/demo-app \
                          --namespace staging \
                          --create-namespace \
                          --set app.namespace=staging \
                          --set app.image.tag=${env.VERSION_TAG} \
                          --set app.replicas=2 \
                          --wait --timeout=300s
                    """
                }
            }
        }
        
        stage('Integration Tests') {
            when {
                anyOf {
                    branch 'develop'
                    params.DEPLOY_ENV == 'staging'
                }
            }
            steps {
                sh './scripts/integration-tests.sh staging'
            }
        }
        
        stage('Deploy to Production') {
            when {
                anyOf {
                    branch 'main'
                    params.DEPLOY_ENV == 'production'
                }
            }
            steps {
                script {
                    input message: '确认部署到生产环境?', ok: '部署'
                    
                    sh """
                        ./scripts/blue-green-deploy.sh production demo-app ${env.VERSION_TAG}
                    """
                }
            }
        }
        
        stage('Production Health Check') {
            when {
                anyOf {
                    branch 'main'
                    params.DEPLOY_ENV == 'production'
                }
            }
            steps {
                sh './scripts/health-check.sh production'
            }
        }
    }
    
    post {
        success {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'good',
                message: "✅ 部署成功: ${env.APP_NAME} ${env.VERSION_TAG} 到 ${params.DEPLOY_ENV}"
            )
        }
        failure {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'danger',
                message: "❌ 部署失败: ${env.APP_NAME} ${env.VERSION_TAG} 到 ${params.DEPLOY_ENV}\n详情: ${BUILD_URL}"
            )
        }
        always {
            cleanWs()
        }
    }
}
EOF
```

#### 🐱 GitHub Actions工作流

**创建GitHub Actions配置:**
```bash
mkdir -p .github/workflows

cat > .github/workflows/ci-cd.yml << 'EOF'
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: app/package-lock.json
    
    - name: Install dependencies
      run: |
        cd app
        npm ci
    
    - name: Run linting
      run: |
        cd app
        npm run lint
    
    - name: Run tests
      run: |
        cd app
        npm test
    
    - name: Run security audit
      run: |
        cd app
        npm audit --audit-level moderate

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    
    permissions:
      contents: read
      packages: write
    
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
      image-digest: ${{ steps.build.outputs.digest }}
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
          type=sha,prefix={{branch}}-
    
    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        file: ./docker/Dockerfile
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}

  deploy-staging:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBECONFIG }}
    
    - name: Install Helm
      uses: azure/setup-helm@v3
      with:
        version: '3.12.0'
    
    - name: Deploy to staging
      run: |
        helm upgrade --install demo-app-staging ./helm/demo-app \
          --namespace staging \
          --create-namespace \
          --set app.namespace=staging \
          --set app.image.repository=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }} \
          --set app.image.tag=${{ github.sha }} \
          --set app.replicas=2 \
          --wait --timeout=300s
    
    - name: Run integration tests
      run: ./scripts/integration-tests.sh staging

  deploy-production:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBECONFIG }}
    
    - name: Install Helm
      uses: azure/setup-helm@v3
      with:
        version: '3.12.0'
    
    - name: Deploy to production
      run: |
        ./scripts/blue-green-deploy.sh production demo-app ${{ github.sha }}
    
    - name: Production health check
      run: ./scripts/health-check.sh production
    
    - name: Notify success
      if: success()
      uses: 8398a7/action-slack@v3
      with:
        status: success
        channel: '#devops'
        text: '✅ 生产环境部署成功: ${{ github.sha }}'
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
    
    - name: Notify failure
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        channel: '#devops'
        text: '❌ 生产环境部署失败: ${{ github.sha }}'
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
EOF
```

#### 🦊 GitLab CI/CD配置

**创建GitLab CI配置:**
```bash
cat > .gitlab-ci.yml << 'EOF'
stages:
  - test
  - build
  - deploy-staging
  - deploy-production

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  APP_NAME: "devops-demo-app"
  REGISTRY: $CI_REGISTRY
  IMAGE: $CI_REGISTRY_IMAGE

# 缓存配置
cache:
  paths:
    - app/node_modules/

# 测试阶段
test:
  stage: test
  image: node:18
  script:
    - cd app
    - npm ci
    - npm run lint
    - npm test
    - npm audit --audit-level moderate
  coverage: '/Statements\s*:\s*([^%]+)/'
  artifacts:
    reports:
      junit: app/test-results.xml
      coverage_report:
        coverage_format: cobertura
        path: app/coverage/cobertura-coverage.xml

# 构建阶段
build:
  stage: build
  image: docker:24.0.5
  services:
    - docker:24.0.5-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - |
      if [[ "$CI_COMMIT_BRANCH" == "$CI_DEFAULT_BRANCH" ]]; then
        tag=""
        echo "Running on default branch '$CI_DEFAULT_BRANCH': tag = 'latest'"
      else
        tag=":$CI_COMMIT_REF_SLUG"
        echo "Running on branch '$CI_COMMIT_BRANCH': tag = $tag"
      fi
    - docker build -t $IMAGE:$CI_COMMIT_SHA -f docker/Dockerfile .
    - docker push $IMAGE:$CI_COMMIT_SHA
    - docker tag $IMAGE:$CI_COMMIT_SHA $IMAGE$tag
    - docker push $IMAGE$tag
  only:
    - main
    - develop

# 部署到测试环境
deploy-staging:
  stage: deploy-staging
  image: alpine/helm:3.12.0
  before_script:
    - apk add --no-cache curl
    - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    - chmod +x kubectl
    - mv kubectl /usr/local/bin/
    - echo $KUBECONFIG | base64 -d > kubeconfig
    - export KUBECONFIG=kubeconfig
  script:
    - |
      helm upgrade --install demo-app-staging ./helm/demo-app \
        --namespace staging \
        --create-namespace \
        --set app.namespace=staging \
        --set app.image.repository=$IMAGE \
        --set app.image.tag=$CI_COMMIT_SHA \
        --set app.replicas=2 \
        --wait --timeout=300s
    - ./scripts/integration-tests.sh staging
  environment:
    name: staging
    url: https://staging.demo-app.local
  only:
    - develop

# 部署到生产环境
deploy-production:
  stage: deploy-production
  image: alpine/helm:3.12.0
  before_script:
    - apk add --no-cache curl bash
    - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    - chmod +x kubectl
    - mv kubectl /usr/local/bin/
    - echo $KUBECONFIG | base64 -d > kubeconfig
    - export KUBECONFIG=kubeconfig
  script:
    - ./scripts/blue-green-deploy.sh production demo-app $CI_COMMIT_SHA
    - ./scripts/health-check.sh production
  environment:
    name: production
    url: https://demo-app.example.com
  when: manual
  only:
    - main

# 通知配置
.notify_success: &notify_success
  - |
    curl -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"✅ 部署成功: $APP_NAME $CI_COMMIT_SHA 到 $CI_ENVIRONMENT_NAME\"}" \
      $SLACK_WEBHOOK_URL

.notify_failure: &notify_failure
  - |
    curl -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"❌ 部署失败: $APP_NAME $CI_COMMIT_SHA 到 $CI_ENVIRONMENT_NAME\n详情: $CI_PIPELINE_URL\"}" \
      $SLACK_WEBHOOK_URL

# 成功后通知
notify-success:
  stage: .post
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
  script: *notify_success
  when: on_success
  only:
    - main
    - develop

# 失败后通知
notify-failure:
  stage: .post
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
  script: *notify_failure
  when: on_failure
  only:
    - main
    - develop
EOF
```

#### ✅ 阶段四检查清单

- [ ] 多环境配置文件创建完成
- [ ] Helm Chart配置正确
- [ ] 蓝绿部署脚本测试成功
- [ ] Jenkins Pipeline配置完成
- [ ] GitHub Actions工作流配置完成
- [ ] GitLab CI/CD配置完成
- [ ] 所有部署脚本能正常执行
- [ ] CI/CD流程端到端测试通过

---

## 阶段五：高级运维监控

> **目标**: 实现完整的监控、告警和自动化运维
> **时间**: 2-3周
> **优先级**: P5 ⭐⭐⭐

### 5.1 监控体系搭建

#### 📊 Prometheus监控配置

**部署Prometheus Stack:**
```bash
# 创建监控命名空间
kubectl create namespace monitoring

# 添加Prometheus Helm仓库
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# 创建Prometheus配置
cat > monitoring/prometheus-values.yaml << 'EOF'
prometheus:
  prometheusSpec:
    retention: 15d
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: local-path
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 10Gi
    
    additionalScrapeConfigs:
      - job_name: 'demo-app'
        kubernetes_sd_configs:
          - role: pod
            namespaces:
              names:
                - default
                - staging
                - production
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
            action: keep
            regex: true
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
            action: replace
            target_label: __metrics_path__
            regex: (.+)

grafana:
  adminPassword: admin123
  persistence:
    enabled: true
    size: 5Gi
  
  dashboardsConfigMaps:
    demo-app: demo-app-dashboard
  
  datasources:
    datasources.yaml:
      apiVersion: 1
      datasources:
        - name: Prometheus
          type: prometheus
          url: http://prometheus-server:80
          access: proxy
          isDefault: true

alertmanager:
  config:
    global:
      slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'
    
    route:
      group_by: ['alertname']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 1h
      receiver: 'web.hook'
    
    receivers:
      - name: 'web.hook'
        slack_configs:
          - channel: '#alerts'
            text: 'Summary: {{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

nodeExporter:
  enabled: true

pushgateway:
  enabled: true

serverFiles:
  alerting_rules.yml:
    groups:
      - name: demo-app.rules
        rules:
          - alert: HighErrorRate
            expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
            for: 5m
            labels:
              severity: critical
            annotations:
              summary: "应用错误率过高"
              description: "{{ $labels.instance }} 错误率为 {{ $value }}"
          
          - alert: HighMemoryUsage
            expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.8
            for: 10m
            labels:
              severity: warning
            annotations:
              summary: "内存使用率过高"
              description: "{{ $labels.pod }} 内存使用率超过80%"
          
          - alert: PodCrashLooping
            expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
            for: 5m
            labels:
              severity: critical
            annotations:
              summary: "Pod频繁重启"
              description: "{{ $labels.pod }} 在过去15分钟内重启了 {{ $value }} 次"
EOF

# 部署Prometheus Stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --values monitoring/prometheus-values.yaml
```

#### 📈 Grafana Dashboard配置

**创建应用监控Dashboard:**
```bash
cat > monitoring/demo-app-dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "DevOps Demo App监控",
    "tags": ["devops", "demo"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "HTTP请求总数",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total[5m]))",
            "legendFormat": "RPS"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 50},
                {"color": "red", "value": 100}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "错误率",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m])) * 100",
            "legendFormat": "Error Rate %"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 1},
                {"color": "red", "value": 5}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0}
      },
      {
        "id": 3,
        "title": "响应时间",
        "type": "stat",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "s",
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 0.5},
                {"color": "red", "value": 1}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0}
      },
      {
        "id": 4,
        "title": "Pod状态",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(kube_pod_status_phase{phase=\"Running\"})",
            "legendFormat": "Running Pods"
          }
        ],
        "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
      },
      {
        "id": 5,
        "title": "HTTP请求趋势",
        "type": "graph",
        "targets": [
          {
            "expr": "sum by (status) (rate(http_requests_total[5m]))",
            "legendFormat": "{{status}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
      },
      {
        "id": 6,
        "title": "内存使用",
        "type": "graph",
        "targets": [
          {
            "expr": "sum by (pod) (container_memory_usage_bytes{container=\"demo-app\"})",
            "legendFormat": "{{pod}}"
          }
        ],
        "yAxes": [
          {
            "unit": "bytes"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
EOF

# 创建ConfigMap
kubectl create configmap demo-app-dashboard \
  --from-file=monitoring/demo-app-dashboard.json \
  --namespace monitoring
```

#### 📋 ELK Stack日志收集

**部署ELK Stack:**
```bash
cat > monitoring/elk-stack.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: filebeat-config
  namespace: monitoring
data:
  filebeat.yml: |
    filebeat.inputs:
    - type: container
      paths:
        - /var/log/containers/*.log
      processors:
        - add_kubernetes_metadata:
            host: ${NODE_NAME}
            matchers:
            - logs_path:
                logs_path: "/var/log/containers/"
    
    output.logstash:
      hosts: ["logstash:5044"]
    
    processors:
      - add_host_metadata: ~
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: filebeat
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: filebeat
  template:
    metadata:
      labels:
        app: filebeat
    spec:
      serviceAccountName: filebeat
      containers:
      - name: filebeat
        image: docker.elastic.co/beats/filebeat:8.8.0
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: config
          mountPath: /usr/share/filebeat/filebeat.yml
          subPath: filebeat.yml
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: varlog
          mountPath: /var/log
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: filebeat-config
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: varlog
        hostPath:
          path: /var/log
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: filebeat
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: filebeat
rules:
- apiGroups: [""]
  resources: ["nodes", "namespaces", "pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: filebeat
subjects:
- kind: ServiceAccount
  name: filebeat
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: filebeat
  apiGroup: rbac.authorization.k8s.io
EOF

# 使用Helm部署ELK Stack
helm repo add elastic https://helm.elastic.co
helm repo update

# 部署Elasticsearch
helm install elasticsearch elastic/elasticsearch \
  --namespace monitoring \
  --set replicas=1 \
  --set minimumMasterNodes=1

# 部署Kibana
helm install kibana elastic/kibana \
  --namespace monitoring \
  --set elasticsearchHosts="http://elasticsearch-master:9200"

# 部署Logstash
cat > monitoring/logstash-values.yaml << 'EOF'
logstashConfig:
  logstash.yml: |
    http.host: 0.0.0.0
    xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch-master:9200"]

logstashPipeline:
  logstash.conf: |
    input {
      beats {
        port => 5044
      }
    }
    
    filter {
      if [kubernetes] {
        mutate {
          add_field => {
            "container_name" => "%{[kubernetes][container][name]}"
            "namespace" => "%{[kubernetes][namespace]}"
            "pod_name" => "%{[kubernetes][pod][name]}"
          }
        }
      }
      
      # 解析JSON日志
      if [message] =~ /^\{.*\}$/ {
        json {
          source => "message"
        }
      }
      
      # 添加时间戳
      date {
        match => [ "@timestamp", "ISO8601" ]
      }
    }
    
    output {
      elasticsearch {
        hosts => ["http://elasticsearch-master:9200"]
        index => "demo-app-logs-%{+YYYY.MM.dd}"
      }
    }

service:
  type: ClusterIP
  ports:
    - name: beats
      port: 5044
      protocol: TCP
      targetPort: 5044
EOF

helm install logstash elastic/logstash \
  --namespace monitoring \
  --values monitoring/logstash-values.yaml

# 部署Filebeat
kubectl apply -f monitoring/elk-stack.yaml
```

### 5.2 自动化运维脚本

#### 🤖 运维自动化脚本

**创建综合运维脚本:**
```bash
#!/bin/bash
# scripts/auto-ops.sh

set -e

# 配置参数
NAMESPACE=${NAMESPACE:-production}
APP_NAME=${APP_NAME:-demo-app}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-7}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS:-30}
ALERT_WEBHOOK=${ALERT_WEBHOOK:-""}

# 日志函数
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# 发送告警
send_alert() {
    local message="$1"
    local level="$2"
    
    log "$level: $message"
    
    if [ -n "$ALERT_WEBHOOK" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$level: $message\"}" \
            "$ALERT_WEBHOOK" || true
    fi
}

# 健康检查
health_check() {
    log "执行健康检查..."
    
    # 检查Pod状态
    local unhealthy_pods=$(kubectl get pods -n $NAMESPACE -l app=$APP_NAME --field-selector=status.phase!=Running --no-headers | wc -l)
    
    if [ $unhealthy_pods -gt 0 ]; then
        send_alert "发现 $unhealthy_pods 个异常Pod" "WARNING"
        
        # 尝试重启异常Pod
        kubectl delete pods -n $NAMESPACE -l app=$APP_NAME --field-selector=status.phase!=Running
        sleep 60
        
        # 再次检查
        unhealthy_pods=$(kubectl get pods -n $NAMESPACE -l app=$APP_NAME --field-selector=status.phase!=Running --no-headers | wc -l)
        if [ $unhealthy_pods -gt 0 ]; then
            send_alert "重启后仍有 $unhealthy_pods 个异常Pod" "CRITICAL"
        else
            send_alert "异常Pod已恢复" "INFO"
        fi
    fi
    
    # 检查服务可用性
    local service_endpoint=$(kubectl get service $APP_NAME-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
    
    if ! kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl -- \
        curl -f http://$service_endpoint/health > /dev/null 2>&1; then
        send_alert "服务健康检查失败" "CRITICAL"
        return 1
    fi
    
    log "健康检查通过"
    return 0
}

# 资源清理
cleanup_resources() {
    log "执行资源清理..."
    
    # 清理Docker资源 (在所有节点上执行)
    kubectl get nodes -o name | while read node; do
        node_name=$(echo $node | cut -d'/' -f2)
        log "清理节点 $node_name 的Docker资源"
        
        kubectl debug node/$node_name -it --image=alpine -- sh -c "
            chroot /host docker system prune -f
            chroot /host docker image prune -f
            chroot /host docker volume prune -f
        " || true
    done
    
    # 清理Kubernetes资源
    log "清理过期的Job和Pod"
    kubectl delete jobs -n $NAMESPACE --field-selector=status.successful=1 --ignore-not-found=true
    kubectl delete pods -n $NAMESPACE --field-selector=status.phase=Succeeded --ignore-not-found=true
    kubectl delete pods -n $NAMESPACE --field-selector=status.phase=Failed --ignore-not-found=true
    
    log "资源清理完成"
}

# 备份数据
backup_data() {
    log "执行数据备份..."
    
    local backup_date=$(date +%Y%m%d_%H%M%S)
    local backup_path="/backup/demo-app-$backup_date"
    
    # 创建备份目录
    mkdir -p $backup_path
    
    # 备份Redis数据 (如果存在)
    if kubectl get deployment redis -n $NAMESPACE > /dev/null 2>&1; then
        log "备份Redis数据"
        kubectl exec deployment/redis -n $NAMESPACE -- redis-cli BGSAVE
        kubectl cp $NAMESPACE/$(kubectl get pods -n $NAMESPACE -l app=redis -o jsonpath='{.items[0].metadata.name}'):/data/dump.rdb $backup_path/redis-dump.rdb
    fi
    
    # 备份应用配置
    log "备份应用配置"
    kubectl get configmaps -n $NAMESPACE -o yaml > $backup_path/configmaps.yaml
    kubectl get secrets -n $NAMESPACE -o yaml > $backup_path/secrets.yaml
    
    # 压缩备份
    tar -czf $backup_path.tar.gz -C /backup demo-app-$backup_date
    rm -rf $backup_path
    
    # 清理旧备份
    find /backup -name "demo-app-*.tar.gz" -mtime +$BACKUP_RETENTION_DAYS -delete
    
    log "数据备份完成: $backup_path.tar.gz"
}

# 日志清理
cleanup_logs() {
    log "执行日志清理..."
    
    # 清理本地日志
    find /var/log -name "*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
    
    # 清理Elasticsearch索引 (如果存在)
    if kubectl get service elasticsearch-master -n monitoring > /dev/null 2>&1; then
        local es_endpoint=$(kubectl get service elasticsearch-master -n monitoring -o jsonpath='{.spec.clusterIP}')
        local cutoff_date=$(date -d "$LOG_RETENTION_DAYS days ago" +%Y.%m.%d)
        
        # 删除过期索引
        kubectl run es-cleanup --rm -i --restart=Never --image=curlimages/curl -- \
            curl -X DELETE "http://$es_endpoint:9200/demo-app-logs-*" -H "Content-Type: application/json" -d "{
                \"query\": {
                    \"range\": {
                        \"@timestamp\": {
                            \"lt\": \"$cutoff_date||/d\"
                        }
                    }
                }
            }" || true
    fi
    
    log "日志清理完成"
}

# 性能优化
optimize_performance() {
    log "执行性能优化..."
    
    # 检查资源使用情况
    local cpu_usage=$(kubectl top pods -n $NAMESPACE --no-headers | awk '{sum+=$2} END {print sum}' | sed 's/m//')
    local memory_usage=$(kubectl top pods -n $NAMESPACE --no-headers | awk '{sum+=$3} END {print sum}' | sed 's/Mi//')
    
    log "当前CPU使用: ${cpu_usage}m, 内存使用: ${memory_usage}Mi"
    
    # 根据资源使用情况调整HPA
    if [ ${cpu_usage:-0} -gt 500 ]; then
        log "CPU使用率较高，调整HPA参数"
        kubectl patch hpa $APP_NAME-hpa -n $NAMESPACE -p '{"spec":{"targetCPUUtilizationPercentage":60}}'
    fi
    
    # 检查并重启长时间运行的Pod
    kubectl get pods -n $NAMESPACE -o custom-columns=NAME:.metadata.name,AGE:.status.startTime \
        --no-headers | while read pod_name start_time; do
        if [ -n "$start_time" ]; then
            local pod_age_seconds=$(( $(date +%s) - $(date -d "$start_time" +%s) ))
            local pod_age_days=$(( pod_age_seconds / 86400 ))
            
            if [ $pod_age_days -gt 7 ]; then
                log "重启长时间运行的Pod: $pod_name (运行了 $pod_age_days 天)"
                kubectl delete pod $pod_name -n $NAMESPACE
            fi
        fi
    done
    
    log "性能优化完成"
}

# 生成运维报告
generate_report() {
    log "生成运维报告..."
    
    local report_date=$(date +%Y-%m-%d)
    local report_file="/tmp/ops-report-$report_date.md"
    
    cat > $report_file << EOF
# 运维报告 - $report_date

## 系统概览
- 报告时间: $(date)
- 命名空间: $NAMESPACE
- 应用名称: $APP_NAME

## 集群状态
### 节点状态
\`\`\`
$(kubectl get nodes)
\`\`\`

### Pod状态
\`\`\`
$(kubectl get pods -n $NAMESPACE -o wide)
\`\`\`

## 资源使用情况
### CPU和内存使用
\`\`\`
$(kubectl top pods -n $NAMESPACE)
\`\`\`

### 存储使用
\`\`\`
$(kubectl get pv)
\`\`\`

## 服务状态
### 服务列表
\`\`\`
$(kubectl get services -n $NAMESPACE)
\`\`\`

### Ingress状态
\`\`\`
$(kubectl get ingress -n $NAMESPACE)
\`\`\`

## 近期事件
\`\`\`
$(kubectl get events -n $NAMESPACE --sort-by='.firstTimestamp' | tail -20)
\`\`\`

## 告警信息
$(kubectl get pods -n monitoring -l app.kubernetes.io/name=alertmanager -o name | head -1 | xargs kubectl logs -n monitoring --tail=50 | grep -E "(FIRING|RESOLVED)" | tail -10 || echo "无告警信息")

---
*报告由自动化运维脚本生成*
EOF
    
    log "运维报告已生成: $report_file"
    
    # 如果配置了邮件或Slack，可以发送报告
    if [ -n "$ALERT_WEBHOOK" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"📊 运维报告已生成: $report_date\n查看详情: \`cat $report_file\`\"}" \
            "$ALERT_WEBHOOK" || true
    fi
}

# 主函数
main() {
    local action=${1:-all}
    
    case $action in
        "health")
            health_check
            ;;
        "cleanup")
            cleanup_resources
            ;;
        "backup")
            backup_data
            ;;
        "logs")
            cleanup_logs
            ;;
        "optimize")
            optimize_performance
            ;;
        "report")
            generate_report
            ;;
        "all")
            log "执行完整运维流程..."
            health_check || send_alert "健康检查失败" "CRITICAL"
            cleanup_resources
            cleanup_logs
            optimize_performance
            backup_data
            generate_report
            log "完整运维流程执行完成"
            ;;
        *)
            echo "用法: $0 {health|cleanup|backup|logs|optimize|report|all}"
            echo ""
            echo "选项说明:"
            echo "  health   - 执行健康检查"
            echo "  cleanup  - 清理系统资源"
            echo "  backup   - 备份重要数据"
            echo "  logs     - 清理过期日志"
            echo "  optimize - 性能优化"
            echo "  report   - 生成运维报告"
            echo "  all      - 执行所有操作"
            exit 1
            ;;
    esac
}

# 错误处理
trap 'send_alert "运维脚本执行失败: $0 $*" "ERROR"' ERR

# 执行主函数
main "$@"
```

#### ⏰ 定时任务配置

**创建CronJob配置:**
```bash
cat > monitoring/cronjobs.yaml << 'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-ops
  namespace: monitoring
spec:
  schedule: "0 2 * * *"  # 每天凌晨2点执行
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ops-automation
          containers:
          - name: auto-ops
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache curl bash kubectl
              /scripts/auto-ops.sh all
            env:
            - name: NAMESPACE
              value: "production"
            - name: APP_NAME
              value: "demo-app"
            - name: ALERT_WEBHOOK
              valueFrom:
                secretKeyRef:
                  name: ops-secrets
                  key: slack-webhook
            volumeMounts:
            - name: scripts
              mountPath: /scripts
            - name: backup
              mountPath: /backup
          volumes:
          - name: scripts
            configMap:
              name: ops-scripts
              defaultMode: 0755
          - name: backup
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hourly-health-check
  namespace: monitoring
spec:
  schedule: "0 * * * *"  # 每小时执行
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ops-automation
          containers:
          - name: health-check
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache curl bash kubectl
              /scripts/auto-ops.sh health
            env:
            - name: NAMESPACE
              value: "production"
            - name: APP_NAME
              value: "demo-app"
            - name: ALERT_WEBHOOK
              valueFrom:
                secretKeyRef:
                  name: ops-secrets
                  key: slack-webhook
            volumeMounts:
            - name: scripts
              mountPath: /scripts
          volumes:
          - name: scripts
            configMap:
              name: ops-scripts
              defaultMode: 0755
          restartPolicy: OnFailure
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: weekly-backup
  namespace: monitoring
spec:
  schedule: "0 3 * * 0"  # 每周日凌晨3点执行
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ops-automation
          containers:
          - name: backup
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache curl bash kubectl
              /scripts/auto-ops.sh backup
            env:
            - name: NAMESPACE
              value: "production"
            - name: APP_NAME
              value: "demo-app"
            volumeMounts:
            - name: scripts
              mountPath: /scripts
            - name: backup
              mountPath: /backup
          volumes:
          - name: scripts
            configMap:
              name: ops-scripts
              defaultMode: 0755
          - name: backup
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
---
# RBAC配置
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ops-automation
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ops-automation
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets", "nodes"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods", "nodes"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ops-automation
subjects:
- kind: ServiceAccount
  name: ops-automation
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: ops-automation
  apiGroup: rbac.authorization.k8s.io
---
# 存储配置
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: backup-pvc
  namespace: monitoring
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
EOF

# 创建运维脚本ConfigMap
kubectl create configmap ops-scripts \
  --from-file=auto-ops.sh=scripts/auto-ops.sh \
  --namespace monitoring

# 创建Secrets (需要替换实际的Webhook URL)
kubectl create secret generic ops-secrets \
  --from-literal=slack-webhook="YOUR_SLACK_WEBHOOK_URL" \
  --namespace monitoring

# 部署CronJobs
kubectl apply -f monitoring/cronjobs.yaml
```

#### ✅ 阶段五检查清单

- [ ] Prometheus监控系统部署成功
- [ ] Grafana Dashboard配置完成
- [ ] ELK Stack日志收集系统正常运行
- [ ] 告警规则配置正确，能正常发送告警
- [ ] 自动化运维脚本测试通过
- [ ] CronJob定时任务配置完成
- [ ] 监控数据收集正常
- [ ] 日志收集和分析功能正常
- [ ] 运维报告能正常生成

---

## 学习时间规划

### 📅 建议学习计划

| 阶段 | 时间安排 | 每日学习时间 | 重点内容 |
|------|----------|--------------|----------|
| **阶段一** | 第1-2周 | 2-3小时 | 基础环境搭建，系统安装配置 |
| **阶段二** | 第3-5周 | 3-4小时 | 核心工具安装配置，Docker/K8s基础 |
| **阶段三** | 第6-8周 | 3-4小时 | 应用容器化，K8s部署实践 |
| **阶段四** | 第9-12周 | 4-5小时 | CI/CD流程，自动化部署 |
| **阶段五** | 第13-15周 | 2-3小时 | 监控告警，运维自动化 |

### 🎯 每周学习目标

**第1周：环境准备**
- [ ] 搭建虚拟化环境
- [ ] 安装Ubuntu Server
- [ ] 基础网络配置
- [ ] SSH密钥配置

**第2周：系统配置**
- [ ] 安全配置强化
- [ ] 用户权限管理
- [ ] 防火墙配置
- [ ] 系统监控基础

**第3周：Docker基础**
- [ ] Docker安装配置
- [ ] Docker命令实践
- [ ] Dockerfile编写
- [ ] Docker网络和存储

**第4周：Docker进阶**
- [ ] Docker Compose实践
- [ ] 多容器应用部署
- [ ] 镜像优化
- [ ] Docker安全实践

**第5周：Kubernetes基础**
- [ ] K8s集群搭建
- [ ] Pod和Service概念
- [ ] Deployment实践
- [ ] kubectl命令掌握

**第6周：应用容器化**
- [ ] 创建示例应用
- [ ] 应用Docker化
- [ ] 多环境配置
- [ ] 健康检查配置

**第7周：K8s应用部署**
- [ ] 应用部署到K8s
- [ ] Service和Ingress配置
- [ ] ConfigMap和Secret使用
- [ ] 资源限制和调度

**第8周：应用验证**
- [ ] 功能测试脚本
- [ ] 性能测试
- [ ] 监控指标配置
- [ ] 故障排查实践

**第9周：Helm和包管理**
- [ ] Helm Chart创建
- [ ] 模板化配置
- [ ] 版本管理
- [ ] 多环境部署

**第10周：CI/CD基础**
- [ ] Jenkins安装配置
- [ ] Pipeline基础
- [ ] Git集成
- [ ] 自动化测试

**第11周：CI/CD进阶**
- [ ] 多分支策略
- [ ] 蓝绿部署
- [ ] 滚动更新
- [ ] 回滚策略

**第12周：CI/CD实践**
- [ ] GitHub Actions
- [ ] GitLab CI
- [ ] 多平台CI/CD对比
- [ ] 最佳实践总结

**第13周：监控系统**
- [ ] Prometheus部署
- [ ] 指标收集配置
- [ ] Grafana Dashboard
- [ ] 告警规则配置

**第14周：日志系统**
- [ ] ELK Stack部署
- [ ] 日志收集配置
- [ ] 日志分析实践
- [ ] 日志告警配置

**第15周：运维自动化**
- [ ] 自动化脚本开发
- [ ] 定时任务配置
- [ ] 运维报告生成
- [ ] 整体项目总结

---

## 实践项目建议

### 🚀 推荐实践项目

#### 项目一：个人博客系统 (阶段二-三)
```bash
技术栈：
- 前端：React/Vue.js
- 后端：Node.js/Python Flask
- 数据库：MySQL/PostgreSQL
- 缓存：Redis
- 搜索：Elasticsearch

实践目标：
- 完整的Docker化部署
- Kubernetes集群部署
- 多环境配置管理
- 基础监控配置
```

#### 项目二：微服务电商平台 (阶段三-四)
```bash
技术栈：
- 用户服务：Java Spring Boot
- 商品服务：Python Django
- 订单服务：Node.js Express
- 消息队列：RabbitMQ/Kafka
- API网关：Nginx/Kong
- 数据库：MySQL + MongoDB

实践目标：
- 微服务架构设计
- 服务间通信配置
- 数据一致性处理
- 完整CI/CD流程
- 蓝绿部署实践
```

#### 项目三：实时数据处理平台 (阶段四-五)
```bash
技术栈：
- 数据采集：Fluentd/Filebeat
- 消息队列：Apache Kafka
- 流处理：Apache Flink
- 数据存储：ClickHouse
- 可视化：Grafana
- 监控：Prometheus

实践目标：
- 大数据处理流程
- 实时监控和告警
- 性能调优实践
- 故障恢复机制
- 运维自动化脚本
```

### 📊 项目评估标准

**基础要求 (60分):**
- [ ] 应用能正常运行
- [ ] 基本的Docker化部署
- [ ] 简单的K8s部署配置
- [ ] 基础的健康检查

**进阶要求 (80分):**
- [ ] 完整的CI/CD流程
- [ ] 多环境部署策略
- [ ] 基础监控和日志收集
- [ ] 自动化测试集成

**高级要求 (100分):**
- [ ] 蓝绿/金丝雀部署
- [ ] 完整的监控告警体系
- [ ] 自动化运维脚本
- [ ] 性能优化和调优
- [ ] 故障恢复机制

---

## 总结

这份《初级DevOps工程师完整学习指南》从基础环境搭建到高级运维自动化，提供了系统性的学习路径。通过5个阶段的渐进式学习，初级工程师能够：

### 🎯 掌握的核心技能

1. **基础设施管理**: Linux系统管理、网络配置、安全加固
2. **容器化技术**: Docker容器化、Kubernetes集群管理
3. **CI/CD流程**: Jenkins、GitHub Actions、GitLab CI等工具使用
4. **监控运维**: Prometheus、Grafana、ELK Stack等监控体系
5. **自动化脚本**: Bash、Python等自动化运维脚本开发

### 📈 职业发展路径

完成本指南学习后，可以继续向以下方向发展：

- **云原生架构师**: 深入学习Service Mesh、Serverless等技术
- **平台工程师**: 专注于开发者平台和工具链建设
- **SRE工程师**: 专注于可靠性工程和大规模系统运维
- **安全工程师**: 专注于DevSecOps和安全自动化

### 🎓 持续学习建议

1. **关注技术趋势**: 定期了解CNCF项目和云原生技术发展
2. **参与开源项目**: 贡献代码，学习最佳实践
3. **考取认证**: CKA、CKAD、AWS等相关认证
4. **实践项目**: 持续进行实际项目练习
5. **技术分享**: 写博客、做分享，巩固所学知识

记住，DevOps是一个持续学习和实践的领域，保持好奇心和学习热情是成功的关键！

---

*本指南持续更新中，欢迎提供反馈和建议*