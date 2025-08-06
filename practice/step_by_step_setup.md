# DevOps 3台虚拟机完整Step-by-Step配置指南

## 第一阶段：虚拟机准备

### Step 1: 虚拟机创建
1. **下载Ubuntu 22.04 LTS ISO镜像**
   ```bash
   # 下载地址
   https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso
   ```

2. **创建3台虚拟机（使用VMware/VirtualBox）**
   - VM1: devops-cicd (2核CPU, 8GB内存, 60GB硬盘)
   - VM2: devops-app (2核CPU, 4GB内存, 40GB硬盘) 
   - VM3: devops-monitor (2核CPU, 4GB内存, 40GB硬盘)

3. **安装Ubuntu系统**
   - 用户名: ubuntu
   - 密码: ubuntu123 (或自定义)
   - 选择"Install OpenSSH server"

### Step 2: 网络配置
1. **设置静态IP（每台虚拟机）**
   ```bash
   sudo nano /etc/netplan/00-installer-config.yaml
   ```
   
   **VM1 (192.168.1.10):**
   ```yaml
   network:
     version: 2
     ethernets:
       eth0:
         dhcp4: false
         addresses: [192.168.1.10/24]
         gateway4: 192.168.1.1
         nameservers:
           addresses: [8.8.8.8, 8.8.4.4]
   ```
   
   **VM2 (192.168.1.11):**
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
   
   **VM3 (192.168.1.12):**
   ```yaml
   network:
     version: 2
     ethernets:
       eth0:
         dhcp4: false
         addresses: [192.168.1.12/24]
         gateway4: 192.168.1.1
         nameservers:
           addresses: [8.8.8.8, 8.8.4.4]
   ```

2. **应用网络配置**
   ```bash
   sudo netplan apply
   sudo reboot
   ```

### Step 3: 基础环境配置（所有虚拟机）
1. **更新系统**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **安装基础工具**
   ```bash
   sudo apt install -y curl wget git vim htop tree unzip
   ```

3. **设置主机名**
   ```bash
   # VM1
   sudo hostnamectl set-hostname devops-cicd
   
   # VM2
   sudo hostnamectl set-hostname devops-app
   
   # VM3
   sudo hostnamectl set-hostname devops-monitor
   ```

4. **配置hosts文件（所有虚拟机）**
   ```bash
   sudo nano /etc/hosts
   
   # 添加以下内容
   192.168.1.10    devops-cicd
   192.168.1.11    devops-app
   192.168.1.12    devops-monitor
   ```

5. **测试网络连通性**
   ```bash
   ping devops-cicd
   ping devops-app
   ping devops-monitor
   ```

## 第二阶段：VM1 CI/CD服务器配置

### Step 4: 安装Docker
```bash
# 卸载旧版本
sudo apt-get remove docker docker-engine docker.io containerd runc

# 安装依赖
sudo apt-get install ca-certificates curl gnupg lsb-release

# 添加Docker官方GPG密钥
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 添加Docker仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker

# 添加用户到docker组
sudo usermod -aG docker ubuntu

# 重新登录生效
exit
# 重新SSH登录
```

### Step 5: 安装Java和Jenkins
```bash
# 安装Java 11
sudo apt install -y openjdk-11-jdk

# 验证Java安装
java -version

# 添加Jenkins仓库密钥
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | sudo tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null

# 添加Jenkins仓库
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/ | sudo tee /etc/apt/sources.list.d/jenkins.list > /dev/null

# 更新包列表并安装Jenkins
sudo apt-get update
sudo apt-get install -y jenkins

# 启动Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins

# 检查Jenkins状态
sudo systemctl status jenkins

# 获取初始密码
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

### Step 6: 安装GitLab CE
```bash
# 安装依赖
sudo apt-get install -y ca-certificates curl openssh-server postfix

# 下载GitLab安装脚本
curl https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash

# 安装GitLab CE
sudo EXTERNAL_URL="http://192.168.1.10" apt-get install gitlab-ce

# 配置GitLab
sudo gitlab-ctl reconfigure

# 重置root密码
sudo gitlab-rake "gitlab:password:reset[root]"
# 输入新密码: gitlab123
```

### Step 7: 配置Nginx反向代理
```bash
# 安装Nginx
sudo apt install -y nginx

# 备份默认配置
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak

# 创建新的Nginx配置
sudo nano /etc/nginx/sites-available/default
```

**Nginx配置内容:**
```nginx
server {
    listen 80 default_server;
    server_name devops-cicd 192.168.1.10;

    # GitLab
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Jenkins
    location /jenkins {
        proxy_pass http://127.0.0.1:8080/jenkins;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# 测试Nginx配置
sudo nginx -t

# 重启Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

### Step 8: 配置防火墙
```bash
# 启用UFW
sudo ufw --force enable

# 允许SSH
sudo ufw allow 22/tcp

# 允许HTTP
sudo ufw allow 80/tcp

# 允许Jenkins
sudo ufw allow 8080/tcp

# 查看防火墙状态
sudo ufw status
```

## 第三阶段：VM2 应用服务器配置

### Step 9: 安装Docker（VM2）
```bash
# 重复Step 4的Docker安装步骤
# 卸载旧版本
sudo apt-get remove docker docker-engine docker.io containerd runc

# 安装依赖
sudo apt-get install ca-certificates curl gnupg lsb-release

# 添加Docker官方GPG密钥
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 添加Docker仓库
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 启动Docker服务
sudo systemctl start docker
sudo systemctl enable docker

# 添加用户到docker组
sudo usermod -aG docker ubuntu
```

### Step 10: 安装Node.js和Nginx
```bash
# 安装Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 验证安装
node --version
npm --version

# 安装Nginx
sudo apt install -y nginx

# 安装PM2进程管理器
sudo npm install -g pm2

# 创建应用目录
sudo mkdir -p /var/www/html
sudo chown -R ubuntu:ubuntu /var/www/html
```

### Step 11: 创建示例应用
```bash
# 创建示例Node.js应用
cd /var/www/html
mkdir demo-app
cd demo-app

# 创建package.json
cat > package.json << 'EOF'
{
  "name": "demo-app",
  "version": "1.0.0",
  "description": "DevOps Demo Application",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "test": "echo \"Test passed\" && exit 0"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
EOF

# 创建应用文件
cat > app.js << 'EOF'
const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.json({
    message: 'DevOps Demo Application',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    hostname: require('os').hostname()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.listen(port, () => {
  console.log(`Demo app listening on port ${port}`);
});
EOF

# 安装依赖
npm install
```

### Step 12: 配置Nginx反向代理（VM2）
```bash
# 配置Nginx
sudo nano /etc/nginx/sites-available/default
```

**Nginx配置:**
```nginx
server {
    listen 80 default_server;
    server_name devops-app 192.168.1.11;

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
    }
}
```

```bash
# 测试并重启Nginx
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

# 使用PM2启动应用
cd /var/www/html/demo-app
pm2 start app.js --name "demo-app"
pm2 save
pm2 startup
```

### Step 13: 安装Node Exporter（VM2）
```bash
# 下载Node Exporter
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz

# 解压并安装
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

# 创建用户
sudo useradd --no-create-home --shell /bin/false node_exporter

# 创建systemd服务
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
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
# 启动Node Exporter
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter

# 配置防火墙
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 9100/tcp
sudo ufw --force enable
```

## 第四阶段：VM3 监控服务器配置

### Step 14: 安装Docker（VM3）
```bash
# 重复Docker安装步骤（同Step 4）
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get install ca-certificates curl gnupg lsb-release

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ubuntu
```

### Step 15: 创建监控配置
```bash
# 创建监控目录
mkdir -p ~/monitoring/{prometheus,grafana}
cd ~/monitoring
```

**创建Prometheus配置:**
```bash
cat > prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node_exporter_app'
    static_configs:
      - targets: ['192.168.1.11:9100']

  - job_name: 'node_exporter_cicd'
    static_configs:
      - targets: ['192.168.1.10:9100']

  - job_name: 'node_exporter_monitor'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'demo_app'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['192.168.1.11:3000']
EOF
```

**创建Docker Compose文件:**
```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.47.0
    container_name: prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:10.1.0
    container_name: grafana
    ports:
      - "3000:3000"
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=grafana123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:v1.6.1
    container_name: node_exporter
    restart: unless-stopped
    ports:
      - "9100:9100"
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    networks:
      - monitoring

volumes:
  prometheus_data: {}
  grafana_data: {}

networks:
  monitoring:
    driver: bridge
EOF
```

### Step 16: 启动监控服务
```bash
# 启动所有服务
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f
```

### Step 17: 配置防火墙（VM3）
```bash
sudo ufw allow 22/tcp
sudo ufw allow 9090/tcp  # Prometheus
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9100/tcp  # Node Exporter
sudo ufw --force enable
```

## 第五阶段：网络连通性和SSH配置

### Step 18: 配置SSH密钥认证
```bash
# 在VM1生成SSH密钥对
ssh-keygen -t rsa -b 4096 -C "jenkins@devops-cicd"
# 按Enter使用默认路径，设置密码或直接回车

# 复制公钥到其他服务器
ssh-copy-id ubuntu@192.168.1.11  # 应用服务器
ssh-copy-id ubuntu@192.168.1.12  # 监控服务器

# 测试SSH连接
ssh ubuntu@192.168.1.11 'hostname'
ssh ubuntu@192.168.1.12 'hostname'
```

### Step 19: 在所有服务器安装Node Exporter
**VM1 (CI/CD服务器):**
```bash
# 下载并安装Node Exporter
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

sudo useradd --no-create-home --shell /bin/false node_exporter

# 创建systemd服务
sudo nano /etc/systemd/system/node_exporter.service
```

**服务配置文件:**
```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl enable node_exporter

# 开放端口
sudo ufw allow 9100/tcp
```

## 第六阶段：服务集成和测试

### Step 20: 配置Jenkins
1. **访问Jenkins Web界面**
   ```
   http://192.168.1.10:8080
   ```

2. **初始设置**
   - 输入初始密码（之前获取的）
   - 选择"Install suggested plugins"
   - 创建管理员用户
   - 完成初始设置

3. **安装必要插件**
   - 进入 "Manage Jenkins" → "Manage Plugins"
   - 安装以下插件：
     - Git plugin
     - SSH Agent plugin
     - Pipeline plugin
     - Docker plugin

4. **配置SSH凭据**
   - "Manage Jenkins" → "Manage Credentials"
   - 添加SSH private key凭据（使用之前生成的私钥）

### Step 21: 创建示例项目和Pipeline
1. **在GitLab创建项目**
   - 访问 http://192.168.1.10
   - 登录 root / gitlab123
   - 创建新项目 "demo-app"

2. **推送代码到GitLab**
   ```bash
   # 在VM2的应用目录
   cd /var/www/html/demo-app
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin http://192.168.1.10/root/demo-app.git
   git push -u origin main
   ```

3. **在Jenkins创建Pipeline任务**
   ```groovy
   pipeline {
       agent any
       
       stages {
           stage('Checkout') {
               steps {
                   git branch: 'main', 
                       url: 'http://192.168.1.10/root/demo-app.git'
               }
           }
           
           stage('Install Dependencies') {
               steps {
                   sh 'npm install'
               }
           }
           
           stage('Test') {
               steps {
                   sh 'npm test'
               }
           }
           
           stage('Deploy') {
               steps {
                   script {
                       sh '''
                           scp -r ./* ubuntu@192.168.1.11:/var/www/html/demo-app/
                           ssh ubuntu@192.168.1.11 "cd /var/www/html/demo-app && npm install && pm2 restart demo-app"
                       '''
                   }
               }
           }
       }
       
       post {
           always {
               cleanWs()
           }
       }
   }
   ```

### Step 22: 配置Grafana仪表板
1. **访问Grafana**
   ```
   http://192.168.1.12:3000
   用户名: admin
   密码: grafana123
   ```

2. **添加Prometheus数据源**
   - Configuration → Data Sources
   - 添加Prometheus数据源: http://prometheus:9090

3. **导入Node Exporter仪表板**
   - Import dashboard ID: 1860
   - 选择Prometheus数据源

### Step 23: 验证整体系统
1. **测试应用访问**
   ```bash
   curl http://192.168.1.11
   curl http://192.168.1.11/health
   ```

2. **测试监控数据**
   ```bash
   curl http://192.168.1.12:9090/api/v1/query?query=up
   ```

3. **测试CI/CD流程**
   - 修改应用代码
   - 提交到GitLab
   - 触发Jenkins构建
   - 验证自动部署

### Step 24: 系统监控验证
1. **检查所有服务状态**
   ```bash
   # VM1
   sudo systemctl status jenkins
   sudo systemctl status gitlab-runsvdir
   sudo systemctl status node_exporter
   
   # VM2
   pm2 status
   sudo systemctl status nginx
   sudo systemctl status node_exporter
   
   # VM3
   docker compose ps
   ```

2. **验证监控指标收集**
   - 访问Prometheus: http://192.168.1.12:9090
   - 查看所有targets状态为UP
   - 访问Grafana查看系统监控图表

## 故障排除指南

### 常见问题解决

1. **SSH连接失败**
   ```bash
   # 检查SSH服务
   sudo systemctl status ssh
   
   # 重新生成SSH密钥
   ssh-keygen -f ~/.ssh/known_hosts -R 192.168.1.11
   ```

2. **Docker服务启动失败**
   ```bash
   # 检查Docker状态
   sudo systemctl status docker
   
   # 重启Docker
   sudo systemctl restart docker
   ```

3. **Jenkins无法访问**
   ```bash
   # 检查Jenkins日志
   sudo journalctl -u jenkins -f
   
   # 检查端口占用
   sudo netstat -tlnp | grep 8080
   ```

4. **Prometheus无法采集数据**
   ```bash
   # 检查网络连通性
   telnet 192.168.1.11 9100
   
   # 检查防火墙设置
   sudo ufw status
   ```

## 完成验证清单

- [ ] 所有虚拟机可以互相ping通
- [ ] SSH密钥认证正常工作
- [ ] GitLab可以正常访问并创建项目
- [ ] Jenkins可以正常访问并执行构建
- [ ] 应用服务器可以正常访问demo应用
- [ ] Prometheus可以采集到所有节点数据
- [ ] Grafana可以正常显示监控图表
- [ ] CI/CD流水线可以完整执行
- [ ] 监控告警功能正常

完成所有步骤后，你将拥有一个完整的DevOps环境，包含版本控制、持续集成/部署和系统监控功能。