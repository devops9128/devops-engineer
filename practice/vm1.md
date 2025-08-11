# VM1: CI/CD服务器完整配置指南

**服务器信息:**
- 主机名: devops-cicd
- IP地址: 192.168.1.10
- 配置: 2核CPU, 8GB内存, 60GB硬盘
- 角色: Git仓库 + Jenkins CI/CD + 反向代理

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
      addresses: [192.168.184.140/24]
      gateway4: 192.168.184.1
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
sudo apt install -y curl wget git vim htop tree unzip net-tools

# 设置主机名
sudo hostnamectl set-hostname devops-cicd

# 配置hosts文件
sudo nano /etc/hosts
```

**添加hosts条目:**
```bash
127.0.0.1       localhost
192.168.184.140    devops-cicd
192.168.184.141    devops-app
192.168.184.142    devops-monitor

# 保存退出 (Ctrl+X, Y, Enter)
```

```bash
# 验证主机名设置
hostname
hostnamectl status

# 测试网络连通性
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
ssh ubuntu@192.168.1.10
```

### 2.5 验证Docker安装
```bash
# 测试Docker（无需sudo）
docker version
docker info

# 运行hello-world测试
docker run hello-world
```

## 第三步：安装Java和Jenkins

### 3.1 安装Java 17 or above
```bash
# 安装OpenJDK 17
sudo apt install openjdk-17-jdk -y

# 验证Java安装
java -version
javac -version

# 查看Java安装路径
update-java-alternatives --list
```

### 3.2 安装Jenkins (注意端口分配)
```bash
# 添加Jenkins仓库密钥
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | sudo tee \
    /usr/share/keyrings/jenkins-keyring.asc > /dev/null

# 添加Jenkins仓库
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
    https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
    /etc/apt/sources.list.d/jenkins.list > /dev/null

# 更新包列表
sudo apt-get update

# 安装Jenkins
sudo apt-get install -y jenkins
```

### 3.3 启动和配置Jenkins(需要java17或以上的版本，不支持java11)
```bash
# 启动Jenkins服务
sudo systemctl start jenkins
sudo systemctl enable jenkins

# 检查Jenkins状态
sudo systemctl status jenkins

# 查看Jenkins日志（如有问题）
sudo journalctl -u jenkins -f

# 获取Jenkins初始密码
sudo cat /var/lib/jenkins/secrets/initialAdminPassword

# 记录这个密码，稍后Web界面需要使用
```

### 3.4 修改Jenkins端口配置
```bash
# 编辑Jenkins配置文件
sudo nano /etc/default/jenkins

# 找到HTTP_PORT行，确保是8080
# HTTP_PORT=8080

# 为支持子路径访问，添加Jenkins参数
# 在JENKINS_ARGS行添加 --prefix=/jenkins
# JENKINS_ARGS="--webroot=/var/cache/$NAME/war --httpPort=$HTTP_PORT --prefix=/jenkins"

# 重启Jenkins
sudo systemctl restart jenkins

# 验证Jenkins端口
sudo netstat -tlnp | grep :8080
```

## 第四步：安装GitLab CE

### 4.1 安装GitLab依赖
```bash
# 安装必要的依赖包
sudo apt-get install -y ca-certificates curl openssh-server postfix

# 在postfix配置中选择 "Internet Site"
# 输入系统邮件名称: devops-cicd
```

### 4.2 添加GitLab仓库
```bash
# 下载GitLab安装脚本
curl https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash

# 验证仓库添加成功
sudo apt update
```

### 4.3 安装GitLab CE 
```bash
# 安装GitLab CE（指定外部URL和端口）
sudo EXTERNAL_URL="http://192.168.184.140:8090" apt-get install gitlab-ce

# 等待安装完成（可能需要5-10分钟）
```

### 4.4 配置GitLab
```bash
# 如果需要修改端口配置，编辑GitLab配置文件
sudo nano /etc/gitlab/gitlab.rb

# 确保external_url已经配置在 /etc/gitlab/gitlab.rb
# external_url 'http://192.168.184.140:8090'

# 重新配置GitLab
sudo gitlab-ctl reconfigure

# 检查GitLab服务状态
sudo gitlab-ctl status

# 重置root用户密码
sudo gitlab-rake "gitlab:password:reset[root]"
# 输入新密码: Gitlab@123!
# 再次输入确认: Gitlab@123!
```

### 4.5 验证GitLab安装 (注意端口分配)
```bash
# 检查GitLab服务端口
sudo netstat -tlnp | grep :8090

# 测试GitLab访问
curl -I http://localhost:8090
```

## 第五步：安装和配置Nginx

### 5.1 安装Nginx
```bash
# 安装Nginx
sudo apt install -y nginx

# 启动Nginx服务
sudo systemctl start nginx
sudo systemctl enable nginx

# 检查Nginx状态
sudo systemctl status nginx
sudo gitlab-ctl stop nginx # gitlab可能造成nginx无法正常运行
sudo systemctl start nginx
sudo systemctl enable nginx
sudo systemctl status nginx
sudo gitlab-ctl start nginx
```

### 5.2 备份默认配置
```bash
# 备份原始配置
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup

# 查看当前配置
sudo cat /etc/nginx/sites-available/default
```

### 5.3 配置反向代理
```bash
# 编辑Nginx配置
sudo nano /etc/nginx/sites-available/default
```

**Nginx配置内容（完全替换）:**
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name devops-cicd 192.168.1.10;
    
    # GitLab - 主站点（代理到8090端口）
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
        proxy_buffering off;
        
        # WebSocket support for GitLab
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Jenkins - 子路径访问（代理到8080端口）
    location ^~ /jenkins/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Jenkins需要的特殊头
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header X-Forwarded-Prefix /jenkins;
        proxy_redirect default;
        proxy_buffering off;
        
        # Jenkins WebSocket支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 5.4 应用Nginx配置
```bash
# 测试Nginx配置语法
sudo nginx -t

# 如果测试通过，重启Nginx
sudo systemctl restart nginx

# 检查Nginx状态
sudo systemctl status nginx

# 查看Nginx错误日志（如有问题）
sudo tail -f /var/log/nginx/error.log
```

## 第六步：安装Node Exporter

### 6.1 下载Node Exporter
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
```

### 6.2 创建Node Exporter用户
```bash
# 创建系统用户
sudo useradd --no-create-home --shell /bin/false node_exporter

# 设置可执行文件权限
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter
```

### 6.3 创建Systemd服务
```bash
# 创建服务文件
sudo nano /etc/systemd/system/node_exporter.service
```

**服务文件内容:**
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

### 6.4 启动Node Exporter
```bash
# 重新加载systemd
sudo systemctl daemon-reload

# 启动Node Exporter
sudo systemctl start node_exporter
sudo systemctl enable node_exporter

# 检查服务状态
sudo systemctl status node_exporter

# 测试Node Exporter
curl http://localhost:9100/metrics | head -20
```

## 第七步：配置防火墙

### 7.1 配置UFW防火墙
```bash
# 启用UFW
sudo ufw --force enable

# 允许SSH访问
sudo ufw allow 22/tcp

# 允许HTTP访问（GitLab）
sudo ufw allow 80/tcp

# 允许Jenkins直接访问
sudo ufw allow 8080/tcp

# 允许GitLab内部端口
sudo ufw allow 8090/tcp

# 允许Node Exporter
sudo ufw allow 9100/tcp

# 查看防火墙状态
sudo ufw status numbered

# 查看详细状态
sudo ufw status verbose
```

## 第八步：生成SSH密钥

### 8.1 生成SSH密钥对
```bash
# 生成RSA密钥对
ssh-keygen -t rsa -b 4096 -C "jenkins@devops-cicd"

# 按提示操作：
# Enter file in which to save the key: 直接回车（使用默认路径）
# Enter passphrase: 直接回车（不设置密码）
# Enter same passphrase again: 直接回车

# 查看生成的密钥
ls -la ~/.ssh/
cat ~/.ssh/id_rsa.pub
```

### 8.2 配置SSH客户端
```bash
# 创建SSH配置文件
nano ~/.ssh/config
```

**SSH配置内容:**
```
Host devops-app
    HostName 192.168.184.141
    User ubuntu
    IdentityFile ~/.ssh/id_rsa

Host devops-monitor
    HostName 192.168.184.142
    User ubuntu
    IdentityFile ~/.ssh/id_rsa
```

```bash
# 设置配置文件权限
chmod 600 ~/.ssh/config
```

## 第九步：系统服务验证

### 9.1 检查所有服务状态
```bash
# 检查系统服务
sudo systemctl status jenkins
sudo systemctl status gitlab-runsvdir
sudo systemctl status nginx
sudo systemctl status node_exporter
sudo systemctl status docker

# 检查端口监听
sudo netstat -tlnp | grep -E ':(80|8080|8090|9100)'
```

### 9.2 验证Docker功能
```bash
# 运行测试容器
docker run --rm hello-world

# 检查Docker信息
docker info
docker version
```

### 9.3 测试网络连通性
```bash
# 测试外网访问
ping -c 4 google.com

# 测试DNS解析
nslookup google.com

# 检查防火墙状态
sudo ufw status
```

## 第十步：Web界面初始化

### 10.1 Jenkins初始化
```bash
# 获取Jenkins初始密码
sudo cat /var/lib/jenkins/secrets/initialAdminPassword

# 记录密码，然后访问: http://192.168.184.140/jenkins/ 或 http://192.168.184.140:8080
```

**Jenkins Web初始化步骤:**
1. 输入初始密码
2. 选择"Install suggested plugins"
3. 等待插件安装完成
4. 创建管理员用户：
   - 用户名: admin
   - 密码: jenkins123
   - 全名: Jenkins Admin
   - 邮箱: admin@devops-cicd
5. 确认Jenkins URL: http://192.168.1.10/jenkins/ （如果通过子路径访问）或 http://192.168.1.10:8080/ （直接访问）
6. 完成初始化

### 10.2 GitLab初始化
```bash
# 访问GitLab: http://192.168.1.10
# 用户名: root
# 密码: gitlab123 (之前设置的)
```

**GitLab Web初始化步骤:**
1. 登录root账户
2. 设置管理员邮箱
3. 创建第一个项目或组织

## 第十一步：配置文件备份

### 11.1 创建配置备份目录
```bash
# 创建备份目录
sudo mkdir -p /opt/backups/configs

# 备份重要配置文件
sudo cp /etc/nginx/sites-available/default /opt/backups/configs/nginx-default
sudo cp /etc/systemd/system/node_exporter.service /opt/backups/configs/
sudo cp /etc/netplan/00-installer-config.yaml /opt/backups/configs/
sudo cp /etc/hosts /opt/backups/configs/
```

### 11.2 创建服务启动脚本
```bash
# 创建服务启动检查脚本
sudo nano /opt/check_services.sh
```

**服务检查脚本内容:**
```bash
#!/bin/bash

echo "=== DevOps CI/CD Server Service Status ==="
echo "Date: $(date)"
echo ""

services=("docker" "jenkins" "gitlab-runsvdir" "nginx" "node_exporter")

for service in "${services[@]}"; do
    echo -n "$service: "
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
    else
        echo "✗ Stopped"
    fi
done

echo ""
echo "=== Port Status ==="
netstat -tlnp | grep -E ':(80|8080|8090|9100)' | awk '{print $4, $7}'

echo ""
echo "=== Disk Usage ==="
df -h /

echo ""
echo "=== Memory Usage ==="
free -h
```

```bash
# 设置脚本权限
sudo chmod +x /opt/check_services.sh

# 运行检查脚本
sudo /opt/check_services.sh
```

## 故障排除指南

### Jenkins访问问题
```bash
# 检查Jenkins日志
sudo journalctl -u jenkins -f

# 重启Jenkins
sudo systemctl restart jenkins

# 检查Java版本
java -version
```

### GitLab访问问题
```bash
# 检查GitLab状态
sudo gitlab-ctl status

# 重启GitLab
sudo gitlab-ctl restart

# 查看GitLab日志
sudo gitlab-ctl tail
```

### Nginx问题
```bash
# 测试配置
sudo nginx -t

# 查看错误日志
sudo tail -f /var/log/nginx/error.log

# 重启Nginx
sudo systemctl restart nginx
```

### 网络问题
```bash
# 检查网络配置
ip addr show
ip route show

# 测试DNS
nslookup google.com
```

## 端口分配总结

**最终端口分配方案:**
- **HTTP访问 (80)**: Nginx反向代理前端
- **GitLab内部 (8090)**: GitLab CE服务端口
- **Jenkins (8080)**: Jenkins CI/CD服务端口  
- **Node Exporter (9100)**: 系统指标监控
- **SSH (22)**: 远程访问端口

**访问方式:**
- GitLab: `http://192.168.1.10/` (通过Nginx)
- Jenkins: `http://192.168.1.10/jenkins/` (通过Nginx) 或 `http://192.168.1.10:8080` (直接)
- 监控: `http://192.168.1.10:9100/metrics`

**端口冲突解决方案:**
1. GitLab从默认8080端口改为8090端口
2. Jenkins保持8080端口不变
3. Nginx配置正确的反向代理路径
4. 防火墙规则包含所有必要端口
5. Jenkins配置子路径支持(/jenkins)

**重要配置文件:**
- GitLab配置: `/etc/gitlab/gitlab.rb` 
- Jenkins配置: `/etc/default/jenkins`
- Nginx配置: `/etc/nginx/sites-available/default`
- 防火墙规则: `sudo ufw status`

VM1 CI/CD服务器配置完成！