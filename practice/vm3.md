# VM3: 监控服务器完整配置指南

**服务器信息:**
- 主机名: devops-monitor
- IP地址: 192.168.1.12
- 配置: 2核CPU, 4GB内存, 40GB硬盘
- 角色: Prometheus监控 + Grafana可视化 + 日志收集

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
      addresses: [192.168.1.12/24]
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
sudo apt install -y curl wget git vim htop tree unzip net-tools jq

# 设置主机名
sudo hostnamectl set-hostname devops-monitor

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
ping -c 4 devops-app
ping -c 4 8.8.8.8
```

## 第二步：安装Docker和Docker Compose

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

### 2.4 安装Docker Engine和Compose
```bash
# 更新包索引
sudo apt-get update

# 安装Docker CE和Compose插件
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
ssh ubuntu@192.168.1.12
```

### 2.5 验证Docker安装
```bash
# 测试Docker（无需sudo）
docker version
docker compose version

# 运行hello-world测试
docker run hello-world

# 验证Docker Compose
docker compose --version
```

## 第三步：创建监控目录结构

### 3.1 创建监控服务目录
```bash
# 创建监控根目录
mkdir -p ~/monitoring

# 创建各服务的配置目录
mkdir -p ~/monitoring/{prometheus,grafana,alertmanager,loki}
mkdir -p ~/monitoring/data/{prometheus,grafana,alertmanager,loki}
mkdir -p ~/monitoring/logs

# 设置目录权限
sudo chown -R ubuntu:ubuntu ~/monitoring

# 查看目录结构
tree ~/monitoring/
```

### 3.2 创建数据存储目录
```bash
# 创建持久化存储目录
sudo mkdir -p /opt/monitoring-data/{prometheus,grafana,alertmanager,loki}

# 设置权限（Grafana需要特定UID）
sudo chown -R 472:472 /opt/monitoring-data/grafana
sudo chown -R 65534:65534 /opt/monitoring-data/prometheus
sudo chown -R ubuntu:ubuntu /opt/monitoring-data/{alertmanager,loki}

# 验证权限设置
ls -la /opt/monitoring-data/
```

## 第四步：配置Prometheus

### 4.1 创建Prometheus配置
```bash
# 创建Prometheus主配置文件
cat > ~/monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'devops-demo'
    replica: 'prometheus-1'

rule_files:
  - "/etc/prometheus/rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Prometheus自身监控
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s

  # 本机Node Exporter
  - job_name: 'node_exporter_monitor'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 10s

  # CI/CD服务器Node Exporter
  - job_name: 'node_exporter_cicd'
    static_configs:
      - targets: ['192.168.1.10:9100']
    scrape_interval: 10s
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: 'devops-cicd'

  # 应用服务器Node Exporter
  - job_name: 'node_exporter_app'
    static_configs:
      - targets: ['192.168.1.11:9100']
    scrape_interval: 10s
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: 'devops-app'

  # 应用服务器Demo应用
  - job_name: 'demo_app'
    static_configs:
      - targets: ['192.168.1.11:3000']
    metrics_path: '/metrics'
    scrape_interval: 10s

  # Jenkins监控
  - job_name: 'jenkins'
    static_configs:
      - targets: ['192.168.1.10:8080']
    metrics_path: '/prometheus'
    scrape_interval: 30s

  # Nginx监控 (如果有nginx-prometheus-exporter)
  - job_name: 'nginx'
    static_configs:
      - targets: ['192.168.1.11:9113']
    scrape_interval: 10s

  # Docker监控
  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:9323']
    scrape_interval: 10s
EOF
```

### 4.2 创建Prometheus告警规则
```bash
# 创建告警规则目录
mkdir -p ~/monitoring/prometheus/rules

# 创建基础告警规则
cat > ~/monitoring/prometheus/rules/basic.yml << 'EOF'
groups:
  - name: basic
    rules:
    - alert: InstanceDown
      expr: up == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Instance {{ $labels.instance }} down"
        description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 1 minute."

    - alert: HighCPUUsage
      expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High CPU usage on {{ $labels.instance }}"
        description: "CPU usage is above 80% on {{ $labels.instance }} for more than 2 minutes."

    - alert: HighMemoryUsage
      expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 80
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage on {{ $labels.instance }}"
        description: "Memory usage is above 80% on {{ $labels.instance }} for more than 2 minutes."

    - alert: DiskSpaceUsage
      expr: (node_filesystem_size_bytes{fstype!="tmpfs"} - node_filesystem_free_bytes{fstype!="tmpfs"}) / node_filesystem_size_bytes{fstype!="tmpfs"} * 100 > 80
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High disk usage on {{ $labels.instance }}"
        description: "Disk usage is above 80% on {{ $labels.instance }} mount {{ $labels.mountpoint }} for more than 2 minutes."

  - name: application
    rules:
    - alert: ApplicationDown
      expr: up{job="demo_app"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Demo application is down"
        description: "The demo application has been down for more than 1 minute."

    - alert: HighResponseTime
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High response time for application"
        description: "95% of requests are taking more than 1 second for more than 2 minutes."
EOF
```

## 第五步：配置Grafana

### 5.1 创建Grafana配置
```bash
# 创建Grafana配置文件
cat > ~/monitoring/grafana/grafana.ini << 'EOF'
[server]
http_port = 3000
domain = devops-monitor

[security]
admin_user = admin
admin_password = grafana123

[users]
allow_sign_up = false
allow_org_create = false

[auth.anonymous]
enabled = false

[dashboards]
default_home_dashboard_path = /etc/grafana/provisioning/dashboards/home.json

[alerting]
enabled = true

[unified_alerting]
enabled = true

[log]
mode = console
level = info
EOF
```

### 5.2 创建Grafana数据源配置
```bash
# 创建数据源配置目录
mkdir -p ~/monitoring/grafana/provisioning/{datasources,dashboards}

# 创建数据源配置
cat > ~/monitoring/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1

deleteDatasources:
  - name: Prometheus
    orgId: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://prometheus:9090
    isDefault: true
    editable: true
    jsonData:
      timeInterval: "5s"
      queryTimeout: "60s"
EOF
```

### 5.3 创建仪表板配置
```bash
# 创建仪表板提供程序配置
cat > ~/monitoring/grafana/provisioning/dashboards/dashboards.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF
```

### 5.4 下载预设仪表板
```bash
# 创建仪表板文件目录
mkdir -p ~/monitoring/grafana/dashboards

# 下载Node Exporter仪表板
curl -L https://grafana.com/api/dashboards/1860/revisions/27/download > ~/monitoring/grafana/dashboards/node-exporter-full.json

# 下载Docker仪表板
curl -L https://grafana.com/api/dashboards/193/revisions/2/download > ~/monitoring/grafana/dashboards/docker-monitoring.json

# 创建自定义应用仪表板
cat > ~/monitoring/grafana/dashboards/demo-app.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Demo Application Monitoring",
    "tags": ["demo", "application"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "HTTP Requests per Second",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{route}}"
          }
        ]
      },
      {
        "id": 2,
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
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
```

## 第六步：配置Alertmanager

### 6.1 创建Alertmanager配置
```bash
# 创建Alertmanager配置文件
cat > ~/monitoring/alertmanager/alertmanager.yml << 'EOF'
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alertmanager@devops-monitor'
  smtp_auth_username: 'alertmanager'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname', 'cluster']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://localhost:5001/webhook'
        send_resolved: true

  - name: 'email'
    email_configs:
      - to: 'admin@example.com'
        subject: 'DevOps Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'cluster']
EOF
```

## 第七步：安装Node Exporter

### 7.1 下载和安装Node Exporter
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

### 7.2 创建Node Exporter服务
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

### 7.3 启动Node Exporter
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
```

## 第八步：创建Docker Compose配置

### 8.1 创建主Docker Compose文件
```bash
# 创建Docker Compose配置
cat > ~/monitoring/docker-compose.yml << 'EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.47.0
    container_name: prometheus
    hostname: prometheus
    user: "0"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/rules:/etc/prometheus/rules:ro
      - /opt/monitoring-data/prometheus:/prometheus
    networks:
      - monitoring
    depends_on:
      - alertmanager

  grafana:
    image: grafana/grafana:10.1.0
    container_name: grafana
    hostname: grafana
    user: "472"
    ports:
      - "3000:3000"
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=grafana123
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - ./grafana/grafana.ini:/etc/grafana/grafana.ini:ro
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - /opt/monitoring-data/grafana:/var/lib/grafana
    networks:
      - monitoring
    depends_on:
      - prometheus

  alertmanager:
    image: prom/alertmanager:v0.26.0
    container_name: alertmanager
    hostname: alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://192.168.1.12:9093'
      - '--cluster.listen-address=0.0.0.0:9094'
    restart: unless-stopped
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - /opt/monitoring-data/alertmanager:/alertmanager
    networks:
      - monitoring

  loki:
    image: grafana/loki:2.9.0
    container_name: loki
    hostname: loki
    ports:
      - "3100:3100"
    restart: unless-stopped
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - ./loki/loki.yml:/etc/loki/local-config.yaml:ro
      - /opt/monitoring-data/loki:/loki
    networks:
      - monitoring

  promtail:
    image: grafana/promtail:2.9.0
    container_name: promtail
    hostname: promtail
    restart: unless-stopped
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./loki/promtail.yml:/etc/promtail/config.yml:ro
    command: -config.file=/etc/promtail/config.yml
    networks:
      - monitoring
    depends_on:
      - loki

volumes:
  prometheus_data:
    external: false
  grafana_data:
    external: false
  alertmanager_data:
    external: false
  loki_data:
    external: false

networks:
  monitoring:
    driver: bridge
EOF
```

### 8.2 创建Loki配置
```bash
# 创建Loki配置文件
cat > ~/monitoring/loki/loki.yml << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://alertmanager:9093

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s

compactor:
  working_directory: /loki/boltdb-shipper-compactor
  shared_store: filesystem
EOF
```

### 8.3 创建Promtail配置
```bash
# 创建Promtail配置文件
cat > ~/monitoring/loki/promtail.yml << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*log

  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: 'container'
      - source_labels: ['__meta_docker_container_log_stream']
        target_label: 'stream'
    pipeline_stages:
      - docker: {}
EOF
```

## 第九步：启动监控服务栈

### 9.1 启动所有服务
```bash
# 进入监控目录
cd ~/monitoring

# 启动所有服务
docker compose up -d

# 查看服务状态
docker compose ps

# 查看服务日志
docker compose logs -f --tail=20
```

### 9.2 验证服务启动
```bash
# 检查Prometheus
curl http://localhost:9090/-/healthy
curl http://localhost:9090/api/v1/targets

# 检查Grafana
curl http://localhost:3000/api/health

# 检查Alertmanager
curl http://localhost:9093/-/healthy

# 检查Loki
curl http://localhost:3100/ready

# 检查所有端口监听
sudo netstat -tlnp | grep -E ':(3000|3100|9090|9093|9100)'
```

### 9.3 验证数据采集
```bash
# 测试Prometheus查询
curl 'http://localhost:9090/api/v1/query?query=up'

# 测试Node Exporter指标
curl 'http://localhost:9090/api/v1/query?query=node_load1'

# 检查应用服务器连接
curl 'http://localhost:9090/api/v1/query?query=up{job="node_exporter_app"}'
```

## 第十步：配置防火墙

### 10.1 配置UFW防火墙
```bash
# 启用UFW
sudo ufw --force enable

# 允许SSH访问
sudo ufw allow 22/tcp

# 允许Prometheus
sudo ufw allow 9090/tcp

# 允许Grafana
sudo ufw allow 3000/tcp

# 允许Alertmanager
sudo ufw allow 9093/tcp

# 允许Loki
sudo ufw allow 3100/tcp

# 允许Node Exporter
sudo ufw allow 9100/tcp

# 查看防火墙状态
sudo ufw status numbered
```

### 10.2 验证网络访问
```bash
# 测试外部访问
curl http://192.168.1.12:9090
curl http://192.168.1.12:3000
curl http://192.168.1.12:9093

# 测试与其他服务器的连通性
ping -c 4 192.168.1.10
ping -c 4 192.168.1.11
```

## 第十一步：创建监控脚本和自动化

### 11.1 创建服务健康检查脚本
```bash
# 创建监控脚本目录
sudo mkdir -p /opt/monitoring

# 创建服务健康检查脚本
sudo nano /opt/monitoring/monitor_health.sh
```

**监控健康检查脚本:**
```bash
#!/bin/bash

LOG_FILE="/var/log/monitoring_health.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "=== Monitoring Health Check $DATE ===" >> $LOG_FILE

# 检查Docker服务
if systemctl is-active --quiet docker; then
    echo "✓ Docker: Running" >> $LOG_FILE
else
    echo "✗ Docker: Stopped" >> $LOG_FILE
fi

# 检查监控容器
containers=("prometheus" "grafana" "alertmanager" "loki" "promtail")

for container in "${containers[@]}"; do
    if docker ps | grep -q $container; then
        echo "✓ Container $container: Running" >> $LOG_FILE
    else
        echo "✗ Container $container: Not running" >> $LOG_FILE
    fi
done

# 检查服务端点
endpoints=(
    "http://localhost:9090/-/healthy:Prometheus"
    "http://localhost:3000/api/health:Grafana"
    "http://localhost:9093/-/healthy:Alertmanager"
    "http://localhost:3100/ready:Loki"
    "http://localhost:9100/metrics:Node Exporter"
)

for endpoint in "${endpoints[@]}"; do
    url=$(echo $endpoint | cut -d: -f1)
    name=$(echo $endpoint | cut -d: -f2)
    
    if curl -s --max-time 5 $url > /dev/null; then
        echo "✓ $name: Accessible" >> $LOG_FILE
    else
        echo "✗ $name: Not accessible" >> $LOG_FILE
    fi
done

# 检查磁盘空间
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -lt 80 ]; then
    echo "✓ Disk Usage: ${DISK_USAGE}%" >> $LOG_FILE
else
    echo "⚠ Disk Usage: ${DISK_USAGE}% (High)" >> $LOG_FILE
fi

# 检查内存使用
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
sudo chmod +x /opt/monitoring/monitor_health.sh

# 运行健康检查测试
sudo /opt/monitoring/monitor_health.sh

# 查看健康检查结果
sudo tail -20 /var/log/monitoring_health.log
```

### 11.2 创建数据清理脚本
```bash
# 创建数据清理脚本
sudo nano /opt/monitoring/cleanup_data.sh
```

**数据清理脚本:**
```bash
#!/bin/bash

LOG_FILE="/var/log/monitoring_cleanup.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "=== Monitoring Data Cleanup $DATE ===" >> $LOG_FILE

# 清理旧的监控日志（保留7天）
find /var/log -name "*.log" -mtime +7 -exec rm {} \; 2>/dev/null
echo "Cleaned old log files" >> $LOG_FILE

# 清理Docker日志
docker system prune -f >> $LOG_FILE 2>&1
echo "Cleaned Docker system" >> $LOG_FILE

# 检查Prometheus数据大小
PROMETHEUS_SIZE=$(du -sh /opt/monitoring-data/prometheus 2>/dev/null | cut -f1)
echo "Prometheus data size: $PROMETHEUS_SIZE" >> $LOG_FILE

# 检查Grafana数据大小
GRAFANA_SIZE=$(du -sh /opt/monitoring-data/grafana 2>/dev/null | cut -f1)
echo "Grafana data size: $GRAFANA_SIZE" >> $LOG_FILE

# 检查Loki数据大小
LOKI_SIZE=$(du -sh /opt/monitoring-data/loki 2>/dev/null | cut -f1)
echo "Loki data size: $LOKI_SIZE" >> $LOG_FILE

echo "Cleanup completed at $(date)" >> $LOG_FILE
echo "" >> $LOG_FILE
```

```bash
# 设置脚本权限
sudo chmod +x /opt/monitoring/cleanup_data.sh

# 运行清理测试
sudo /opt/monitoring/cleanup_data.sh
```

### 11.3 设置定时任务
```bash
# 编辑crontab
crontab -e

# 添加以下定时任务
# 每5分钟检查服务健康状态
*/5 * * * * /opt/monitoring/monitor_health.sh

# 每天凌晨2点清理数据
0 2 * * * /opt/monitoring/cleanup_data.sh

# 每周日凌晨3点重启所有监控服务
0 3 * * 0 cd /home/ubuntu/monitoring && docker compose restart

# 验证crontab设置
crontab -l
```

## 第十二步：备份和恢复配置

### 12.1 创建备份脚本
```bash
# 创建备份目录
sudo mkdir -p /opt/backups

# 创建备份脚本
sudo nano /opt/backups/backup_monitoring.sh
```

**监控备份脚本:**
```bash
#!/bin/bash

BACKUP_DIR="/opt/backups"
DATE=$(date +%Y%m%d_%H%M%S)
MONITORING_DIR="/home/ubuntu/monitoring"

echo "Starting monitoring backup at $(date)"

# 创建今日备份目录
mkdir -p $BACKUP_DIR/$DATE

# 备份监控配置
tar -czf $BACKUP_DIR/$DATE/monitoring_config.tar.gz -C /home/ubuntu monitoring

# 备份Docker Compose文件
cp $MONITORING_DIR/docker-compose.yml $BACKUP_DIR/$DATE/

# 备份Prometheus配置和规则
cp -r $MONITORING_DIR/prometheus $BACKUP_DIR/$DATE/

# 备份Grafana配置
cp -r $MONITORING_DIR/grafana $BACKUP_DIR/$DATE/

# 备份Alertmanager配置
cp -r $MONITORING_DIR/alertmanager $BACKUP_DIR/$DATE/

# 备份系统配置
cp /etc/systemd/system/node_exporter.service $BACKUP_DIR/$DATE/
cp /etc/netplan/00-installer-config.yaml $BACKUP_DIR/$DATE/

# 导出Grafana仪表板
if curl -s http://localhost:3000/api/health > /dev/null; then
    mkdir -p $BACKUP_DIR/$DATE/grafana_dashboards
    # 这里可以添加Grafana API调用来导出仪表板
    echo "Grafana dashboards exported" > $BACKUP_DIR/$DATE/grafana_dashboards/README.txt
fi

# 创建系统信息快照
echo "=== System Info at $(date) ===" > $BACKUP_DIR/$DATE/system_info.txt
hostname >> $BACKUP_DIR/$DATE/system_info.txt
df -h >> $BACKUP_DIR/$DATE/system_info.txt
free -h >> $BACKUP_DIR/$DATE/system_info.txt
docker ps >> $BACKUP_DIR/$DATE/system_info.txt

# 删除30天前的备份
find $BACKUP_DIR -type d -name "*_*" -mtime +30 -exec rm -rf {} +

echo "Backup completed at $(date)"
echo "Backup saved to: $BACKUP_DIR/$DATE"
```

```bash
# 设置脚本权限
sudo chmod +x /opt/backups/backup_monitoring.sh

# 运行备份测试
sudo /opt/backups/backup_monitoring.sh

# 验证备份
ls -la /opt/backups/
```

### 12.2 创建系统信息脚本
```bash
# 创建系统信息脚本
sudo nano /opt/monitoring/system_status.sh
```

**系统状态脚本:**
```bash
#!/bin/bash

echo "=== DevOps Monitoring Server System Status ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"
echo ""

echo "=== System Services Status ==="
services=("docker" "node_exporter" "ssh")

for service in "${services[@]}"; do
    echo -n "$service: "
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
    else
        echo "✗ Stopped"
    fi
done

echo ""
echo "=== Docker Containers Status ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "=== Monitoring Endpoints Status ==="
endpoints=(
    "http://localhost:9090:Prometheus"
    "http://localhost:3000:Grafana"
    "http://localhost:9093:Alertmanager"
    "http://localhost:3100:Loki"
    "http://localhost:9100:Node Exporter"
)

for endpoint in "${endpoints[@]}"; do
    url=$(echo $endpoint | cut -d: -f1-3)
    name=$(echo $endpoint | cut -d: -f4)
    echo -n "$name: "
    
    if curl -s --max-time 5 $url > /dev/null; then
        echo "✓ Accessible"
    else
        echo "✗ Not accessible"
    fi
done

echo ""
echo "=== Port Status ==="
netstat -tlnp | grep -E ':(3000|3100|9090|9093|9100)' | awk '{print $4, $7}'

echo ""
echo "=== Resource Usage ==="
echo "Disk Usage:"
df -h /

echo ""
echo "Memory Usage:"
free -h

echo ""
echo "CPU Load:"
cat /proc/loadavg

echo ""
echo "=== Monitoring Data Sizes ==="
if [ -d "/opt/monitoring-data" ]; then
    du -sh /opt/monitoring-data/*
fi

echo ""
echo "=== Recent Alerts ==="
if curl -s http://localhost:9093/api/v1/alerts > /dev/null; then
    curl -s http://localhost:9093/api/v1/alerts | jq '.data[] | select(.status.state=="active") | {alertname: .labels.alertname, status: .status.state}' 2>/dev/null || echo "No active alerts or jq not available"
else
    echo "Alertmanager not accessible"
fi
```

```bash
# 设置脚本权限
sudo chmod +x /opt/monitoring/system_status.sh

# 运行系统状态检查
sudo /opt/monitoring/system_status.sh
```

## 第十三步：Web界面访问和配置

### 13.1 访问Prometheus
```bash
# Prometheus Web界面
# URL: http://192.168.1.12:9090

# 验证targets状态
curl 'http://localhost:9090/api/v1/targets' | jq '.data.activeTargets[] | {job: .labels.job, health: .health, lastScrape: .lastScrape}'

# 测试查询
curl 'http://localhost:9090/api/v1/query?query=up' | jq .
```

### 13.2 访问Grafana
```bash
# Grafana Web界面
# URL: http://192.168.1.12:3000
# 用户名: admin
# 密码: grafana123

echo "Grafana登录信息："
echo "URL: http://192.168.1.12:3000"
echo "用户名: admin"
echo "密码: grafana123"
```

### 13.3 访问Alertmanager
```bash
# Alertmanager Web界面
# URL: http://192.168.1.12:9093

echo "Alertmanager访问地址："
echo "URL: http://192.168.1.12:9093"
```

## 完成验证清单

**系统基础验证:**
- [ ] 网络配置正确，可以ping通其他VM
- [ ] SSH服务正常运行
- [ ] 防火墙规则配置正确
- [ ] 主机名和hosts配置正确

**Docker环境验证:**
- [ ] Docker服务正常运行
- [ ] Docker Compose可以正常使用
- [ ] 容器网络通信正常

**监控服务验证:**
- [ ] Prometheus正常启动并可以访问
- [ ] Grafana正常启动并可以访问
- [ ] Alertmanager正常启动并可以访问
- [ ] Loki日志系统正常运行
- [ ] Node Exporter正常运行并暴露指标

**数据收集验证:**
- [ ] 可以从CI/CD服务器收集指标
- [ ] 可以从应用服务器收集指标
- [ ] 本机Node Exporter指标正常
- [ ] 应用指标正常收集
- [ ] 日志收集功能正常

**Web界面验证:**
- [ ] 可以访问 http://192.168.1.12:9090 (Prometheus)
- [ ] 可以访问 http://192.168.1.12:3000 (Grafana)
- [ ] 可以访问 http://192.168.1.12:9093 (Alertmanager)
- [ ] Grafana仪表板正常显示数据

**告警功能验证:**
- [ ] 告警规则正确加载
- [ ] Alertmanager与Prometheus正确集成
- [ ] 可以发送测试告警

**运维功能验证:**
- [ ] 健康检查脚本正常工作
- [ ] 备份脚本可以正常执行
- [ ] 定时任务配置正确
- [ ] 日志轮转配置正确

## 故障排除指南

### Docker容器问题
```bash
# 检查容器状态
docker compose ps
docker compose logs <service_name>

# 重启特定服务
docker compose restart <service_name>

# 重建服务
docker compose up -d --force-recreate <service_name>

# 检查容器内部
docker exec -it <container_name> /bin/sh
```

### Prometheus问题
```bash
# 检查Prometheus配置
curl http://localhost:9090/-/healthy
curl http://localhost:9090/api/v1/status/config

# 重载配置
curl -X POST http://localhost:9090/-/reload

# 检查targets状态
curl http://localhost:9090/api/v1/targets
```

### Grafana问题
```bash
# 检查Grafana日志
docker logs grafana

# 重置Grafana密码
docker exec -it grafana grafana-cli admin reset-admin-password grafana123

# 检查数据源连接
curl http://localhost:3000/api/datasources
```

### 网络连接问题
```bash
# 检查端口监听
sudo netstat -tlnp | grep -E ':(3000|3100|9090|9093|9100)'

# 检查防火墙
sudo ufw status

# 测试服务连通性
curl -v http://192.168.1.10:9100/metrics
curl -v http://192.168.1.11:9100/metrics
curl -v http://192.168.1.11:3000/metrics
```

### 性能问题
```bash
# 检查系统资源
htop
df -h
free -h

# 检查容器资源使用
docker stats

# 清理Docker数据
docker system prune -f
```

VM3 监控服务器配置完成！