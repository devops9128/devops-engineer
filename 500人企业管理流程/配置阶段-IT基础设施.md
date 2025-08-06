# 配置阶段 - IT基础设施管理

## 阶段概述
配置阶段是将采购的硬件设备和软件产品按照设计方案进行系统化配置的关键阶段，确保所有组件能够协同工作并满足业务需求。

## 1. 硬件配置管理

### 1.1 服务器配置

#### 物理服务器基础配置
```bash
服务器标准化配置流程：

# 1. BIOS/UEFI配置
- 启用虚拟化支持（Intel VT-x/AMD-V）
- 配置内存设置（启用ECC、内存镜像）
- 设置启动顺序（PXE、USB、HDD）
- 配置RAID控制器（RAID1用于系统盘，RAID5用于数据盘）
- 启用远程管理（iDRAC/iLO）

# 2. 网络接口配置
eth0: 管理网络 (192.168.1.0/24)
eth1: 业务网络 (192.168.10.0/24)
eth2: 存储网络 (192.168.50.0/24)
eth3: 备用网络 (预留)

# 3. 硬件监控配置
- 温度传感器监控
- 风扇转速监控
- 电源状态监控
- 内存错误监控
```

#### 虚拟化主机配置
```yaml
# VMware ESXi 8.0 配置标准
ESXi主机配置:
  主机名: esx-host-[01-03].company.local
  管理IP: 192.168.1.101-103
  DNS服务器: 192.168.1.10, 192.168.1.11
  NTP服务器: pool.ntp.org, time.windows.com
  
  网络配置:
    管理网络:
      vSwitch: vSwitch0
      端口组: Management Network
      VLAN: 1
      网卡: vmnic0, vmnic1 (冗余)
    
    虚拟机网络:
      vSwitch: vSwitch1
      端口组: VM Network
      VLAN: 100
      网卡: vmnic2, vmnic3 (链路聚合)
    
    存储网络:
      vSwitch: vSwitch2
      端口组: iSCSI Network
      VLAN: 200
      网卡: vmnic4, vmnic5 (专用)

  存储配置:
    本地存储: 用于系统和临时文件
    共享存储: SAN存储，用于虚拟机
    备份存储: NAS存储，用于备份数据
```

### 1.2 网络设备配置

#### 核心交换机配置
```bash
# Cisco Catalyst 9500系列核心交换机配置示例

# 基础配置
hostname Core-Switch-01
enable secret cisco123!
service password-encryption
no ip domain-lookup
ip domain-name company.local

# 管理配置
interface Vlan1
 ip address 192.168.1.2 255.255.255.0
 no shutdown

ip route 0.0.0.0 0.0.0.0 192.168.1.1
ip name-server 192.168.1.10 192.168.1.11
ntp server pool.ntp.org

# VLAN配置
vlan 1
 name Management
vlan 100
 name User-Network
vlan 200
 name Server-Network
vlan 300
 name DMZ-Network

# 链路聚合配置
interface Port-channel1
 description Link to Access Switch
 switchport mode trunk
 switchport trunk allowed vlan 1,100

interface range GigabitEthernet1/0/1-2
 description Link to Access Switch
 switchport mode trunk
 switchport trunk allowed vlan 1,100
 channel-group 1 mode active

# 安全配置
# 启用端口安全
interface range GigabitEthernet1/0/3-48
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky

# 访问控制列表
ip access-list extended OFFICE-TO-SERVER
 permit tcp 192.168.100.0 0.0.0.255 192.168.200.0 0.0.0.255 eq 80
 permit tcp 192.168.100.0 0.0.0.255 192.168.200.0 0.0.0.255 eq 443
 deny ip any any log
```

#### 防火墙配置
```bash
# 深信服NGAF防火墙配置示例

# 安全域配置
security-zone trust
 priority 85
security-zone untrust
 priority 5
security-zone dmz
 priority 50

# 接口配置
interface ethernet1/1
 description "WAN Interface"
 ip address 202.102.1.100/24
 security-zone untrust
 
interface ethernet1/2
 description "LAN Interface"
 ip address 192.168.1.1/24
 security-zone trust

interface ethernet1/3
 description "DMZ Interface"
 ip address 192.168.100.1/24
 security-zone dmz

# 路由配置
ip route 0.0.0.0/0 202.102.1.1

# 安全策略配置
security-policy rule allow-web
 from trust to untrust
 source-address 192.168.0.0/16
 destination-address any
 application http https
 action permit
 log session-start session-end

security-policy rule deny-all
 from any to any
 action deny
 log session-start session-end

# NAT配置
nat-policy rule outbound-nat
 from trust to untrust
 source-address 192.168.0.0/16
 action source-nat interface

nat-policy rule dmz-dnat
 from untrust to dmz
 destination-address 202.102.1.100
 destination-port 80 443
 action destination-nat ip 192.168.100.10
```

### 1.3 存储系统配置

#### SAN存储配置
```yaml
# EMC Unity 500存储配置
Unity存储系统:
  系统信息:
    型号: Unity 500
    序列号: APM00123456789
    管理IP: 192.168.1.50
    
  存储池配置:
    Pool-01-SSD:
      磁盘类型: SSD
      RAID级别: RAID5
      容量: 20TB
      用途: 高性能应用
      
    Pool-02-SAS:
      磁盘类型: SAS 10K
      RAID级别: RAID6
      容量: 50TB
      用途: 一般应用
      
    Pool-03-NL-SAS:
      磁盘类型: NL-SAS 7.2K
      RAID级别: RAID6
      容量: 100TB
      用途: 归档数据

  LUN配置:
    vmware-datastore-01:
      存储池: Pool-01-SSD
      大小: 5TB
      协议: iSCSI
      主机组: ESXi-Cluster
      
    vmware-datastore-02:
      存储池: Pool-02-SAS
      大小: 20TB
      协议: iSCSI
      主机组: ESXi-Cluster

  网络配置:
    iSCSI-A:
      IP地址: 192.168.50.10
      子网掩码: 255.255.255.0
      VLAN: 200
      
    iSCSI-B:
      IP地址: 192.168.50.11
      子网掩码: 255.255.255.0
      VLAN: 200
```

#### NAS存储配置
```bash
# Synology DiskStation NAS配置

# 存储空间配置
存储空间1:
  名称: Volume_1
  文件系统: Btrfs
  RAID类型: SHR-2
  容量: 48TB
  用途: 文件共享和备份

# 共享文件夹配置
共享文件夹:
  部门共享:
    - /volume1/departments/it
    - /volume1/departments/finance
    - /volume1/departments/sales
    - /volume1/departments/hr
  
  备份共享:
    - /volume1/backup/servers
    - /volume1/backup/databases
    - /volume1/backup/workstations

# 用户和权限配置
用户组:
  IT_Group: 完全控制IT部门文件夹
  Finance_Group: 完全控制财务部门文件夹
  All_Users: 读取公共文件夹

# 备份任务配置
备份任务:
  服务器备份:
    源: ESXi虚拟机
    目标: /volume1/backup/servers
    计划: 每日23:00
    保留: 30天
    
  数据库备份:
    源: 数据库服务器
    目标: /volume1/backup/databases
    计划: 每4小时
    保留: 7天
```

## 2. 软件配置管理

### 2.1 操作系统配置

#### Windows Server 2022配置
```powershell
# Windows Server 2022标准化配置脚本

# 1. 基础系统配置
# 设置计算机名和域加入
$computerName = "WIN-SRV-01"
$domainName = "company.local"
$credential = Get-Credential -Message "输入域管理员凭据"

Rename-Computer -NewName $computerName -Force
Add-Computer -DomainName $domainName -Credential $credential -Restart

# 2. 网络配置
$adapter = Get-NetAdapter -Name "Ethernet"
New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress "192.168.10.10" -PrefixLength 24 -DefaultGateway "192.168.10.1"
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "192.168.1.10","192.168.1.11"

# 3. 防火墙配置
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
New-NetFirewallRule -DisplayName "Allow ICMP" -Protocol ICMPv4 -IcmpType 8 -Action Allow
New-NetFirewallRule -DisplayName "Allow RDP" -Protocol TCP -LocalPort 3389 -Action Allow

# 4. 服务配置
Set-Service -Name "Windows Update" -StartupType Manual
Set-Service -Name "BITS" -StartupType Automatic
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

# 5. 安全配置
# 启用审计策略
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable

# 6. 性能优化
# 禁用不必要的服务
$servicesToDisable = @("Fax", "Print Spooler", "Windows Search")
foreach ($service in $servicesToDisable) {
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# 7. 安装必要软件
# 安装Windows特性
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic
```

#### Ubuntu 22.04 LTS配置
```bash
#!/bin/bash
# Ubuntu 22.04 LTS标准化配置脚本

# 1. 系统更新
apt update && apt upgrade -y

# 2. 设置主机名和网络
hostnamectl set-hostname ubuntu-srv-01
echo "192.168.10.20 ubuntu-srv-01.company.local ubuntu-srv-01" >> /etc/hosts

# 3. 网络配置 (使用netplan)
cat > /etc/netplan/01-netcfg.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      addresses:
        - 192.168.10.20/24
      gateway4: 192.168.10.1
      nameservers:
        addresses: [192.168.1.10, 192.168.1.11]
        search: [company.local]
EOF
netplan apply

# 4. SSH安全配置
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart ssh

# 5. 防火墙配置
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp  # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS

# 6. 安装基础软件包
apt install -y curl wget git vim htop iftop iotop net-tools
apt install -y docker.io docker-compose
systemctl enable docker
systemctl start docker

# 7. 用户和权限配置
useradd -m -s /bin/bash -G sudo,docker sysadmin
echo 'sysadmin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysadmin

# 8. 日志配置
# 配置rsyslog发送到中央日志服务器
echo "*.* @@192.168.1.100:514" >> /etc/rsyslog.conf
systemctl restart rsyslog

# 9. 性能优化
echo 'vm.swappiness=10' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p

# 10. 时间同步
timedatectl set-timezone Asia/Shanghai
sed -i 's/#NTP=/NTP=pool.ntp.org/' /etc/systemd/timesyncd.conf
systemctl restart systemd-timesyncd
```

### 2.2 虚拟化平台配置

#### VMware vSphere 8.0集群配置
```yaml
# vCenter Server配置
vCenter配置:
  版本: vCenter Server 8.0
  部署类型: 嵌入式部署
  主机名: vcenter.company.local
  IP地址: 192.168.1.100
  管理员: administrator@vsphere.local
  
  数据中心配置:
    名称: Company-Datacenter
    位置: 北京总部机房
    
  集群配置:
    名称: Production-Cluster
    主机数量: 3台
    HA配置:
      启用: true
      故障转移主机: 1台
      准入控制策略: 25%资源预留
      
    DRS配置:
      启用: true
      自动化级别: 全自动
      VM分布: 均衡分布
      
    vSAN配置:
      启用: false
      存储: 外部SAN存储
      
  网络配置:
    分布式交换机:
      名称: DSwitch-Production
      版本: 7.0.3
      端口组:
        - Management: VLAN 1
        - VM-Network: VLAN 100
        - DMZ-Network: VLAN 300
        - Storage: VLAN 200

# 资源池配置
资源池:
  Production-Pool:
    CPU预留: 50%
    内存预留: 50%
    优先级: 高
    
  Development-Pool:
    CPU预留: 20%
    内存预留: 20%
    优先级: 一般
    
  Test-Pool:
    CPU预留: 10%
    内存预留: 10%
    优先级: 低
```

#### 虚拟机模板配置
```yaml
# Windows Server 2022模板
Windows模板:
  名称: Template-Windows-2022
  操作系统: Windows Server 2022 Standard
  配置:
    CPU: 2 vCPU
    内存: 8 GB
    硬盘: 80 GB (精简置备)
    网卡: VMXNET3
    
  软件:
    - Windows Updates (最新)
    - VMware Tools (最新版本)
    - .NET Framework 4.8
    - PowerShell 7.x
    - 企业防病毒软件
    - 监控代理
    
  配置:
    - 域加入准备
    - 管理员账户配置
    - 网络配置脚本
    - 自动化部署脚本

# Ubuntu 22.04模板  
Ubuntu模板:
  名称: Template-Ubuntu-2204
  操作系统: Ubuntu 22.04 LTS Server
  配置:
    CPU: 2 vCPU
    内存: 4 GB
    硬盘: 40 GB (精简置备)
    网卡: VMXNET3
    
  软件:
    - 系统更新 (最新)
    - VMware Tools / open-vm-tools
    - Docker Engine
    - Python 3.10
    - Git
    - 监控代理
    
  配置:
    - SSH密钥配置
    - 用户账户配置
    - 网络配置模板
    - 自动化部署脚本
```

### 2.3 数据库配置

#### SQL Server 2022配置
```sql
-- SQL Server 2022标准化配置

-- 1. 实例配置
USE master;
GO

-- 配置最大服务器内存 (保留4GB给OS)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'max server memory', 12288; -- 12GB
RECONFIGURE;

-- 配置备份压缩
EXEC sp_configure 'backup compression default', 1;
RECONFIGURE;

-- 配置数据库邮件
-- (此处配置邮件服务器设置)

-- 2. 数据库配置
-- 创建企业标准数据库
CREATE DATABASE CompanyDB
ON (
    NAME = 'CompanyDB_Data',
    FILENAME = 'E:\Data\CompanyDB_Data.mdf',
    SIZE = 1GB,
    MAXSIZE = 100GB,
    FILEGROWTH = 100MB
)
LOG ON (
    NAME = 'CompanyDB_Log',
    FILENAME = 'F:\Logs\CompanyDB_Log.ldf',
    SIZE = 256MB,
    MAXSIZE = 10GB,
    FILEGROWTH = 64MB
);

-- 3. 安全配置
-- 创建数据库用户
USE CompanyDB;
GO
CREATE LOGIN app_user WITH PASSWORD = 'StrongPassword123!';
CREATE USER app_user FOR LOGIN app_user;
EXEC sp_addrolemember 'db_datareader', 'app_user';
EXEC sp_addrolemember 'db_datawriter', 'app_user';

-- 4. 维护计划
-- 创建备份作业
USE msdb;
GO
EXEC dbo.sp_add_job
    @job_name = N'CompanyDB Full Backup';
    
EXEC dbo.sp_add_jobstep
    @job_name = N'CompanyDB Full Backup',
    @step_name = N'Backup Database',
    @command = N'BACKUP DATABASE CompanyDB TO DISK = ''G:\Backup\CompanyDB_Full.bak'' 
                 WITH COMPRESSION, CHECKSUM, INIT';

-- 5. 监控配置
-- 启用查询存储
ALTER DATABASE CompanyDB
SET QUERY_STORE = ON (
    OPERATION_MODE = READ_WRITE,
    CLEANUP_POLICY = (STALE_QUERY_THRESHOLD_DAYS = 30),
    DATA_FLUSH_INTERVAL_SECONDS = 900,
    MAX_STORAGE_SIZE_MB = 1000
);
```

#### PostgreSQL 15配置
```bash
# PostgreSQL 15标准化配置

# 1. 安装PostgreSQL 15
sudo apt install postgresql-15 postgresql-client-15 postgresql-contrib-15

# 2. 基础配置文件修改
sudo vim /etc/postgresql/15/main/postgresql.conf

# 主要配置参数：
# 连接配置
listen_addresses = '*'
port = 5432
max_connections = 200

# 内存配置
shared_buffers = 4GB                    # 总内存的25%
effective_cache_size = 12GB             # 总内存的75%
work_mem = 16MB
maintenance_work_mem = 512MB

# 检查点配置
checkpoint_timeout = 10min
checkpoint_completion_target = 0.9
wal_buffers = 16MB

# 日志配置
log_destination = 'stderr'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'all'
log_min_duration_statement = 1000       # 记录慢查询(>1秒)

# 3. 客户端认证配置
sudo vim /etc/postgresql/15/main/pg_hba.conf

# 配置内容：
# Database administrative login by Unix domain socket
local   all             postgres                                peer

# "local" is for Unix domain socket connections only
local   all             all                                     md5

# IPv4 local connections:
host    all             all             127.0.0.1/32            md5
host    all             all             192.168.10.0/24         md5

# 4. 创建数据库和用户
sudo -u postgres psql

-- 创建应用数据库
CREATE DATABASE companydb
    WITH OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'zh_CN.UTF-8'
    LC_CTYPE = 'zh_CN.UTF-8'
    TEMPLATE = template0;

-- 创建应用用户
CREATE USER appuser WITH PASSWORD 'SecurePassword123!';
GRANT ALL PRIVILEGES ON DATABASE companydb TO appuser;

-- 创建只读用户
CREATE USER readonly WITH PASSWORD 'ReadOnlyPass123!';
GRANT CONNECT ON DATABASE companydb TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;

# 5. 备份配置
sudo vim /etc/cron.d/postgresql-backup

# 每日备份任务
0 2 * * * postgres /usr/bin/pg_dump -h localhost -U postgres -d companydb | gzip > /backup/postgresql/companydb_$(date +\%Y\%m\%d).sql.gz

# 每周清理旧备份
0 3 * * 0 find /backup/postgresql -name "*.sql.gz" -mtime +30 -delete

# 6. 重启服务
sudo systemctl restart postgresql
sudo systemctl enable postgresql
```

### 2.4 应用中间件配置

#### Nginx配置
```nginx
# /etc/nginx/nginx.conf
# Nginx主配置文件

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 2048;
    use epoll;
    multi_accept on;
}

http {
    # 基础配置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # MIME类型
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # 上游服务器配置
    upstream backend {
        server 192.168.10.21:8080 weight=3;
        server 192.168.10.22:8080 weight=3;
        server 192.168.10.23:8080 weight=2 backup;
        keepalive 32;
    }

    # 主站点配置
    server {
        listen 80;
        server_name company.local www.company.local;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name company.local www.company.local;

        # SSL配置
        ssl_certificate /etc/ssl/certs/company.local.crt;
        ssl_certificate_key /etc/ssl/private/company.local.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # 安全头
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

        # 反向代理配置
        location / {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 5s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # 静态文件配置
        location /static/ {
            alias /var/www/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # 健康检查
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }

    # 管理后台配置
    server {
        listen 8443 ssl;
        server_name admin.company.local;

        ssl_certificate /etc/ssl/certs/admin.company.local.crt;
        ssl_certificate_key /etc/ssl/private/admin.company.local.key;

        # 限制访问IP
        allow 192.168.1.0/24;
        allow 192.168.10.0/24;
        deny all;

        location / {
            proxy_pass http://192.168.10.30:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
```

#### Redis配置
```bash
# /etc/redis/redis.conf
# Redis 7.0配置文件

# 网络配置
bind 192.168.10.40 127.0.0.1
port 6379
protected-mode yes
requirepass "RedisPassword123!"

# 持久化配置
save 900 1      # 15分钟内至少1个键改变
save 300 10     # 5分钟内至少10个键改变  
save 60 10000   # 1分钟内至少10000个键改变

# AOF持久化
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec

# 内存配置
maxmemory 4gb
maxmemory-policy allkeys-lru

# 日志配置
loglevel notice
logfile /var/log/redis/redis-server.log

# 慢查询日志
slowlog-log-slower-than 10000  # 10毫秒
slowlog-max-len 128

# 客户端连接
maxclients 1000
timeout 300

# 安全配置
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command EVAL ""
rename-command DEBUG ""

# 主从复制配置 (如果是从节点)
# replicaof 192.168.10.41 6379
# masterauth "RedisPassword123!"

# 集群配置 (如果启用集群)
# cluster-enabled yes
# cluster-config-file nodes-6379.conf
# cluster-node-timeout 15000
```

## 3. 安全配置管理

### 3.1 网络安全配置

#### 防火墙策略配置
```bash
# 企业防火墙安全策略配置

# 1. 基础安全策略
# 拒绝所有未明确允许的流量
security-policy rule default-deny
  from any to any
  action deny
  log session-start session-end

# 2. 内网到外网访问策略
security-policy rule internal-to-internet
  from trust to untrust
  source-address 192.168.0.0/16
  destination-address any
  application http https dns ntp
  action permit
  log session-end

# 3. DMZ访问策略
security-policy rule dmz-inbound
  from untrust to dmz
  destination-address 192.168.100.10-192.168.100.20
  application http https ssh
  action permit
  log session-start session-end

security-policy rule dmz-to-internal
  from dmz to trust
  destination-address 192.168.10.0/24
  destination-port 3306 5432 1433
  action permit
  log session-start session-end

# 4. 管理访问策略
security-policy rule admin-access
  from trust to trust
  source-address 192.168.1.0/24
  destination-address any
  application ssh rdp snmp
  action permit
  log session-start session-end

# 5. 威胁防护策略
# 启用入侵防护
ips-policy rule block-attacks
  signature-category critical high
  action block-ip
  log-level high

# 启用防病毒扫描
antivirus-policy rule scan-files
  file-type any
  action block
  log-level medium

# 启用URL过滤
url-filtering-policy rule block-malicious
  category malware phishing
  action block
  log-level high
```

#### IDS/IPS配置
```yaml
# Suricata IDS/IPS配置
Suricata配置:
  版本: 6.0.x
  模式: IPS模式 (内联部署)
  
  网络接口:
    监控接口: eth1 (内联模式)
    管理接口: eth0
    
  规则集配置:
    Emerging Threats: 启用
    Suricata规则: 启用
    自定义规则: 启用
    
  检测配置:
    协议检测: 全部启用
    文件提取: 启用 (可执行文件、Office文档)
    日志记录: 详细模式
    
  性能优化:
    多线程: 启用
    CPU亲和性: 配置
    内存优化: 启用
    
  告警配置:
    告警阈值: 中等及以上
    SIEM集成: 启用
    邮件通知: 启用 (管理员)
    
自定义规则示例:
  # 检测内网扫描
  alert tcp $HOME_NET any -> $HOME_NET any (
    msg:"Internal Port Scan Detected";
    threshold:type both,track by_src,count 20,seconds 60;
    classtype:attempted-recon;
    sid:1000001;
  )
  
  # 检测可疑文件下载
  alert http any any -> $HOME_NET any (
    msg:"Suspicious Executable Download";
    content:"Content-Type|3a 20|application/octet-stream";
    flow:established,to_client;
    classtype:trojan-activity;
    sid:1000002;
  )
```

### 3.2 终端安全配置

#### Windows终端安全策略
```powershell
# Windows终端安全配置脚本

# 1. 组策略配置
# 密码策略
net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:12

# 账户锁定策略
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# 2. 审计策略配置
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

# 3. Windows Defender配置
# 启用实时保护
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false

# 配置排除项 (性能优化)
Add-MpPreference -ExclusionPath "C:\Program Files\VMware"
Add-MpPreference -ExclusionProcess "vmware.exe"

# 配置云保护
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# 4. BitLocker配置 (如果需要)
# 启用BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly
```

#### Linux终端安全配置
```bash
#!/bin/bash
# Linux终端安全配置脚本

# 1. 系统加固
# 禁用不必要的服务
systemctl disable cups
systemctl disable bluetooth
systemctl disable avahi-daemon

# 2. SSH安全配置
sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/' /etc/ssh/sshd_config

# 添加SSH访问控制
echo "AllowUsers sysadmin appuser" >> /etc/ssh/sshd_config
echo "DenyUsers root" >> /etc/ssh/sshd_config

# 3. 防火墙配置
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.1.0/24 to any port 22
ufw allow 80/tcp
ufw allow 443/tcp

# 4. 审计配置
# 安装auditd
apt install auditd -y

# 配置审计规则
cat >> /etc/audit/rules.d/audit.rules << EOF
# 监控用户账户操作
-w /etc/passwd -p wa -k user-account
-w /etc/group -p wa -k user-account
-w /etc/shadow -p wa -k user-account

# 监控sudo使用
-w /var/log/sudo.log -p wa -k sudo-log
-w /etc/sudoers -p wa -k sudo-config

# 监控系统配置文件
-w /etc/ssh/sshd_config -p wa -k ssh-config
-w /etc/hosts -p wa -k network-config

# 监控系统调用
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
EOF

# 重启auditd
systemctl restart auditd

# 5. 文件权限加固
# 设置关键文件权限
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/ssh/sshd_config

# 6. 内核参数优化
cat >> /etc/sysctl.conf << EOF
# 网络安全参数
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF

sysctl -p

# 7. 日志转发配置
# 配置rsyslog转发到SIEM
echo "*.* @@192.168.1.100:514" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

### 3.3 数据安全配置

#### 数据库加密配置
```sql
-- SQL Server TDE (透明数据加密) 配置

-- 1. 创建主密钥
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyPassword123!';

-- 2. 创建证书
CREATE CERTIFICATE TDECert
WITH SUBJECT = 'TDE Certificate for CompanyDB';

-- 3. 备份证书 (重要!)
BACKUP CERTIFICATE TDECert
TO FILE = 'C:\Backup\TDECert.cer'
WITH PRIVATE KEY (
    FILE = 'C:\Backup\TDECert.pvk',
    ENCRYPTION BY PASSWORD = 'CertBackupPassword123!'
);

-- 4. 在用户数据库中创建数据库加密密钥
USE CompanyDB;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDECert;

-- 5. 启用TDE
ALTER DATABASE CompanyDB
SET ENCRYPTION ON;

-- 6. 验证加密状态
SELECT 
    db_name(database_id) as database_name,
    encryption_state,
    encryption_state_desc
FROM sys.dm_database_encryption_keys;
```

#### 备份加密配置
```powershell
# Windows Server备份加密配置

# 1. 创建备份策略
$policy = New-WBPolicy
$fileSpec = New-WBFileSpec -FileSpec "C:\Data"
Add-WBFileSpec -Policy $policy -FileSpec $fileSpec

# 2. 设置备份目标 (加密)
$backupLocation = New-WBBackupTarget -VolumePath "E:"
Add-WBBackupTarget -Policy $policy -Target $backupLocation

# 3. 设置备份计划
Set-WBSchedule -Policy $policy -Schedule "21:00"

# 4. 启用备份加密
$password = ConvertTo-SecureString "BackupPassword123!" -AsPlainText -Force
Set-WBPolicy -Policy $policy -Password $password -Encryption $true

# 5. 应用策略
Set-WBPolicy -Policy $policy
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*负责人：系统配置团队*