# 配置阶段 - 中小企业IT基础设施 (50-100人)

## 阶段概述
配置阶段针对中小企业的实际情况，重点关注快速部署、标准化配置和自动化管理，通过精简的配置流程确保系统快速稳定上线。

## 1. 基础设施配置

### 1.1 服务器系统配置

#### Proxmox VE虚拟化平台配置
```bash
#!/bin/bash
# Proxmox VE 快速配置脚本 (中小企业版)

# 1. 基础系统配置
configure_proxmox_basic() {
    echo "配置Proxmox VE基础设置..."
    
    # 更新系统
    apt update && apt upgrade -y
    
    # 配置时区
    timedatectl set-timezone Asia/Shanghai
    
    # 配置NTP
    apt install chrony -y
    cat > /etc/chrony/chrony.conf << EOF
pool pool.ntp.org iburst
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
EOF
    systemctl restart chrony
    systemctl enable chrony
    
    # 配置主机名和hosts
    hostnamectl set-hostname pve-server01.company.local
    echo "192.168.1.100 pve-server01.company.local pve-server01" >> /etc/hosts
    
    echo "Proxmox VE基础配置完成"
}

# 2. 存储配置
configure_storage() {
    echo "配置存储..."
    
    # 配置本地存储
    pvesm set local --content vztmpl,iso,backup
    pvesm set local-lvm --content images,rootdir
    
    # 添加NFS存储 (如果有NAS)
    pvesm add nfs backup-nfs --server 192.168.1.200 --export /backup --content backup,iso,vztmpl
    
    # 配置目录存储
    mkdir -p /mnt/templates
    pvesm add dir templates --path /mnt/templates --content vztmpl,iso
    
    echo "存储配置完成"
}

# 3. 网络配置
configure_network() {
    echo "配置网络..."
    
    # 创建Linux Bridge
    cat > /etc/network/interfaces << EOF
auto lo
iface lo inet loopback

iface eno1 inet manual

auto vmbr0
iface vmbr0 inet static
    address 192.168.1.100/24
    gateway 192.168.1.1
    bridge-ports eno1
    bridge-stp off
    bridge-fd 0
    dns-nameservers 192.168.1.10 192.168.1.11

# DMZ网络
auto vmbr1
iface vmbr1 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
EOF
    
    # 重启网络
    systemctl restart networking
    
    echo "网络配置完成"
}

# 4. 创建虚拟机模板
create_vm_templates() {
    echo "创建虚拟机模板..."
    
    # 下载Ubuntu 22.04 ISO
    cd /var/lib/vz/template/iso
    wget https://releases.ubuntu.com/22.04/ubuntu-22.04-live-server-amd64.iso
    
    # 创建Ubuntu模板VM
    qm create 9000 --name ubuntu-2204-template --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0
    qm importdisk 9000 ubuntu-22.04-live-server-amd64.iso local-lvm
    qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
    qm set 9000 --ide2 local:iso/ubuntu-22.04-live-server-amd64.iso,media=cdrom
    qm set 9000 --boot c --bootdisk scsi0
    qm set 9000 --serial0 socket --vga serial0
    qm set 9000 --agent enabled=1
    
    echo "模板创建完成"
}

# 5. 配置用户和权限
configure_users() {
    echo "配置用户权限..."
    
    # 创建管理组
    pveum group add admins -comment "IT管理员组"
    pveum group add users -comment "普通用户组"
    
    # 分配权限
    pveum acl modify / -group admins -role Administrator
    pveum acl modify /vms -group users -role PVEVMUser
    
    # 创建用户
    pveum user add admin@pve --groups admins --comment "系统管理员"
    pveum passwd admin@pve
    
    echo "用户权限配置完成"
}

# 执行配置
configure_proxmox_basic
configure_storage
configure_network
create_vm_templates
configure_users

echo "Proxmox VE配置完成！"
```

#### Ubuntu Server 模板配置
```bash
#!/bin/bash
# Ubuntu Server 标准化配置脚本

# 1. 系统基础配置
configure_ubuntu_base() {
    echo "配置Ubuntu基础环境..."
    
    # 更新系统
    apt update && apt upgrade -y
    
    # 安装基础工具
    apt install -y curl wget git vim htop iftop iotop tree unzip
    apt install -y net-tools dnsutils telnet tcpdump
    apt install -y software-properties-common apt-transport-https ca-certificates
    
    # 配置时区和语言
    timedatectl set-timezone Asia/Shanghai
    locale-gen zh_CN.UTF-8
    
    # 优化系统参数
    cat >> /etc/sysctl.conf << EOF
# 网络优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 12582912 16777216
net.ipv4.tcp_wmem = 4096 12582912 16777216
net.core.netdev_max_backlog = 5000

# 文件系统优化
fs.file-max = 65536
vm.swappiness = 10
EOF
    sysctl -p
    
    echo "Ubuntu基础配置完成"
}

# 2. SSH安全配置
configure_ssh() {
    echo "配置SSH安全..."
    
    # 备份原配置
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # 安全配置
    cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 登录配置
LoginGraceTime 60
PermitRootLogin no
MaxAuthTries 3
MaxSessions 10
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# 网络配置
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# 安全限制
AllowUsers sysadmin
DenyUsers root
ClientAliveInterval 600
ClientAliveCountMax 3
EOF
    
    # 重启SSH服务
    systemctl restart ssh
    systemctl enable ssh
    
    echo "SSH配置完成"
}

# 3. 防火墙配置
configure_firewall() {
    echo "配置防火墙..."
    
    # 启用UFW
    ufw --force enable
    
    # 基础规则
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许SSH (限制源IP)
    ufw allow from 192.168.1.0/24 to any port 22
    
    # 允许常用服务
    ufw allow 80/tcp     # HTTP
    ufw allow 443/tcp    # HTTPS
    ufw allow 53         # DNS
    
    # 状态检查
    ufw status verbose
    
    echo "防火墙配置完成"
}

# 4. 日志配置
configure_logging() {
    echo "配置日志系统..."
    
    # 配置rsyslog
    cat >> /etc/rsyslog.conf << EOF
# 发送日志到中央日志服务器
*.* @@192.168.1.150:514
EOF
    
    # 配置logrotate
    cat > /etc/logrotate.d/custom << EOF
/var/log/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    systemctl restart rsyslog
    
    echo "日志配置完成"
}

# 5. 监控代理配置
install_monitoring() {
    echo "安装监控代理..."
    
    # 安装Node Exporter (Prometheus监控)
    cd /tmp
    wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
    tar xzf node_exporter-1.6.1.linux-amd64.tar.gz
    cp node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
    chmod +x /usr/local/bin/node_exporter
    
    # 创建systemd服务
    cat > /etc/systemd/system/node_exporter.service << EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=nobody
Group=nogroup
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter
    
    echo "监控代理安装完成"
}

# 执行配置
configure_ubuntu_base
configure_ssh
configure_firewall
configure_logging
install_monitoring

echo "Ubuntu Server配置完成！"
```

### 1.2 网络设备配置

#### 企业路由器配置 (华为AR1220C)
```bash
# 华为AR1220C路由器配置脚本
# 通过SSH连接到路由器执行

# 1. 基础配置
sysname Company-Router
clock timezone BeiJing add 08:00:00

# 2. 接口配置
interface GigabitEthernet0/0/0
 description "WAN-Internet"
 ip address dhcp-alloc
 nat outbound 2000
 
interface GigabitEthernet0/0/1
 description "LAN-Internal"
 ip address 192.168.1.1 255.255.255.0
 dhcp select interface
 dhcp server dns-list 114.114.114.114 8.8.8.8

# 3. DHCP配置
dhcp enable
ip pool LAN
 gateway-list 192.168.1.1
 network 192.168.1.0 mask 255.255.255.0 
 dns-list 192.168.1.10 192.168.1.11
 lease day 1 hour 0 minute 0

# 4. NAT配置
acl number 2000
 rule 5 permit source 192.168.1.0 0.0.0.255

nat address-group 1 202.96.1.100 202.96.1.100
nat outbound 2000 address-group 1

# 5. VPN配置 (L2TP)
l2tp enable
l2tp-group 1
 tunnel authentication
 tunnel hello 60
 tunnel timer hello 60
 allow l2tp virtual-template 1
 
interface Virtual-Template1
 ppp authentication-mode pap
 ip address unnumbered interface GigabitEthernet0/0/1
 remote address pool remote_pool

ip pool remote_pool
 network 192.168.1.100 mask 255.255.255.0

# 6. QoS配置
traffic classifier web operator and
 if-match protocol http
 if-match protocol https
 
traffic behavior high-priority
 car cir 50000 pir 100000
 
traffic policy company-qos
 classifier web behavior high-priority

interface GigabitEthernet0/0/0
 traffic-policy company-qos outbound

# 7. 安全配置
acl number 3000
 rule 5 deny tcp destination-port eq 135
 rule 10 deny tcp destination-port eq 139  
 rule 15 deny tcp destination-port eq 445
 rule 20 permit ip

interface GigabitEthernet0/0/0
 traffic-filter inbound acl 3000

# 8. 管理配置
snmp-agent
snmp-agent community read public
snmp-agent community write private
snmp-agent sys-info version v2c v3

user-interface vty 0 4
 authentication-mode password
 set authentication password cipher admin123
 user privilege level 15
 protocol inbound ssh

# 保存配置
save
```

#### 核心交换机配置 (华为S1720)
```bash
# 华为S1720交换机配置

# 1. 基础配置
sysname Core-Switch-01
clock timezone BeiJing add 08:00:00

# 2. VLAN配置
vlan 1
 description Management
vlan 10
 description Servers
vlan 20  
 description Workstations
vlan 30
 description Printers
vlan 40
 description WiFi
vlan 99
 description Guest

# 3. 接口配置
interface Vlanif1
 ip address 192.168.1.2 255.255.255.0
 
interface Vlanif10
 ip address 192.168.10.1 255.255.255.0
 
interface Vlanif20
 ip address 192.168.20.1 255.255.255.0

# 4. 端口配置
# 服务器端口 (1-4)
interface range GigabitEthernet0/0/1 to GigabitEthernet0/0/4
 port link-type access
 port default vlan 10
 stp edged-port enable
 
# 工作站端口 (5-20)
interface range GigabitEthernet0/0/5 to GigabitEthernet0/0/20
 port link-type access
 port default vlan 20
 stp edged-port enable
 port-security enable
 port-security max-mac-num 2

# WiFi AP端口 (21-24)
interface range GigabitEthernet0/0/21 to GigabitEthernet0/0/24
 port link-type trunk
 port trunk allow-pass vlan 20 40 99
 poe enable
 
# 上联端口 (万兆口)
interface 10GE0/0/1
 description "Uplink to Router"
 port link-type trunk
 port trunk allow-pass vlan all

# 5. STP配置
stp mode rstp
stp enable
stp priority 4096

# 6. 端口安全
port-security enable
port-security aging-time 60
port-security violation restrict

# 7. 环路检测
loopback-detection enable
interface range GigabitEthernet0/0/5 to GigabitEthernet0/0/20
 loopback-detection enable
 loopback-detection action block

# 8. SNMP管理
snmp-agent
snmp-agent community read public
snmp-agent sys-info version v2c

# 保存配置
save
```

#### 无线AP配置 (华为AP4050DN)
```bash
# 华为AP4050DN无线接入点配置

# 1. 基本网络配置
# (通过AC控制器或Web界面配置)

# 2. SSID配置
SSID配置:
  主要SSID:
    名称: Company-WiFi
    安全: WPA3-PSK
    密码: CompanyWiFi2025!
    VLAN: 20 (工作站网络)
    带宽限制: 100Mbps/用户
    
  访客SSID:
    名称: Company-Guest
    安全: WPA2-PSK
    密码: Guest2025
    VLAN: 99 (访客网络)
    带宽限制: 10Mbps/用户
    隔离: 启用客户端隔离
    
  管理SSID:
    名称: Company-Admin
    安全: WPA3-Enterprise
    认证: RADIUS
    VLAN: 1 (管理网络)
    隐藏: 是

# 3. 射频配置
射频参数:
  2.4GHz:
    信道: 自动 (1,6,11优先)
    功率: 自动调整
    信道带宽: 40MHz
    
  5GHz:
    信道: 自动 (36-165)
    功率: 自动调整  
    信道带宽: 80MHz
    
# 4. 高级功能
高级设置:
  负载均衡: 启用
  频段引导: 启用 (引导至5GHz)
  快速漫游: 启用 (802.11r)
  空口时间公平: 启用
  智能天线: 启用

# 5. 安全配置
安全设置:
  隐藏SSID: 管理网络启用
  MAC过滤: 管理网络启用白名单
  接入控制: 按时间段控制访客网络
  防钓鱼: 启用
  
# 6. QoS配置
QoS设置:
  语音: 最高优先级
  视频: 高优先级
  数据: 标准优先级
  背景: 低优先级
```

### 1.3 安全设备配置

#### 防火墙配置 (SonicWall TZ570)
```bash
# SonicWall TZ570 防火墙配置指南
# 通过Web管理界面配置

# 1. 网络接口配置
网络设置:
  X0 (LAN):
    IP地址: 192.168.1.1
    子网掩码: 255.255.255.0
    安全域: LAN
    
  X1 (WAN):
    配置: DHCP客户端 (或静态IP)
    安全域: WAN
    
  X2 (DMZ):
    IP地址: 192.168.100.1
    子网掩码: 255.255.255.0
    安全域: DMZ

# 2. 安全域规则
访问规则:
  LAN → WAN:
    源: LAN网段 (192.168.1.0/24)
    目标: Any
    服务: HTTP, HTTPS, DNS, Email
    动作: 允许
    
  LAN → DMZ:
    源: LAN网段
    目标: DMZ网段 (192.168.100.0/24)
    服务: HTTP, HTTPS, SSH, RDP
    动作: 允许
    
  WAN → DMZ:
    源: Any
    目标: Web服务器 (192.168.100.10)
    服务: HTTP, HTTPS
    动作: 允许
    
  DMZ → LAN:
    动作: 拒绝 (默认)

# 3. NAT策略
NAT规则:
  出站NAT:
    源: LAN网段
    目标: WAN
    转换: 接口IP
    
  入站NAT (端口映射):
    外部端口: 80, 443
    内部IP: 192.168.100.10
    内部端口: 80, 443

# 4. VPN配置
SSL VPN:
  启用: 是
  端口: 443
  用户数: 20
  客户端IP池: 192.168.50.100-120
  DNS服务器: 192.168.1.10
  
  用户组:
    IT管理员: 完全访问
    销售人员: 限制访问
    远程员工: 基础访问

# 5. 内容过滤
Web过滤:
  启用类别过滤:
    - 恶意软件: 阻止
    - 成人内容: 阻止  
    - 社交媒体: 警告
    - 在线游戏: 阻止
    - 文件共享: 阻止
    
  时间策略:
    工作时间: 严格过滤
    休息时间: 宽松过滤

# 6. 入侵防护
IPS设置:
  启用签名类别:
    - 高风险: 阻止并记录
    - 中风险: 阻止并记录
    - 低风险: 记录
    
  自定义签名:
    - SQL注入: 阻止
    - XSS攻击: 阻止
    - 暴力破解: 阻止

# 7. 反恶意软件
安全服务:
  网关防病毒: 启用
  反间谍软件: 启用
  入侵防护: 启用
  应用控制: 启用
  
  云沙箱: 启用
  文件类型阻止: exe, scr, bat

# 8. 日志和监控
日志设置:
  系统日志: 启用
  安全日志: 启用
  Web使用: 启用
  邮件安全: 启用
  
  日志服务器: 192.168.1.150
  保留天数: 90天
```

## 2. 应用软件配置

### 2.1 Office 365配置

#### Microsoft 365 Business Premium配置
```powershell
# Microsoft 365 PowerShell配置脚本

# 1. 连接到Microsoft 365
Install-Module -Name MSOnline -Force
Connect-MsolService

# 2. 域名配置
$DomainName = "company.local"
New-MsolDomain -Name $DomainName

# 验证域名 (需要添加TXT记录)
Get-MsolDomainVerificationDns -DomainName $DomainName

# 3. 用户批量创建
$users = @(
    @{Name="张三"; Email="zhangsan@company.local"; Department="IT"; JobTitle="系统管理员"},
    @{Name="李四"; Email="lisi@company.local"; Department="Sales"; JobTitle="销售经理"},
    @{Name="王五"; Email="wangwu@company.local"; Department="Finance"; JobTitle="财务专员"}
)

foreach ($user in $users) {
    $password = "TempPass2025!" | ConvertTo-SecureString -AsPlainText -Force
    New-MsolUser -DisplayName $user.Name -UserPrincipalName $user.Email -Password $password -ForceChangePassword $true -UsageLocation "CN"
    
    # 分配许可证
    Set-MsolUserLicense -UserPrincipalName $user.Email -AddLicenses "company:ENTERPRISEPREMIUM"
}

# 4. 安全策略配置
# 启用多因子认证
$mfaSettings = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$mfaSettings.RelyingParty = "*"
$mfaSettings.State = "Enabled"

Get-MsolUser | Set-MsolUser -StrongAuthenticationRequirements $mfaSettings

# 5. Exchange Online配置
Connect-ExchangeOnline

# 创建邮箱策略
New-AddressList -Name "IT部门" -RecipientFilter {Department -eq "IT"}
New-AddressList -Name "销售部门" -RecipientFilter {Department -eq "Sales"}

# 配置邮件流规则
New-TransportRule -Name "外部邮件警告" -FromScope NotInOrganization -ApplyHtmlDisclaimerText "此邮件来自外部发件人，请谨慎处理链接和附件。"

# 6. SharePoint Online配置
Connect-SPOService -Url https://company-admin.sharepoint.com

# 创建团队站点
New-SPOSite -Url https://company.sharepoint.com/sites/IT -Title "IT部门" -Owner "admin@company.local" -StorageQuota 5120

# 7. Teams配置
Install-Module -Name MicrosoftTeams -Force
Connect-MicrosoftTeams

# 创建团队策略
New-CsTeamsMessagingPolicy -Identity "RestrictedPolicy" -AllowUserChat $false -AllowUserDeleteMessage $false

# 分配策略给用户
Grant-CsTeamsMessagingPolicy -Identity "zhangsan@company.local" -PolicyName "RestrictedPolicy"
```

#### Google Workspace配置 (备选方案)
```python
#!/usr/bin/env python3
# Google Workspace API配置脚本

from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import json

class GoogleWorkspaceSetup:
    def __init__(self, credentials_file):
        self.credentials = Credentials.from_authorized_user_file(credentials_file)
        self.admin_service = build('admin', 'directory_v1', credentials=self.credentials)
        self.gmail_service = build('gmail', 'v1', credentials=self.credentials)
    
    def create_organizational_units(self):
        """创建组织单位"""
        ous = [
            {'name': 'IT部门', 'orgUnitPath': '/IT'},
            {'name': '销售部门', 'orgUnitPath': '/Sales'},
            {'name': '财务部门', 'orgUnitPath': '/Finance'},
            {'name': '管理层', 'orgUnitPath': '/Management'}
        ]
        
        for ou in ous:
            try:
                self.admin_service.orgunits().insert(
                    customerId='my_customer',
                    body={
                        'name': ou['name'],
                        'orgUnitPath': ou['orgUnitPath']
                    }
                ).execute()
                print(f"创建组织单位: {ou['name']}")
            except Exception as e:
                print(f"创建组织单位失败: {e}")
    
    def create_users_batch(self, users_data):
        """批量创建用户"""
        for user in users_data:
            user_body = {
                'primaryEmail': user['email'],
                'name': {
                    'givenName': user['firstName'],
                    'familyName': user['lastName']
                },
                'password': user['password'],
                'orgUnitPath': user['orgUnit'],
                'changePasswordAtNextLogin': True
            }
            
            try:
                result = self.admin_service.users().insert(body=user_body).execute()
                print(f"创建用户: {user['email']}")
            except Exception as e:
                print(f"创建用户失败: {e}")
    
    def setup_gmail_filters(self):
        """配置Gmail过滤器"""
        filters = [
            {
                'criteria': {
                    'from': '*@competitor.com'
                },
                'action': {
                    'addLabelIds': ['SPAM']
                }
            },
            {
                'criteria': {
                    'hasAttachment': True,
                    'size': 25000000  # 25MB
                },
                'action': {
                    'addLabelIds': ['Large-Attachments']
                }
            }
        ]
        
        for filter_config in filters:
            try:
                self.gmail_service.users().settings().filters().create(
                    userId='me',
                    body=filter_config
                ).execute()
                print("创建邮件过滤器")
            except Exception as e:
                print(f"创建过滤器失败: {e}")
    
    def configure_security_settings(self):
        """配置安全设置"""
        # 启用2FA
        try:
            self.admin_service.users().update(
                userKey='admin@company.local',
                body={
                    'isEnforcedIn2Sv': True,
                    'isEnrolledIn2Sv': True
                }
            ).execute()
            print("启用两步验证")
        except Exception as e:
            print(f"配置安全设置失败: {e}")

# 使用示例
if __name__ == "__main__":
    workspace = GoogleWorkspaceSetup('credentials.json')
    
    # 创建组织结构
    workspace.create_organizational_units()
    
    # 批量创建用户
    users = [
        {
            'email': 'zhangsan@company.local',
            'firstName': '三',
            'lastName': '张',
            'password': 'TempPass2025!',
            'orgUnit': '/IT'
        },
        {
            'email': 'lisi@company.local',
            'firstName': '四', 
            'lastName': '李',
            'password': 'TempPass2025!',
            'orgUnit': '/Sales'
        }
    ]
    
    workspace.create_users_batch(users)
    workspace.setup_gmail_filters()
    workspace.configure_security_settings()
```

### 2.2 业务应用配置

#### 开源ERP系统配置 (Odoo)
```python
#!/usr/bin/env python3
# Odoo ERP自动化部署脚本

import os
import subprocess
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

class OdooDeployment:
    def __init__(self):
        self.odoo_user = 'odoo'
        self.odoo_password = 'odoo_password_2025'
        self.db_name = 'company_erp'
        self.odoo_version = '16.0'
    
    def install_dependencies(self):
        """安装系统依赖"""
        print("安装系统依赖...")
        
        # 更新系统
        subprocess.run(['apt', 'update'], check=True)
        subprocess.run(['apt', 'upgrade', '-y'], check=True)
        
        # 安装Python和依赖
        packages = [
            'python3', 'python3-pip', 'python3-dev', 'python3-venv',
            'postgresql', 'postgresql-server-dev-all',
            'build-essential', 'wget', 'git',
            'libxml2-dev', 'libxslt1-dev', 'libevent-dev',
            'libsasl2-dev', 'libldap2-dev', 'libpq-dev',
            'libjpeg8-dev', 'liblcms2-dev', 'libblas-dev',
            'libatlas-base-dev', 'libssl-dev', 'libffi-dev',
            'wkhtmltopdf', 'node-less'
        ]
        
        subprocess.run(['apt', 'install', '-y'] + packages, check=True)
        print("系统依赖安装完成")
    
    def create_odoo_user(self):
        """创建Odoo系统用户"""
        print("创建Odoo用户...")
        
        try:
            subprocess.run(['adduser', '--system', '--home=/opt/odoo', '--shell=/bin/bash', '--group', self.odoo_user], check=True)
            print("Odoo用户创建成功")
        except subprocess.CalledProcessError:
            print("Odoo用户已存在")
    
    def setup_postgresql(self):
        """配置PostgreSQL数据库"""
        print("配置PostgreSQL...")
        
        # 启动PostgreSQL
        subprocess.run(['systemctl', 'enable', 'postgresql'], check=True)
        subprocess.run(['systemctl', 'start', 'postgresql'], check=True)
        
        # 创建数据库用户
        try:
            subprocess.run(['sudo', '-u', 'postgres', 'createuser', '-s', self.odoo_user], check=True)
            print("数据库用户创建成功")
        except subprocess.CalledProcessError:
            print("数据库用户已存在")
        
        # 创建数据库
        try:
            conn = psycopg2.connect(host='localhost', user='postgres', password='')
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE {self.db_name} OWNER {self.odoo_user};")
            conn.close()
            print("数据库创建成功")
        except psycopg2.Error as e:
            print(f"数据库创建失败或已存在: {e}")
    
    def install_odoo(self):
        """安装Odoo"""
        print("安装Odoo...")
        
        # 切换到odoo用户目录
        os.chdir('/opt/odoo')
        
        # 下载Odoo源码
        if not os.path.exists('odoo'):
            subprocess.run([
                'git', 'clone', 
                f'https://github.com/odoo/odoo.git',
                '--depth', '1',
                '--branch', self.odoo_version,
                'odoo'
            ], check=True)
        
        # 创建Python虚拟环境
        subprocess.run(['python3', '-m', 'venv', 'odoo-venv'], check=True)
        
        # 安装Python依赖
        subprocess.run([
            '/opt/odoo/odoo-venv/bin/pip', 'install', '-r', 
            '/opt/odoo/odoo/requirements.txt'
        ], check=True)
        
        print("Odoo安装完成")
    
    def configure_odoo(self):
        """配置Odoo"""
        print("配置Odoo...")
        
        config_content = f"""[options]
; 管理员密码
admin_passwd = {self.odoo_password}

; 数据库配置
db_host = localhost
db_port = 5432
db_user = {self.odoo_user}
db_password = False

; 服务器配置
http_port = 8069
http_interface = 0.0.0.0

; 文件路径
addons_path = /opt/odoo/odoo/addons,/opt/odoo/custom-addons
data_dir = /opt/odoo/.local/share/Odoo

; 日志配置
logfile = /var/log/odoo/odoo.log
log_level = info
logrotate = True

; 性能配置
workers = 4
max_cron_threads = 2
limit_memory_soft = 2147483648
limit_memory_hard = 2684354560
limit_time_cpu = 60
limit_time_real = 120

; 安全配置
list_db = False
"""
        
        # 创建配置文件
        os.makedirs('/etc/odoo', exist_ok=True)
        with open('/etc/odoo/odoo.conf', 'w') as f:
            f.write(config_content)
        
        # 创建日志目录
        os.makedirs('/var/log/odoo', exist_ok=True)
        subprocess.run(['chown', '-R', f'{self.odoo_user}:{self.odoo_user}', '/var/log/odoo'], check=True)
        
        # 创建自定义插件目录
        os.makedirs('/opt/odoo/custom-addons', exist_ok=True)
        subprocess.run(['chown', '-R', f'{self.odoo_user}:{self.odoo_user}', '/opt/odoo'], check=True)
        
        print("Odoo配置完成")
    
    def create_systemd_service(self):
        """创建systemd服务"""
        print("创建系统服务...")
        
        service_content = f"""[Unit]
Description=Odoo
Documentation=http://www.odoo.com
Requires=postgresql.service
After=postgresql.service

[Service]
Type=notify
User={self.odoo_user}
ExecStart=/opt/odoo/odoo-venv/bin/python /opt/odoo/odoo/odoo-bin -c /etc/odoo/odoo.conf
KillMode=mixed
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
        
        with open('/etc/systemd/system/odoo.service', 'w') as f:
            f.write(service_content)
        
        # 启用并启动服务
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'odoo'], check=True)
        subprocess.run(['systemctl', 'start', 'odoo'], check=True)
        
        print("Odoo服务创建并启动完成")
    
    def install_chinese_modules(self):
        """安装中文模块"""
        print("配置中文环境...")
        
        # 生成中文locale
        subprocess.run(['locale-gen', 'zh_CN.UTF-8'], check=True)
        
        # 下载中文会计科目表等本地化模块
        chinese_modules_url = "https://github.com/odoo/odoo/tree/16.0/addons/l10n_cn"
        print(f"请手动下载中文本地化模块: {chinese_modules_url}")
        
        print("中文环境配置完成")
    
    def deploy(self):
        """执行完整部署"""
        print("开始Odoo ERP部署...")
        
        self.install_dependencies()
        self.create_odoo_user()
        self.setup_postgresql()
        self.install_odoo()
        self.configure_odoo()
        self.create_systemd_service()
        self.install_chinese_modules()
        
        print("Odoo ERP部署完成！")
        print(f"访问地址: http://localhost:8069")
        print(f"管理员密码: {self.odoo_password}")
        print(f"数据库名: {self.db_name}")

# 使用示例
if __name__ == "__main__":
    deployment = OdooDeployment()
    deployment.deploy()
```

#### CRM系统配置 (SuiteCRM)
```bash
#!/bin/bash
# SuiteCRM开源CRM部署脚本

# 1. 环境准备
prepare_environment() {
    echo "准备SuiteCRM环境..."
    
    # 安装LAMP环境
    apt update
    apt install -y apache2 mysql-server php8.1 php8.1-mysql php8.1-curl php8.1-gd php8.1-json php8.1-mbstring php8.1-xml php8.1-zip php8.1-imap
    
    # 启用Apache模块
    a2enmod rewrite
    systemctl restart apache2
    
    echo "环境准备完成"
}

# 2. 数据库配置
setup_database() {
    echo "配置MySQL数据库..."
    
    # 安全配置MySQL
    mysql_secure_installation
    
    # 创建数据库和用户
    mysql -u root -p << EOF
CREATE DATABASE suitecrm CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'suitecrm'@'localhost' IDENTIFIED BY 'suitecrm_password_2025';
GRANT ALL PRIVILEGES ON suitecrm.* TO 'suitecrm'@'localhost';
FLUSH PRIVILEGES;
EXIT;
EOF
    
    echo "数据库配置完成"
}

# 3. 下载和安装SuiteCRM
install_suitecrm() {
    echo "安装SuiteCRM..."
    
    # 下载最新版本
    cd /tmp
    wget https://suitecrm.com/files/160/SuiteCRM-7.14/499/SuiteCRM-7.14.2.zip
    unzip SuiteCRM-7.14.2.zip
    
    # 移动到web目录
    mv SuiteCRM-7.14.2 /var/www/html/suitecrm
    chown -R www-data:www-data /var/www/html/suitecrm
    chmod -R 755 /var/www/html/suitecrm
    
    # 设置特殊权限
    chmod -R 775 /var/www/html/suitecrm/cache
    chmod -R 775 /var/www/html/suitecrm/custom
    chmod -R 775 /var/www/html/suitecrm/modules
    chmod -R 775 /var/www/html/suitecrm/themes
    chmod -R 775 /var/www/html/suitecrm/data
    chmod -R 775 /var/www/html/suitecrm/upload
    
    echo "SuiteCRM安装完成"
}

# 4. Apache虚拟主机配置
configure_apache() {
    echo "配置Apache虚拟主机..."
    
    cat > /etc/apache2/sites-available/suitecrm.conf << EOF
<VirtualHost *:80>
    DocumentRoot /var/www/html/suitecrm
    ServerName crm.company.local
    
    <Directory /var/www/html/suitecrm>
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/suitecrm_error.log
    CustomLog \${APACHE_LOG_DIR}/suitecrm_access.log combined
</VirtualHost>
EOF
    
    # 启用站点
    a2ensite suitecrm.conf
    a2dissite 000-default.conf
    systemctl reload apache2
    
    echo "Apache配置完成"
}

# 5. PHP配置优化
optimize_php() {
    echo "优化PHP配置..."
    
    # 修改php.ini
    sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' /etc/php/8.1/apache2/php.ini
    sed -i 's/post_max_size = 8M/post_max_size = 64M/' /etc/php/8.1/apache2/php.ini
    sed -i 's/max_execution_time = 30/max_execution_time = 300/' /etc/php/8.1/apache2/php.ini
    sed -i 's/memory_limit = 128M/memory_limit = 256M/' /etc/php/8.1/apache2/php.ini
    
    # 重启Apache
    systemctl restart apache2
    
    echo "PHP配置优化完成"
}

# 6. 安全配置
secure_installation() {
    echo "安全配置..."
    
    # 设置文件权限
    find /var/www/html/suitecrm -type f -exec chmod 644 {} \;
    find /var/www/html/suitecrm -type d -exec chmod 755 {} \;
    
    # 保护配置文件
    chmod 600 /var/www/html/suitecrm/config.php
    
    # 禁用危险函数
    sed -i 's/;disable_functions =/disable_functions = exec,passthru,shell_exec,system,proc_open,popen/' /etc/php/8.1/apache2/php.ini
    
    systemctl restart apache2
    
    echo "安全配置完成"
}

# 执行安装
prepare_environment
setup_database
install_suitecrm
configure_apache
optimize_php
secure_installation

echo "SuiteCRM安装完成！"
echo "访问地址: http://crm.company.local"
echo "数据库信息:"
echo "  主机: localhost"
echo "  数据库: suitecrm"
echo "  用户: suitecrm"
echo "  密码: suitecrm_password_2025"
```

## 3. 监控系统配置

### 3.1 Zabbix监控系统配置

#### Zabbix Server安装配置
```bash
#!/bin/bash
# Zabbix 6.0 监控系统部署脚本

# 1. 安装Zabbix仓库
install_zabbix_repo() {
    echo "安装Zabbix仓库..."
    
    # 下载仓库包
    wget https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu22.04_all.deb
    dpkg -i zabbix-release_6.0-4+ubuntu22.04_all.deb
    apt update
    
    echo "Zabbix仓库安装完成"
}

# 2. 安装Zabbix组件
install_zabbix_components() {
    echo "安装Zabbix组件..."
    
    # 安装Zabbix server, frontend, agent
    apt install -y zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent
    
    echo "Zabbix组件安装完成"
}

# 3. 配置MySQL数据库
setup_zabbix_database() {
    echo "配置Zabbix数据库..."
    
    # 创建数据库
    mysql -u root -p << EOF
CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'zabbix_password_2025';
GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
SET GLOBAL log_bin_trust_function_creators = 1;
FLUSH PRIVILEGES;
EOF
    
    # 导入初始数据
    zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -u zabbix -p zabbix
    
    # 禁用log_bin_trust_function_creators
    mysql -u root -p << EOF
SET GLOBAL log_bin_trust_function_creators = 0;
EOF
    
    echo "数据库配置完成"
}

# 4. 配置Zabbix Server
configure_zabbix_server() {
    echo "配置Zabbix Server..."
    
    # 修改配置文件
    sed -i 's/# DBPassword=/DBPassword=zabbix_password_2025/' /etc/zabbix/zabbix_server.conf
    
    # 配置PHP时区
    sed -i 's/# php_value date.timezone Europe\/Riga/php_value date.timezone Asia\/Shanghai/' /etc/zabbix/apache.conf
    
    echo "Zabbix Server配置完成"
}

# 5. 启动服务
start_zabbix_services() {
    echo "启动Zabbix服务..."
    
    # 重启服务
    systemctl restart zabbix-server zabbix-agent apache2
    systemctl enable zabbix-server zabbix-agent apache2
    
    echo "Zabbix服务启动完成"
}

# 6. 配置监控模板
configure_monitoring_templates() {
    echo "配置监控模板..."
    
    # 创建自定义脚本目录
    mkdir -p /usr/lib/zabbix/externalscripts
    chown zabbix:zabbix /usr/lib/zabbix/externalscripts
    
    # 网络设备监控脚本
    cat > /usr/lib/zabbix/externalscripts/check_network_device.sh << 'EOF'
#!/bin/bash
# 网络设备监控脚本

HOST=$1
COMMUNITY=$2
OID=$3

if [ $# -ne 3 ]; then
    echo "Usage: $0 <host> <community> <oid>"
    exit 1
fi

snmpget -v2c -c $COMMUNITY $HOST $OID | awk '{print $4}'
EOF
    
    chmod +x /usr/lib/zabbix/externalscripts/check_network_device.sh
    
    echo "监控模板配置完成"
}

# 执行安装
install_zabbix_repo
install_zabbix_components  
setup_zabbix_database
configure_zabbix_server
start_zabbix_services
configure_monitoring_templates

echo "Zabbix安装完成！"
echo "访问地址: http://localhost/zabbix"
echo "默认用户: Admin"
echo "默认密码: zabbix"
echo "请立即更改默认密码！"
```

#### Grafana可视化配置
```bash
#!/bin/bash
# Grafana安装配置脚本

# 1. 安装Grafana
install_grafana() {
    echo "安装Grafana..."
    
    # 添加GPG密钥
    wget -q -O - https://packages.grafana.com/gpg.key | apt-key add -
    
    # 添加仓库
    echo "deb https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
    
    # 安装
    apt update
    apt install -y grafana
    
    # 启动服务
    systemctl enable grafana-server
    systemctl start grafana-server
    
    echo "Grafana安装完成"
}

# 2. 配置Grafana
configure_grafana() {
    echo "配置Grafana..."
    
    # 修改配置文件
    cat >> /etc/grafana/grafana.ini << EOF
[server]
http_port = 3000
domain = monitoring.company.local

[security]
admin_user = admin
admin_password = grafana_admin_2025

[users]
allow_sign_up = false
default_theme = dark

[auth.anonymous]
enabled = false

[smtp]
enabled = true
host = smtp.company.local:587
user = noreply@company.local
password = smtp_password
from_address = noreply@company.local
from_name = Grafana
EOF
    
    # 重启服务
    systemctl restart grafana-server
    
    echo "Grafana配置完成"
}

# 3. 安装插件
install_grafana_plugins() {
    echo "安装Grafana插件..."
    
    # 安装常用插件
    grafana-cli plugins install grafana-clock-panel
    grafana-cli plugins install grafana-piechart-panel
    grafana-cli plugins install grafana-worldmap-panel
    grafana-cli plugins install alexanderzobnin-zabbix-app
    
    # 重启服务
    systemctl restart grafana-server
    
    echo "插件安装完成"
}

# 执行安装
install_grafana
configure_grafana
install_grafana_plugins

echo "Grafana安装完成！"
echo "访问地址: http://localhost:3000"
echo "用户名: admin"
echo "密码: grafana_admin_2025"
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*适用规模：50-100人中小企业*  
*负责人：系统配置团队*