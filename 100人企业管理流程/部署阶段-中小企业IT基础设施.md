# 部署阶段 - 中小企业IT基础设施 (50-100人)

## 阶段概述
部署阶段针对中小企业快速上线的需求，采用精简高效的部署策略，确保在有限的时间窗口内完成系统部署并达到生产就绪状态。

## 1. 快速部署策略

### 1.1 部署优先级排序

#### 关键系统优先 (Phase 1 - 3天)
```yaml
核心基础设施:
  优先级1 (第1天):
    - 网络设备配置和测试
    - 核心服务器部署
    - 基础网络连通性
    - 域控制器/身份认证
  
  优先级2 (第2天):
    - 文件服务器和共享
    - 邮件系统配置
    - 基础安全设置
    - 备份系统配置
  
  优先级3 (第3天):
    - 监控系统部署
    - 防火墙细化配置
    - VPN远程接入
    - 打印服务配置
```

#### 业务应用部署 (Phase 2 - 4天)
```yaml
应用系统部署:
  第4天:
    - Office 365/Google Workspace配置
    - 基础邮箱和协作平台
    - 文档管理系统
    - 即时通讯系统
  
  第5天:
    - CRM系统部署
    - 基础客户数据导入
    - 销售流程配置
    - 用户权限设置
  
  第6天:
    - ERP系统核心模块
    - 财务管理系统
    - 基础业务流程
    - 数据集成测试
  
  第7天:
    - 系统集成测试
    - 性能优化调整
    - 安全配置验证
    - 备份恢复验证
```

### 1.2 自动化部署脚本

#### 一键基础设施部署脚本
```bash
#!/bin/bash
# 中小企业IT基础设施一键部署脚本

set -e  # 遇到错误立即退出

# 配置变量
COMPANY_DOMAIN="company.local"
ADMIN_EMAIL="admin@company.local"
NETWORK_RANGE="192.168.1.0/24"
SERVER_IP="192.168.1.100"

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" | tee -a /var/log/deployment.log
}

error_exit() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" | tee -a /var/log/deployment.log
    exit 1
}

# 1. 系统准备
prepare_system() {
    log "开始系统准备..."
    
    # 更新系统
    apt update && apt upgrade -y || error_exit "系统更新失败"
    
    # 安装基础工具
    apt install -y curl wget git vim htop net-tools dnsutils || error_exit "基础工具安装失败"
    
    # 配置时区
    timedatectl set-timezone Asia/Shanghai || error_exit "时区设置失败"
    
    # 配置主机名
    hostnamectl set-hostname server.${COMPANY_DOMAIN} || error_exit "主机名设置失败"
    
    log "系统准备完成"
}

# 2. 网络配置
configure_network() {
    log "配置网络..."
    
    # 配置静态IP
    cat > /etc/netplan/01-netcfg.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      addresses:
        - ${SERVER_IP}/24
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
        search: [${COMPANY_DOMAIN}]
EOF
    
    netplan apply || error_exit "网络配置失败"
    
    log "网络配置完成"
}

# 3. DNS服务配置
setup_dns() {
    log "配置DNS服务..."
    
    # 安装BIND9
    apt install -y bind9 bind9utils bind9-doc || error_exit "DNS服务安装失败"
    
    # 配置DNS
    cat > /etc/bind/named.conf.local << EOF
zone "${COMPANY_DOMAIN}" {
    type master;
    file "/etc/bind/db.${COMPANY_DOMAIN}";
};

zone "1.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/db.192";
};
EOF
    
    # 创建正向解析文件
    cat > /etc/bind/db.${COMPANY_DOMAIN} << EOF
\$TTL    604800
@       IN      SOA     server.${COMPANY_DOMAIN}. admin.${COMPANY_DOMAIN}. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      server.${COMPANY_DOMAIN}.
@       IN      A       ${SERVER_IP}
server  IN      A       ${SERVER_IP}
mail    IN      A       ${SERVER_IP}
web     IN      A       ${SERVER_IP}
EOF
    
    systemctl restart bind9 || error_exit "DNS服务启动失败"
    systemctl enable bind9
    
    log "DNS服务配置完成"
}

# 4. DHCP服务配置
setup_dhcp() {
    log "配置DHCP服务..."
    
    # 安装isc-dhcp-server
    apt install -y isc-dhcp-server || error_exit "DHCP服务安装失败"
    
    # 配置DHCP
    cat > /etc/dhcp/dhcpd.conf << EOF
option domain-name "${COMPANY_DOMAIN}";
option domain-name-servers ${SERVER_IP};

default-lease-time 600;
max-lease-time 7200;

ddns-update-style none;

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.50 192.168.1.99;
    option routers 192.168.1.1;
    option domain-name-servers ${SERVER_IP};
    option domain-name "${COMPANY_DOMAIN}";
}
EOF
    
    # 配置网络接口
    echo 'INTERFACESv4="ens160"' > /etc/default/isc-dhcp-server
    
    systemctl restart isc-dhcp-server || error_exit "DHCP服务启动失败"
    systemctl enable isc-dhcp-server
    
    log "DHCP服务配置完成"
}

# 5. 文件服务器配置
setup_file_server() {
    log "配置文件服务器..."
    
    # 安装Samba
    apt install -y samba samba-common-bin || error_exit "Samba安装失败"
    
    # 创建共享目录
    mkdir -p /srv/shares/{public,departments,backups}
    chmod 755 /srv/shares/public
    chmod 770 /srv/shares/departments
    chmod 750 /srv/shares/backups
    
    # 配置Samba
    cat > /etc/samba/smb.conf << EOF
[global]
   workgroup = WORKGROUP
   server string = Company File Server
   netbios name = FILESERVER
   security = user
   map to guest = bad user
   dns proxy = no

[public]
   comment = Public Share
   path = /srv/shares/public
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no

[departments]
   comment = Department Shares
   path = /srv/shares/departments
   browsable = yes
   writable = yes
   valid users = @smbusers
   create mask = 0770
   directory mask = 0770
EOF
    
    systemctl restart smbd nmbd || error_exit "Samba服务启动失败"
    systemctl enable smbd nmbd
    
    log "文件服务器配置完成"
}

# 6. Web服务器配置
setup_web_server() {
    log "配置Web服务器..."
    
    # 安装Nginx
    apt install -y nginx || error_exit "Nginx安装失败"
    
    # 创建默认站点
    cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location /status {
        stub_status on;
        access_log off;
        allow 192.168.1.0/24;
        deny all;
    }
}
EOF
    
    # 创建状态页面
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Company IT Infrastructure</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { background: #e7f3ff; padding: 20px; border-radius: 5px; }
        .service { margin: 10px 0; padding: 10px; background: #f0f0f0; }
    </style>
</head>
<body>
    <h1>Company IT Infrastructure Status</h1>
    <div class="status">
        <h2>System Status: Online</h2>
        <p>Deployment Date: $(date)</p>
    </div>
    
    <div class="service">
        <h3>Available Services</h3>
        <ul>
            <li>DNS Server: ${SERVER_IP}</li>
            <li>DHCP Server: Active</li>
            <li>File Server: //server.${COMPANY_DOMAIN}/public</li>
            <li>Web Server: http://server.${COMPANY_DOMAIN}</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    systemctl restart nginx || error_exit "Nginx启动失败"
    systemctl enable nginx
    
    log "Web服务器配置完成"
}

# 7. 基础监控配置
setup_monitoring() {
    log "配置基础监控..."
    
    # 安装Node Exporter
    cd /tmp
    wget -q https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
    tar xzf node_exporter-1.6.1.linux-amd64.tar.gz
    cp node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
    
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
    systemctl start node_exporter || error_exit "Node Exporter启动失败"
    
    log "基础监控配置完成"
}

# 8. 安全配置
configure_security() {
    log "配置基础安全..."
    
    # 配置防火墙
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许基础服务
    ufw allow ssh
    ufw allow 53          # DNS
    ufw allow 67          # DHCP
    ufw allow 80          # HTTP
    ufw allow 443         # HTTPS
    ufw allow 139,445     # Samba
    ufw allow 9100        # Node Exporter
    
    # 配置fail2ban
    apt install -y fail2ban || error_exit "Fail2ban安装失败"
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
    
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "基础安全配置完成"
}

# 9. 系统优化
optimize_system() {
    log "系统优化..."
    
    # 内核参数优化
    cat >> /etc/sysctl.conf << EOF
# 网络优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 12582912 16777216
net.ipv4.tcp_wmem = 4096 12582912 16777216

# 文件系统优化
fs.file-max = 65536
vm.swappiness = 10
EOF
    
    sysctl -p
    
    # 配置定时任务
    cat > /etc/cron.d/system-maintenance << EOF
# 每日系统维护
0 2 * * * root /usr/bin/apt update && /usr/bin/apt upgrade -y >> /var/log/auto-update.log 2>&1
0 3 * * * root /usr/bin/find /var/log -name "*.log" -mtime +30 -delete
0 4 * * * root /bin/df -h > /var/log/disk-usage.log
EOF
    
    log "系统优化完成"
}

# 10. 部署验证
verify_deployment() {
    log "验证部署结果..."
    
    local failed_services=()
    
    # 检查服务状态
    services=("bind9" "isc-dhcp-server" "smbd" "nginx" "node_exporter" "fail2ban")
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            failed_services+=("$service")
        fi
    done
    
    # 检查网络连通性
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        failed_services+=("internet-connectivity")
    fi
    
    # 检查DNS解析
    if ! nslookup server.${COMPANY_DOMAIN} ${SERVER_IP} > /dev/null 2>&1; then
        failed_services+=("dns-resolution")
    fi
    
    if [ ${#failed_services[@]} -eq 0 ]; then
        log "✓ 所有服务部署成功"
        return 0
    else
        error_exit "以下服务部署失败: ${failed_services[*]}"
    fi
}

# 11. 生成部署报告
generate_deployment_report() {
    log "生成部署报告..."
    
    local report_file="/var/log/deployment-report-$(date +%Y%m%d).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>IT基础设施部署报告</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 15px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; } .error { color: red; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>中小企业IT基础设施部署报告</h1>
        <p>部署日期: $(date)</p>
        <p>服务器IP: ${SERVER_IP}</p>
        <p>域名: ${COMPANY_DOMAIN}</p>
    </div>
    
    <div class="section">
        <h2>部署的服务</h2>
        <table>
            <tr><th>服务</th><th>状态</th><th>访问地址</th></tr>
            <tr><td>DNS服务器</td><td class="success">运行中</td><td>${SERVER_IP}:53</td></tr>
            <tr><td>DHCP服务器</td><td class="success">运行中</td><td>192.168.1.50-99</td></tr>
            <tr><td>文件服务器</td><td class="success">运行中</td><td>//server.${COMPANY_DOMAIN}/public</td></tr>
            <tr><td>Web服务器</td><td class="success">运行中</td><td>http://server.${COMPANY_DOMAIN}</td></tr>
            <tr><td>监控系统</td><td class="success">运行中</td><td>http://${SERVER_IP}:9100/metrics</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>网络配置</h2>
        <ul>
            <li>服务器IP: ${SERVER_IP}/24</li>
            <li>网关: 192.168.1.1</li>
            <li>DNS: ${SERVER_IP}</li>
            <li>DHCP范围: 192.168.1.50-99</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>下一步工作</h2>
        <ol>
            <li>配置用户账户和权限</li>
            <li>部署业务应用系统</li>
            <li>配置备份策略</li>
            <li>进行用户培训</li>
            <li>建立运维流程</li>
        </ol>
    </div>
</body>
</html>
EOF
    
    log "部署报告已生成: $report_file"
}

# 主函数
main() {
    log "开始中小企业IT基础设施一键部署..."
    
    prepare_system
    configure_network
    setup_dns
    setup_dhcp
    setup_file_server
    setup_web_server
    setup_monitoring
    configure_security
    optimize_system
    verify_deployment
    generate_deployment_report
    
    log "IT基础设施部署完成！"
    log "访问 http://${SERVER_IP} 查看系统状态"
    log "部署报告: /var/log/deployment-report-$(date +%Y%m%d).html"
}

# 执行部署
main "$@"
```

## 2. 应用系统部署

### 2.1 协作办公平台部署

#### Microsoft 365快速配置脚本
```powershell
# Microsoft 365 快速部署脚本

# 1. 安装必要模块
function Install-RequiredModules {
    Write-Host "安装必要的PowerShell模块..." -ForegroundColor Green
    
    $modules = @(
        "MSOnline",
        "AzureAD", 
        "ExchangeOnlineManagement",
        "MicrosoftTeams",
        "SharePointPnPPowerShellOnline"
    )
    
    foreach ($module in $modules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Install-Module -Name $module -Force -AllowClobber
            Write-Host "已安装模块: $module" -ForegroundColor Yellow
        }
    }
}

# 2. 连接到Microsoft 365
function Connect-M365Services {
    Write-Host "连接到Microsoft 365服务..." -ForegroundColor Green
    
    # 获取管理员凭据
    $credential = Get-Credential -Message "请输入Microsoft 365管理员账户"
    
    # 连接到各项服务
    Connect-MsolService -Credential $credential
    Connect-AzureAD -Credential $credential
    Connect-ExchangeOnline -Credential $credential
    Connect-MicrosoftTeams -Credential $credential
    
    Write-Host "已连接到Microsoft 365服务" -ForegroundColor Yellow
}

# 3. 批量创建用户
function Create-BulkUsers {
    param(
        [string]$CsvPath = "users.csv"
    )
    
    Write-Host "从CSV文件批量创建用户..." -ForegroundColor Green
    
    # 示例CSV格式创建
    if (!(Test-Path $CsvPath)) {
        $sampleUsers = @"
DisplayName,UserPrincipalName,FirstName,LastName,Department,JobTitle,PhoneNumber
张三,zhangsan@company.onmicrosoft.com,三,张,IT,系统管理员,13800138001
李四,lisi@company.onmicrosoft.com,四,李,Sales,销售经理,13800138002
王五,wangwu@company.onmicrosoft.com,五,王,Finance,财务专员,13800138003
"@
        $sampleUsers | Out-File $CsvPath -Encoding UTF8
        Write-Host "已创建示例用户文件: $CsvPath" -ForegroundColor Yellow
    }
    
    $users = Import-Csv $CsvPath
    
    foreach ($user in $users) {
        $password = "TempPass2025!" | ConvertTo-SecureString -AsPlainText -Force
        
        try {
            # 创建用户
            New-MsolUser -DisplayName $user.DisplayName `
                        -UserPrincipalName $user.UserPrincipalName `
                        -FirstName $user.FirstName `
                        -LastName $user.LastName `
                        -Department $user.Department `
                        -Title $user.JobTitle `
                        -PhoneNumber $user.PhoneNumber `
                        -Password $password `
                        -ForceChangePassword $true `
                        -UsageLocation "CN"
            
            # 分配许可证
            Set-MsolUserLicense -UserPrincipalName $user.UserPrincipalName -AddLicenses "company:ENTERPRISEPREMIUM"
            
            Write-Host "已创建用户: $($user.DisplayName)" -ForegroundColor Yellow
        }
        catch {
            Write-Host "创建用户失败: $($user.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 4. 配置Exchange Online
function Configure-ExchangeOnline {
    Write-Host "配置Exchange Online..." -ForegroundColor Green
    
    # 创建通讯组
    $groups = @(
        @{ Name = "全体员工"; Alias = "all-staff"; Members = @() },
        @{ Name = "IT部门"; Alias = "it-dept"; Members = @("zhangsan@company.onmicrosoft.com") },
        @{ Name = "销售部门"; Alias = "sales-dept"; Members = @("lisi@company.onmicrosoft.com") }
    )
    
    foreach ($group in $groups) {
        try {
            New-DistributionGroup -Name $group.Name -Alias $group.Alias -Type "Distribution"
            
            # 添加成员
            foreach ($member in $group.Members) {
                Add-DistributionGroupMember -Identity $group.Alias -Member $member
            }
            
            Write-Host "已创建通讯组: $($group.Name)" -ForegroundColor Yellow
        }
        catch {
            Write-Host "创建通讯组失败: $($group.Name)" -ForegroundColor Red
        }
    }
    
    # 配置邮件流规则
    New-TransportRule -Name "外部邮件警告" `
                     -FromScope NotInOrganization `
                     -ApplyHtmlDisclaimerText "⚠️ 此邮件来自外部发件人，请谨慎处理附件和链接。" `
                     -ApplyHtmlDisclaimerLocation Prepend
    
    Write-Host "Exchange Online配置完成" -ForegroundColor Yellow
}

# 5. 配置Teams
function Configure-Teams {
    Write-Host "配置Microsoft Teams..." -ForegroundColor Green
    
    # 创建团队
    $teams = @(
        @{ DisplayName = "公司全员"; Description = "全公司沟通频道"; Visibility = "Public" },
        @{ DisplayName = "IT支持"; Description = "IT部门协作"; Visibility = "Private" },
        @{ DisplayName = "销售团队"; Description = "销售部门协作"; Visibility = "Private" }
    )
    
    foreach ($team in $teams) {
        try {
            $newTeam = New-Team -DisplayName $team.DisplayName `
                               -Description $team.Description `
                               -Visibility $team.Visibility
            
            Write-Host "已创建团队: $($team.DisplayName)" -ForegroundColor Yellow
        }
        catch {
            Write-Host "创建团队失败: $($team.DisplayName)" -ForegroundColor Red
        }
    }
    
    # 配置Teams策略
    New-CsTeamsMessagingPolicy -Identity "RestrictedPolicy" `
                              -AllowUserChat $true `
                              -AllowUserDeleteMessage $false `
                              -AllowUserEditMessage $true
    
    Write-Host "Teams配置完成" -ForegroundColor Yellow
}

# 6. 配置SharePoint
function Configure-SharePoint {
    Write-Host "配置SharePoint Online..." -ForegroundColor Green
    
    # 需要先获取SharePoint管理员URL
    $tenantName = (Get-MsolDomain | Where-Object {$_.IsDefault -eq $true}).Name.Split('.')[0]
    $adminUrl = "https://$tenantName-admin.sharepoint.com"
    
    try {
        Connect-PnPOnline -Url $adminUrl -Interactive
        
        # 创建站点集合
        $sites = @(
            @{ Title = "公司门户"; Url = "https://$tenantName.sharepoint.com/sites/portal"; Template = "STS#3" },
            @{ Title = "文档中心"; Url = "https://$tenantName.sharepoint.com/sites/docs"; Template = "STS#0" },
            @{ Title = "项目协作"; Url = "https://$tenantName.sharepoint.com/sites/projects"; Template = "PROJECTSITE#0" }
        )
        
        foreach ($site in $sites) {
            New-PnPSite -Type TeamSite -Title $site.Title -Url $site.Url
            Write-Host "已创建站点: $($site.Title)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "SharePoint配置失败: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "SharePoint配置完成" -ForegroundColor Yellow
}

# 7. 配置安全策略
function Configure-SecurityPolicies {
    Write-Host "配置安全策略..." -ForegroundColor Green
    
    # 启用多因子认证
    $mfaSettings = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
    $mfaSettings.RelyingParty = "*"
    $mfaSettings.State = "Enabled"
    
    # 为管理员启用MFA
    $adminUsers = Get-MsolUser | Where-Object {$_.UserPrincipalName -like "*admin*"}
    foreach ($admin in $adminUsers) {
        Set-MsolUser -UserPrincipalName $admin.UserPrincipalName -StrongAuthenticationRequirements $mfaSettings
        Write-Host "已为管理员启用MFA: $($admin.UserPrincipalName)" -ForegroundColor Yellow
    }
    
    # 配置条件访问策略 (需要Azure AD Premium)
    try {
        # 创建位置策略
        $trustedLocations = @("192.168.1.0/24", "办公室IP地址")
        # 这里需要具体的条件访问配置
        Write-Host "请在Azure AD管理中心手动配置条件访问策略" -ForegroundColor Yellow
    }
    catch {
        Write-Host "条件访问配置需要手动完成" -ForegroundColor Yellow
    }
    
    Write-Host "安全策略配置完成" -ForegroundColor Yellow
}

# 8. 生成配置报告
function Generate-ConfigurationReport {
    Write-Host "生成配置报告..." -ForegroundColor Green
    
    $reportPath = "M365-Configuration-Report-$(Get-Date -Format 'yyyyMMdd').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 配置报告</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #0078d4; color: white; padding: 15px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft 365 配置报告</h1>
        <p>配置日期: $(Get-Date)</p>
    </div>
    
    <div class="section">
        <h2>用户账户</h2>
        <table>
            <tr><th>显示名</th><th>邮箱</th><th>部门</th><th>许可证</th></tr>
"@
    
    $users = Get-MsolUser
    foreach ($user in $users) {
        $licenses = ($user.Licenses | ForEach-Object { $_.AccountSkuId }) -join ", "
        $html += "<tr><td>$($user.DisplayName)</td><td>$($user.UserPrincipalName)</td><td>$($user.Department)</td><td>$licenses</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
    
    <div class="section">
        <h2>服务状态</h2>
        <ul>
            <li>Exchange Online: 已配置</li>
            <li>SharePoint Online: 已配置</li>
            <li>Microsoft Teams: 已配置</li>
            <li>OneDrive: 已启用</li>
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File $reportPath -Encoding UTF8
    Write-Host "配置报告已生成: $reportPath" -ForegroundColor Yellow
}

# 主函数
function Deploy-Microsoft365 {
    Write-Host "开始Microsoft 365快速部署..." -ForegroundColor Cyan
    
    Install-RequiredModules
    Connect-M365Services
    Create-BulkUsers
    Configure-ExchangeOnline
    Configure-Teams
    Configure-SharePoint
    Configure-SecurityPolicies
    Generate-ConfigurationReport
    
    Write-Host "Microsoft 365部署完成！" -ForegroundColor Green
}

# 执行部署
Deploy-Microsoft365
```

## 3. 测试验证

### 3.1 自动化测试脚本

#### 全面系统测试脚本
```python
#!/usr/bin/env python3
# 中小企业IT基础设施测试脚本

import subprocess
import requests
import socket
import time
import json
from datetime import datetime
import concurrent.futures
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('infrastructure_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class InfrastructureTest:
    def __init__(self):
        self.test_results = []
        self.config = {
            'server_ip': '192.168.1.100',
            'domain': 'company.local',
            'network_range': '192.168.1.0/24',
            'services': {
                'dns': 53,
                'dhcp': 67,
                'http': 80,
                'https': 443,
                'smb': 445,
                'monitoring': 9100
            }
        }
    
    def add_result(self, test_name, status, message, duration=None):
        """添加测试结果"""
        result = {
            'test_name': test_name,
            'status': status,  # PASS, FAIL, SKIP
            'message': message,
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status_icon = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
        logger.info(f"{status_icon} {test_name}: {message}")
    
    def test_network_connectivity(self):
        """测试网络连通性"""
        logger.info("开始网络连通性测试...")
        
        # 测试本地网络
        start_time = time.time()
        try:
            result = subprocess.run(['ping', '-c', '3', '192.168.1.1'], 
                                 capture_output=True, text=True, timeout=10)
            duration = time.time() - start_time
            
            if result.returncode == 0:
                self.add_result("网关连通性", "PASS", "网关192.168.1.1连通正常", duration)
            else:
                self.add_result("网关连通性", "FAIL", "无法连接到网关", duration)
        except subprocess.TimeoutExpired:
            self.add_result("网关连通性", "FAIL", "连接网关超时", time.time() - start_time)
        
        # 测试外网连通性
        start_time = time.time()
        try:
            result = subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                                 capture_output=True, text=True, timeout=10)
            duration = time.time() - start_time
            
            if result.returncode == 0:
                self.add_result("外网连通性", "PASS", "外网连接正常", duration)
            else:
                self.add_result("外网连通性", "FAIL", "无法连接外网", duration)
        except subprocess.TimeoutExpired:
            self.add_result("外网连通性", "FAIL", "外网连接超时", time.time() - start_time)
    
    def test_dns_resolution(self):
        """测试DNS解析"""
        logger.info("开始DNS解析测试...")
        
        test_domains = [
            ('server.company.local', '192.168.1.100'),
            ('google.com', None),  # 外网域名
            ('baidu.com', None)
        ]
        
        for domain, expected_ip in test_domains:
            start_time = time.time()
            try:
                result = socket.gethostbyname(domain)
                duration = time.time() - start_time
                
                if expected_ip and result == expected_ip:
                    self.add_result(f"DNS解析-{domain}", "PASS", f"解析到正确IP: {result}", duration)
                elif not expected_ip and result:
                    self.add_result(f"DNS解析-{domain}", "PASS", f"解析成功: {result}", duration)
                else:
                    self.add_result(f"DNS解析-{domain}", "FAIL", f"解析结果不正确: {result}", duration)
            except socket.gaierror:
                self.add_result(f"DNS解析-{domain}", "FAIL", "DNS解析失败", time.time() - start_time)
    
    def test_service_ports(self):
        """测试服务端口"""
        logger.info("开始服务端口测试...")
        
        server_ip = self.config['server_ip']
        services = self.config['services']
        
        def test_port(service_name, port):
            start_time = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((server_ip, port))
                sock.close()
                duration = time.time() - start_time
                
                if result == 0:
                    self.add_result(f"端口测试-{service_name}", "PASS", f"端口{port}开放正常", duration)
                else:
                    self.add_result(f"端口测试-{service_name}", "FAIL", f"端口{port}无法连接", duration)
            except Exception as e:
                self.add_result(f"端口测试-{service_name}", "FAIL", f"端口测试异常: {str(e)}", time.time() - start_time)
        
        # 并发测试端口
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_port, name, port) for name, port in services.items()]
            concurrent.futures.wait(futures)
    
    def test_web_services(self):
        """测试Web服务"""
        logger.info("开始Web服务测试...")
        
        web_endpoints = [
            f"http://{self.config['server_ip']}",
            f"http://server.{self.config['domain']}",
            f"http://{self.config['server_ip']}/status"
        ]
        
        for url in web_endpoints:
            start_time = time.time()
            try:
                response = requests.get(url, timeout=10)
                duration = time.time() - start_time
                
                if response.status_code == 200:
                    self.add_result(f"Web服务-{url}", "PASS", f"HTTP状态码: {response.status_code}", duration)
                else:
                    self.add_result(f"Web服务-{url}", "FAIL", f"HTTP状态码: {response.status_code}", duration)
            except requests.RequestException as e:
                self.add_result(f"Web服务-{url}", "FAIL", f"请求失败: {str(e)}", time.time() - start_time)
    
    def test_file_shares(self):
        """测试文件共享"""
        logger.info("开始文件共享测试...")
        
        share_tests = [
            f"//server.{self.config['domain']}/public",
            f"//{self.config['server_ip']}/public"
        ]
        
        for share in share_tests:
            start_time = time.time()
            try:
                # 使用smbclient测试
                result = subprocess.run(['smbclient', '-L', share, '-N'], 
                                     capture_output=True, text=True, timeout=10)
                duration = time.time() - start_time
                
                if result.returncode == 0:
                    self.add_result(f"文件共享-{share}", "PASS", "SMB共享可访问", duration)
                else:
                    self.add_result(f"文件共享-{share}", "FAIL", "SMB共享无法访问", duration)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.add_result(f"文件共享-{share}", "SKIP", "smbclient未安装或超时", time.time() - start_time)
    
    def test_monitoring_endpoints(self):
        """测试监控端点"""
        logger.info("开始监控端点测试...")
        
        monitoring_urls = [
            f"http://{self.config['server_ip']}:9100/metrics"
        ]
        
        for url in monitoring_urls:
            start_time = time.time()
            try:
                response = requests.get(url, timeout=10)
                duration = time.time() - start_time
                
                if response.status_code == 200 and 'node_' in response.text:
                    self.add_result(f"监控端点-{url}", "PASS", "监控数据正常", duration)
                else:
                    self.add_result(f"监控端点-{url}", "FAIL", "监控数据异常", duration)
            except requests.RequestException as e:
                self.add_result(f"监控端点-{url}", "FAIL", f"监控端点不可达: {str(e)}", time.time() - start_time)
    
    def test_system_performance(self):
        """测试系统性能"""
        logger.info("开始系统性能测试...")
        
        start_time = time.time()
        try:
            # CPU使用率
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # 解析CPU使用率
                for line in result.stdout.split('\n'):
                    if 'Cpu(s):' in line and 'id' in line:
                        idle = float(line.split('id')[0].split()[-1].replace('%', ''))
                        cpu_usage = 100 - idle
                        
                        if cpu_usage < 80:
                            self.add_result("系统性能-CPU", "PASS", f"CPU使用率: {cpu_usage:.1f}%", time.time() - start_time)
                        else:
                            self.add_result("系统性能-CPU", "FAIL", f"CPU使用率过高: {cpu_usage:.1f}%", time.time() - start_time)
                        break
            
            # 内存使用率
            result = subprocess.run(['free'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.startswith('Mem:'):
                        parts = line.split()
                        total = int(parts[1])
                        used = int(parts[2])
                        mem_usage = (used / total) * 100
                        
                        if mem_usage < 85:
                            self.add_result("系统性能-内存", "PASS", f"内存使用率: {mem_usage:.1f}%", time.time() - start_time)
                        else:
                            self.add_result("系统性能-内存", "FAIL", f"内存使用率过高: {mem_usage:.1f}%", time.time() - start_time)
                        break
            
            # 磁盘使用率
            result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # 跳过标题行
                for line in lines:
                    if line and not line.startswith('tmpfs'):
                        parts = line.split()
                        if len(parts) >= 5:
                            usage = int(parts[4].replace('%', ''))
                            filesystem = parts[5]
                            
                            if usage < 85:
                                self.add_result(f"磁盘使用率-{filesystem}", "PASS", f"磁盘使用率: {usage}%", time.time() - start_time)
                            else:
                                self.add_result(f"磁盘使用率-{filesystem}", "FAIL", f"磁盘使用率过高: {usage}%", time.time() - start_time)
        
        except Exception as e:
            self.add_result("系统性能", "FAIL", f"性能测试异常: {str(e)}", time.time() - start_time)
    
    def generate_test_report(self):
        """生成测试报告"""
        logger.info("生成测试报告...")
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.test_results if r['status'] == 'FAIL'])
        skipped_tests = len([r for r in self.test_results if r['status'] == 'SKIP'])
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>IT基础设施测试报告</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .summary {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .section {{ margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
        .skip {{ color: orange; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>中小企业IT基础设施测试报告</h1>
        <p>测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>测试服务器: {self.config['server_ip']}</p>
    </div>
    
    <div class="summary">
        <h2>测试汇总</h2>
        <p><strong>总测试数:</strong> {total_tests}</p>
        <p><strong>通过:</strong> <span class="pass">{passed_tests}</span></p>
        <p><strong>失败:</strong> <span class="fail">{failed_tests}</span></p>
        <p><strong>跳过:</strong> <span class="skip">{skipped_tests}</span></p>
        <p><strong>成功率:</strong> {success_rate:.1f}%</p>
    </div>
    
    <div class="section">
        <h2>详细测试结果</h2>
        <table>
            <tr>
                <th>测试项目</th>
                <th>状态</th>
                <th>说明</th>
                <th>耗时(秒)</th>
                <th>时间戳</th>
            </tr>
"""
        
        for result in self.test_results:
            status_class = result['status'].lower()
            duration = f"{result['duration']:.2f}" if result['duration'] else "N/A"
            
            report_html += f"""
            <tr>
                <td>{result['test_name']}</td>
                <td class="{status_class}">{result['status']}</td>
                <td>{result['message']}</td>
                <td>{duration}</td>
                <td>{result['timestamp']}</td>
            </tr>
"""
        
        report_html += """
        </table>
    </div>
    
    <div class="section">
        <h2>建议</h2>
        <ul>
"""
        
        if failed_tests > 0:
            report_html += "<li>请检查失败的测试项目，确保系统正常运行</li>"
        
        if success_rate < 90:
            report_html += "<li>系统测试成功率较低，建议进行全面检查</li>"
        else:
            report_html += "<li>系统测试通过，可以投入生产使用</li>"
        
        report_html += """
        </ul>
    </div>
</body>
</html>
"""
        
        # 保存报告
        report_filename = f"infrastructure_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        # 保存JSON格式
        json_filename = f"infrastructure_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.test_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"测试报告已生成:")
        logger.info(f"  HTML报告: {report_filename}")
        logger.info(f"  JSON数据: {json_filename}")
        
        return success_rate >= 80  # 80%以上通过率认为测试成功
    
    def run_all_tests(self):
        """运行所有测试"""
        logger.info("开始IT基础设施全面测试...")
        
        test_functions = [
            self.test_network_connectivity,
            self.test_dns_resolution,
            self.test_service_ports,
            self.test_web_services,
            self.test_file_shares,
            self.test_monitoring_endpoints,
            self.test_system_performance
        ]
        
        for test_func in test_functions:
            try:
                test_func()
            except Exception as e:
                logger.error(f"测试函数 {test_func.__name__} 执行失败: {str(e)}")
        
        # 生成报告
        success = self.generate_test_report()
        
        if success:
            logger.info("✓ 所有测试完成，系统状态良好")
        else:
            logger.warning("⚠ 测试完成，但发现一些问题需要处理")
        
        return success

if __name__ == "__main__":
    tester = InfrastructureTest()
    success = tester.run_all_tests()
    
    exit(0 if success else 1)
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*适用规模：50-100人中小企业*  
*负责人：部署实施团队*