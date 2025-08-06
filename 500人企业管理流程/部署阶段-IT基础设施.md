# 部署阶段 - IT基础设施管理

## 阶段概述
部署阶段是将已配置好的系统组件按照既定计划有序部署到生产环境的关键阶段，包括分阶段部署、测试验证、数据迁移和用户培训等核心活动。

## 1. 部署策略与计划

### 1.1 部署策略选择

#### 蓝绿部署策略
```
蓝绿部署方案:
┌─────────────────┐    ┌─────────────────┐
│   蓝环境 (旧)    │    │   绿环境 (新)    │
│   Production     │    │   Standby       │
└─────────────────┘    └─────────────────┘
         │                       │
         └───── 负载均衡器 ────────┘
                  │
            切换流量方向
```

**适用场景：**
- 核心业务系统升级
- 零停机时间要求
- 需要快速回滚能力

**实施步骤：**
1. 准备绿环境（新版本）
2. 部署并测试新版本
3. 切换流量到绿环境
4. 监控运行状态
5. 保留蓝环境作为备份

#### 滚动部署策略
```
滚动部署流程:
服务器1 ──► 下线 ──► 更新 ──► 测试 ──► 上线
服务器2 ──► 等待 ──► 下线 ──► 更新 ──► 测试 ──► 上线
服务器3 ──► 等待 ──► 等待 ──► 下线 ──► 更新 ──► 测试 ──► 上线
```

**适用场景：**
- 分布式应用部署
- 资源有限环境
- 渐进式风险控制

#### 金丝雀部署策略
```
金丝雀部署模型:
生产流量 100%
     │
     ├── 95% ──► 稳定版本
     └── 5%  ──► 金丝雀版本 (新)
```

**适用场景：**
- 新功能试验
- 风险评估
- 用户反馈收集

### 1.2 部署时间规划

#### 分阶段部署计划
```
Phase 1: 基础设施部署 (Week 1-2)
├── 网络设备部署
├── 存储系统部署  
├── 虚拟化平台部署
└── 基础监控部署

Phase 2: 系统软件部署 (Week 3-4)
├── 操作系统部署
├── 数据库系统部署
├── 中间件部署
└── 安全软件部署

Phase 3: 应用系统部署 (Week 5-6)
├── 业务应用部署
├── 集成测试
├── 性能测试
└── 安全测试

Phase 4: 数据迁移 (Week 7)
├── 数据备份
├── 数据转换
├── 数据同步
└── 数据验证

Phase 5: 用户培训 (Week 8)
├── 管理员培训
├── 终端用户培训
├── 故障处理培训
└── 应急响应培训
```

#### 部署时间窗口
```
部署时间安排:
┌─────────────────────────────────────────────────┐
│ 时间段      │ 类型     │ 说明              │
├─────────────────────────────────────────────────┤
│ 工作日 18:00-22:00 │ 标准窗口 │ 常规部署      │
│ 周五 22:00-周日 18:00 │ 扩展窗口 │ 重大部署   │
│ 国家法定假期首日 │ 紧急窗口 │ 应急部署      │
│ 业务高峰期  │ 禁止窗口 │ 禁止任何变更      │
└─────────────────────────────────────────────────┘
```

## 2. 基础设施部署

### 2.1 网络基础设施部署

#### 网络设备部署流程
```bash
#!/bin/bash
# 网络设备自动化部署脚本

# 1. 设备基础配置
deploy_network_device() {
    local device_type=$1
    local device_ip=$2
    local hostname=$3
    
    echo "开始部署 $device_type: $hostname ($device_ip)"
    
    # 通过TFTP推送配置文件
    tftp -p -l "/configs/${hostname}.cfg" $device_ip
    
    # 验证配置
    expect -c "
        spawn ssh admin@$device_ip
        expect \"Password:\"
        send \"admin123\r\"
        expect \"#\"
        send \"show running-config\r\"
        expect \"#\"
        send \"exit\r\"
        expect eof
    "
    
    echo "$device_type $hostname 部署完成"
}

# 2. 核心交换机部署
deploy_network_device "core-switch" "192.168.1.2" "core-sw-01"
deploy_network_device "core-switch" "192.168.1.3" "core-sw-02"

# 3. 接入交换机部署
for i in {1..10}; do
    ip="192.168.1.$((10+i))"
    hostname="access-sw-$(printf "%02d" $i)"
    deploy_network_device "access-switch" "$ip" "$hostname"
done

# 4. 防火墙部署
deploy_network_device "firewall" "192.168.1.1" "fw-01"
deploy_network_device "firewall" "192.168.1.4" "fw-02"

# 5. 部署验证
echo "验证网络连通性..."
for ip in $(seq 192.168.1.1 192.168.1.20); do
    if ping -c 1 $ip >/dev/null 2>&1; then
        echo "✓ $ip 连通正常"
    else
        echo "✗ $ip 连通失败"
    fi
done
```

#### 网络监控部署
```yaml
# Zabbix网络监控自动发现配置
Discovery_Rules:
  网络设备自动发现:
    名称: "Network Device Discovery"
    类型: "SNMP"
    OID: "1.3.6.1.2.1.1.2.0"
    更新间隔: "3600s"
    
    Item_Prototypes:
      - 名称: "设备CPU使用率"
        OID: "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1"
        类型: "SNMP代理"
        
      - 名称: "设备内存使用率"  
        OID: "1.3.6.1.4.1.9.9.48.1.1.1.5.1"
        类型: "SNMP代理"
        
      - 名称: "接口流量统计"
        OID: "1.3.6.1.2.1.2.2.1.10.{#SNMPINDEX}"
        类型: "SNMP代理"
        
    Trigger_Prototypes:
      - 名称: "CPU使用率过高"
        表达式: "last(//{#DEVICENAME}/cpu.usage)>90"
        严重级别: "高"
        
      - 名称: "内存使用率过高"
        表达式: "last(//{#DEVICENAME}/memory.usage)>85"
        严重级别: "告警"
        
      - 名称: "接口流量异常"
        表达式: "rate(//{#DEVICENAME}/interface.traffic,300s)>800M"
        严重级别: "信息"
```

### 2.2 服务器基础设施部署

#### 虚拟化平台部署
```powershell
# VMware vSphere自动化部署脚本

# 1. ESXi主机自动化配置
function Deploy-ESXiHost {
    param(
        [string]$HostIP,
        [string]$HostName,
        [PSCredential]$Credential
    )
    
    Write-Host "开始部署ESXi主机: $HostName ($HostIP)"
    
    # 连接到ESXi主机
    Connect-VIServer -Server $HostIP -Credential $Credential
    
    # 配置主机名
    Get-VMHost | Set-VMHost -Name $HostName
    
    # 配置NTP
    $ntpServers = @("pool.ntp.org", "time.windows.com")
    Get-VMHost | Get-VMHostNtpServer | Remove-VMHostNtpServer -Confirm:$false
    foreach ($ntp in $ntpServers) {
        Get-VMHost | Add-VMHostNtpServer -NtpServer $ntp
    }
    
    # 启动NTP服务
    Get-VMHost | Get-VMHostService | Where-Object {$_.Key -eq "ntpd"} | Start-VMHostService
    Get-VMHost | Get-VMHostService | Where-Object {$_.Key -eq "ntpd"} | Set-VMHostService -Policy "on"
    
    # 配置DNS
    Get-VMHost | Get-VMHostNetwork | Set-VMHostNetwork -DnsAddress @("192.168.1.10","192.168.1.11") -DomainName "company.local"
    
    # 配置vSwitch
    New-VirtualSwitch -VMHost (Get-VMHost) -Name "vSwitch1" -Nic "vmnic2","vmnic3"
    New-VirtualPortGroup -VirtualSwitch (Get-VirtualSwitch -Name "vSwitch1") -Name "VM Network" -VLanId 100
    
    Write-Host "ESXi主机 $HostName 部署完成"
    Disconnect-VIServer -Confirm:$false
}

# 2. 批量部署ESXi主机
$esxiHosts = @(
    @{IP="192.168.1.101"; Name="esx-host-01.company.local"},
    @{IP="192.168.1.102"; Name="esx-host-02.company.local"},
    @{IP="192.168.1.103"; Name="esx-host-03.company.local"}
)

$credential = Get-Credential -Message "输入ESXi root密码"

foreach ($host in $esxiHosts) {
    Deploy-ESXiHost -HostIP $host.IP -HostName $host.Name -Credential $credential
}

# 3. 创建vCenter集群
Connect-VIServer -Server "vcenter.company.local" -Credential (Get-Credential)

# 创建数据中心
New-Datacenter -Location (Get-Folder -NoRecursion) -Name "Company-Datacenter"

# 创建集群
$cluster = New-Cluster -Location (Get-Datacenter -Name "Company-Datacenter") -Name "Production-Cluster"

# 配置集群HA
$cluster | Set-Cluster -HAEnabled:$true -HAAdmissionControlEnabled:$true -HAFailoverLevel 1

# 配置集群DRS
$cluster | Set-Cluster -DrsEnabled:$true -DrsAutomationLevel "FullyAutomated"

# 添加主机到集群
foreach ($host in $esxiHosts) {
    Add-VMHost -Name $host.Name -Location $cluster -Credential $credential -Force
}
```

#### 虚拟机批量部署
```yaml
# Ansible虚拟机批量部署Playbook
---
- name: 批量部署虚拟机
  hosts: localhost
  gather_facts: false
  vars:
    vcenter_hostname: "vcenter.company.local"
    vcenter_username: "administrator@vsphere.local"
    vcenter_password: "vCenter123!"
    datacenter: "Company-Datacenter"
    cluster: "Production-Cluster"
    
  tasks:
    - name: 从模板克隆Windows服务器
      vmware_guest:
        hostname: "{{ vcenter_hostname }}"
        username: "{{ vcenter_username }}"
        password: "{{ vcenter_password }}"
        validate_certs: no
        datacenter: "{{ datacenter }}"
        cluster: "{{ cluster }}"
        name: "{{ item.name }}"
        template: "Template-Windows-2022"
        disk:
          - size_gb: "{{ item.disk_size }}"
            type: thin
            datastore: "{{ item.datastore }}"
        hardware:
          memory_mb: "{{ item.memory }}"
          num_cpus: "{{ item.cpu }}"
        networks:
          - name: "{{ item.network }}"
            ip: "{{ item.ip }}"
            netmask: "255.255.255.0"
            gateway: "{{ item.gateway }}"
            dns_servers:
              - "192.168.1.10"
              - "192.168.1.11"
        wait_for_ip_address: yes
        state: poweredon
      loop:
        - { name: "win-app-01", memory: 8192, cpu: 4, disk_size: 100, datastore: "datastore1", network: "VM Network", ip: "192.168.10.11", gateway: "192.168.10.1" }
        - { name: "win-app-02", memory: 8192, cpu: 4, disk_size: 100, datastore: "datastore1", network: "VM Network", ip: "192.168.10.12", gateway: "192.168.10.1" }
        - { name: "win-db-01", memory: 16384, cpu: 8, disk_size: 200, datastore: "datastore2", network: "VM Network", ip: "192.168.10.21", gateway: "192.168.10.1" }
    
    - name: 从模板克隆Linux服务器
      vmware_guest:
        hostname: "{{ vcenter_hostname }}"
        username: "{{ vcenter_username }}"
        password: "{{ vcenter_password }}"
        validate_certs: no
        datacenter: "{{ datacenter }}"
        cluster: "{{ cluster }}"
        name: "{{ item.name }}"
        template: "Template-Ubuntu-2204"
        disk:
          - size_gb: "{{ item.disk_size }}"
            type: thin
            datastore: "{{ item.datastore }}"
        hardware:
          memory_mb: "{{ item.memory }}"
          num_cpus: "{{ item.cpu }}"
        networks:
          - name: "{{ item.network }}"
            ip: "{{ item.ip }}"
            netmask: "255.255.255.0"
            gateway: "{{ item.gateway }}"
            dns_servers:
              - "192.168.1.10"
              - "192.168.1.11"
        wait_for_ip_address: yes
        state: poweredon
      loop:
        - { name: "linux-web-01", memory: 4096, cpu: 2, disk_size: 60, datastore: "datastore1", network: "VM Network", ip: "192.168.10.31", gateway: "192.168.10.1" }
        - { name: "linux-web-02", memory: 4096, cpu: 2, disk_size: 60, datastore: "datastore1", network: "VM Network", ip: "192.168.10.32", gateway: "192.168.10.1" }
        - { name: "linux-monitor", memory: 8192, cpu: 4, disk_size: 100, datastore: "datastore2", network: "VM Network", ip: "192.168.10.41", gateway: "192.168.10.1" }
```

### 2.3 存储系统部署

#### SAN存储连接配置
```bash
#!/bin/bash
# iSCSI存储连接配置脚本

# 1. 安装iSCSI客户端
install_iscsi_client() {
    if [ -f /etc/redhat-release ]; then
        yum install -y iscsi-initiator-utils
    elif [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y open-iscsi
    fi
}

# 2. 配置iSCSI发起端
configure_iscsi_initiator() {
    local initiator_name="iqn.2023-01.local.company:$(hostname)"
    
    # 设置Initiator名称
    echo "InitiatorName=$initiator_name" > /etc/iscsi/initiatorname.iscsi
    
    # 配置iSCSI认证
    cat >> /etc/iscsi/iscsid.conf << EOF
node.session.auth.authmethod = CHAP
node.session.auth.username = iscsi_user
node.session.auth.password = iscsi_password123!
discovery.sendtargets.auth.authmethod = CHAP
discovery.sendtargets.auth.username = iscsi_user
discovery.sendtargets.auth.password = iscsi_password123!
EOF
    
    # 重启iSCSI服务
    systemctl restart iscsid
    systemctl enable iscsid
}

# 3. 发现iSCSI目标
discover_iscsi_targets() {
    local target_ip=$1
    
    echo "发现iSCSI目标: $target_ip"
    iscsiadm -m discovery -t sendtargets -p $target_ip
    
    # 登录到所有目标
    iscsiadm -m node --login
    
    # 设置自动登录
    iscsiadm -m node --op=update --name=node.startup --value=automatic
}

# 4. 配置多路径
configure_multipath() {
    # 安装多路径软件
    if [ -f /etc/redhat-release ]; then
        yum install -y device-mapper-multipath
    elif [ -f /etc/debian_version ]; then
        apt-get install -y multipath-tools
    fi
    
    # 创建多路径配置
    cat > /etc/multipath.conf << EOF
defaults {
    polling_interval        10
    path_selector           "round-robin 0"
    path_grouping_policy    multibus
    uid_attribute           ID_SERIAL
    rr_min_io               100
    failback                immediate
    no_path_retry           queue
    user_friendly_names     yes
}

blacklist {
    devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st)[0-9]*"
    devnode "^hd[a-z]"
    devnode "^sda"
}

multipaths {
    multipath {
        wwid   "36000d31000fcb300000000000000001"
        alias  datastore1
    }
    multipath {
        wwid   "36000d31000fcb300000000000000002"
        alias  datastore2
    }
}
EOF
    
    # 启动多路径服务
    systemctl restart multipathd
    systemctl enable multipathd
}

# 5. 执行部署
echo "开始iSCSI存储部署..."
install_iscsi_client
configure_iscsi_initiator
discover_iscsi_targets "192.168.50.10"
discover_iscsi_targets "192.168.50.11"
configure_multipath

echo "iSCSI存储部署完成"
lsblk
multipath -ll
```

#### VMware存储配置
```powershell
# VMware存储自动化配置脚本

# 1. 连接vCenter
Connect-VIServer -Server "vcenter.company.local" -Credential (Get-Credential)

# 2. 配置iSCSI适配器
function Configure-iSCSIAdapter {
    param([string]$VMHostName)
    
    $vmhost = Get-VMHost -Name $VMHostName
    
    # 启用软件iSCSI适配器
    $hba = Get-VMHostHba -VMHost $vmhost -Type iScsi | Where-Object {$_.Model -eq "iSCSI Software Adapter"}
    if ($hba -eq $null) {
        Write-Host "在主机 $VMHostName 上启用软件iSCSI适配器"
        $vmhost | Get-VMHostStorage | Set-VMHostStorage -SoftwareIScsiEnabled:$true
        $hba = Get-VMHostHba -VMHost $vmhost -Type iScsi | Where-Object {$_.Model -eq "iSCSI Software Adapter"}
    }
    
    # 配置iSCSI目标
    $targets = @("192.168.50.10", "192.168.50.11")
    foreach ($target in $targets) {
        Write-Host "添加iSCSI目标: $target"
        New-IScsiHbaTarget -IScsiHba $hba -Address $target
    }
    
    # 重新扫描存储
    Get-VMHostStorage -VMHost $vmhost -RescanAllHba
}

# 3. 为所有主机配置iSCSI
$vmhosts = Get-VMHost
foreach ($vmhost in $vmhosts) {
    Configure-iSCSIAdapter -VMHostName $vmhost.Name
}

# 4. 创建VMFS数据存储
function Create-VMFSDatastore {
    param(
        [string]$DatastoreName,
        [string]$ClusterName
    )
    
    $cluster = Get-Cluster -Name $ClusterName
    $vmhost = $cluster | Get-VMHost | Select-Object -First 1
    
    # 获取可用磁盘
    $disks = Get-ScsiLun -VMHost $vmhost -LunType disk | Where-Object {$_.MultipathPolicy -ne "Fixed" -and $_.IsLocal -eq $false}
    
    foreach ($disk in $disks) {
        if ($disk.CapacityGB -gt 100 -and $disk.CanonicalName -notlike "*datastore*") {
            Write-Host "在磁盘 $($disk.CanonicalName) 上创建数据存储 $DatastoreName"
            
            # 创建VMFS分区
            New-Datastore -VMHost $vmhost -Name $DatastoreName -Path $disk.CanonicalName -Vmfs
            break
        }
    }
}

# 5. 创建数据存储
Create-VMFSDatastore -DatastoreName "datastore1" -ClusterName "Production-Cluster"
Create-VMFSDatastore -DatastoreName "datastore2" -ClusterName "Production-Cluster"

# 6. 设置存储DRS
$cluster = Get-Cluster -Name "Production-Cluster"
$cluster | Set-Cluster -HAEnabled:$true -DrsEnabled:$true

# 7. 验证存储配置
Write-Host "存储配置验证:"
Get-Datastore | Select-Object Name, CapacityGB, FreeSpaceGB, @{N="Usage%";E={[math]::Round(($_.CapacityGB-$_.FreeSpaceGB)/$_.CapacityGB*100,2)}}
```

## 3. 应用系统部署

### 3.1 数据库系统部署

#### SQL Server集群部署
```powershell
# SQL Server Always On可用性组部署脚本

# 1. 安装SQL Server故障转移集群
function Install-SQLServerCluster {
    param(
        [string[]]$ClusterNodes,
        [string]$ClusterName,
        [string]$VirtualName,
        [string]$VirtualIP
    )
    
    # 安装故障转移集群功能
    foreach ($node in $ClusterNodes) {
        Invoke-Command -ComputerName $node -ScriptBlock {
            Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools
        }
    }
    
    # 创建故障转移集群
    New-Cluster -Name $ClusterName -Node $ClusterNodes -StaticAddress $VirtualIP
    
    # 配置集群仲裁
    Set-ClusterQuorum -CloudWitness -AccountName "companystorage" -AccessKey "storagekey"
}

# 2. 配置Always On可用性组
function Configure-AlwaysOn {
    param(
        [string]$PrimaryReplica,
        [string[]]$SecondaryReplicas,
        [string]$AvailabilityGroupName
    )
    
    # 在主副本上启用Always On
    Invoke-Sqlcmd -ServerInstance $PrimaryReplica -Query "
        EXEC sp_configure 'show advanced options', 1;
        RECONFIGURE WITH OVERRIDE;
        EXEC sp_configure 'hadr enabled', 1;
        RECONFIGURE WITH OVERRIDE;
    "
    
    # 重启SQL Server服务
    Restart-Service -Name "MSSQLSERVER" -ComputerName $PrimaryReplica
    
    # 在辅助副本上启用Always On
    foreach ($replica in $SecondaryReplicas) {
        Invoke-Sqlcmd -ServerInstance $replica -Query "
            EXEC sp_configure 'show advanced options', 1;
            RECONFIGURE WITH OVERRIDE;
            EXEC sp_configure 'hadr enabled', 1;
            RECONFIGURE WITH OVERRIDE;
        "
        Restart-Service -Name "MSSQLSERVER" -ComputerName $replica
    }
    
    # 创建可用性组
    $createAGScript = @"
        CREATE AVAILABILITY GROUP [$AvailabilityGroupName]
        WITH (AUTOMATED_BACKUP_PREFERENCE = SECONDARY)
        FOR DATABASE [CompanyDB]
        REPLICA ON 
        N'$PrimaryReplica' WITH (
            ENDPOINT_URL = N'TCP://${PrimaryReplica}:5022',
            AVAILABILITY_MODE = SYNCHRONOUS_COMMIT,
            FAILOVER_MODE = AUTOMATIC,
            BACKUP_PRIORITY = 30,
            SECONDARY_ROLE(ALLOW_CONNECTIONS = NO)
        ),
"@
    
    foreach ($replica in $SecondaryReplicas) {
        $createAGScript += @"
        N'$replica' WITH (
            ENDPOINT_URL = N'TCP://${replica}:5022',
            AVAILABILITY_MODE = ASYNCHRONOUS_COMMIT,
            FAILOVER_MODE = MANUAL,
            BACKUP_PRIORITY = 50,
            SECONDARY_ROLE(ALLOW_CONNECTIONS = YES)
        ),
"@
    }
    
    $createAGScript = $createAGScript.TrimEnd(',')
    
    Invoke-Sqlcmd -ServerInstance $PrimaryReplica -Query $createAGScript
}

# 3. 执行部署
$clusterNodes = @("SQL-01", "SQL-02", "SQL-03")
Install-SQLServerCluster -ClusterNodes $clusterNodes -ClusterName "SQL-Cluster" -VirtualName "SQL-VIP" -VirtualIP "192.168.10.100"
Configure-AlwaysOn -PrimaryReplica "SQL-01" -SecondaryReplicas @("SQL-02", "SQL-03") -AvailabilityGroupName "CompanyAG"
```

#### PostgreSQL主从部署
```bash
#!/bin/bash
# PostgreSQL主从复制部署脚本

# 1. 主服务器配置
configure_postgresql_master() {
    local master_ip="192.168.10.21"
    local slave_ip="192.168.10.22"
    
    echo "配置PostgreSQL主服务器..."
    
    # 修改postgresql.conf
    cat >> /etc/postgresql/15/main/postgresql.conf << EOF
# 复制配置
wal_level = replica
max_wal_senders = 3
max_replication_slots = 3
synchronous_commit = on
synchronous_standby_names = 'standby1'

# 归档配置
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/15/archive/%f'
EOF
    
    # 修改pg_hba.conf
    cat >> /etc/postgresql/15/main/pg_hba.conf << EOF
# 复制连接
host    replication     replicator      $slave_ip/32            md5
EOF
    
    # 创建复制用户
    sudo -u postgres psql << EOF
CREATE USER replicator REPLICATION LOGIN ENCRYPTED PASSWORD 'ReplicatorPass123!';
EOF
    
    # 重启PostgreSQL
    systemctl restart postgresql
    
    echo "主服务器配置完成"
}

# 2. 从服务器配置
configure_postgresql_slave() {
    local master_ip="192.168.10.21"
    local slave_ip="192.168.10.22"
    
    echo "配置PostgreSQL从服务器..."
    
    # 停止PostgreSQL服务
    systemctl stop postgresql
    
    # 清空数据目录
    rm -rf /var/lib/postgresql/15/main/*
    
    # 从主服务器基础备份
    sudo -u postgres pg_basebackup -h $master_ip -D /var/lib/postgresql/15/main -U replicator -P -v -R -X stream -C -S standby1
    
    # 修改postgresql.conf
    cat >> /var/lib/postgresql/15/main/postgresql.conf << EOF
# 从服务器配置
hot_standby = on
max_standby_streaming_delay = 30s
wal_receiver_status_interval = 10s
hot_standby_feedback = on
EOF
    
    # 创建恢复配置
    cat > /var/lib/postgresql/15/main/standby.signal << EOF
# 从服务器标识文件
EOF
    
    # 设置权限
    chown -R postgres:postgres /var/lib/postgresql/15/main
    chmod 700 /var/lib/postgresql/15/main
    
    # 启动PostgreSQL
    systemctl start postgresql
    
    echo "从服务器配置完成"
}

# 3. 验证复制状态
verify_replication() {
    local master_ip="192.168.10.21"
    local slave_ip="192.168.10.22"
    
    echo "验证主从复制状态..."
    
    # 在主服务器上检查复制状态
    echo "主服务器复制状态:"
    sudo -u postgres psql -h $master_ip -c "SELECT client_addr, state, sync_state FROM pg_stat_replication;"
    
    # 在从服务器上检查复制状态
    echo "从服务器复制状态:"
    sudo -u postgres psql -h $slave_ip -c "SELECT status, receive_start_lsn, received_lsn FROM pg_stat_wal_receiver;"
    
    # 测试数据同步
    echo "测试数据同步..."
    sudo -u postgres psql -h $master_ip -c "CREATE TABLE test_replication (id int, data text);"
    sudo -u postgres psql -h $master_ip -c "INSERT INTO test_replication VALUES (1, 'test data');"
    
    sleep 5
    
    echo "从服务器数据验证:"
    sudo -u postgres psql -h $slave_ip -c "SELECT * FROM test_replication;"
}

# 4. 执行部署
configure_postgresql_master
configure_postgresql_slave
verify_replication

echo "PostgreSQL主从复制部署完成"
```

### 3.2 Web应用部署

#### 容器化应用部署
```yaml
# Docker Compose应用部署配置
version: '3.8'

services:
  # Nginx负载均衡器
  nginx:
    image: nginx:1.24-alpine
    container_name: nginx-lb
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/logs:/var/log/nginx
    depends_on:
      - app1
      - app2
    networks:
      - app-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  # 应用服务器1
  app1:
    image: company/web-app:latest
    container_name: web-app-01
    environment:
      - NODE_ENV=production
      - DB_HOST=192.168.10.21
      - DB_USER=appuser
      - DB_PASS=SecurePassword123!
      - REDIS_HOST=192.168.10.40
      - REDIS_PASS=RedisPassword123!
    volumes:
      - ./app/logs:/app/logs
      - ./app/uploads:/app/uploads
    networks:
      - app-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # 应用服务器2
  app2:
    image: company/web-app:latest
    container_name: web-app-02
    environment:
      - NODE_ENV=production
      - DB_HOST=192.168.10.21
      - DB_USER=appuser
      - DB_PASS=SecurePassword123!
      - REDIS_HOST=192.168.10.40
      - REDIS_PASS=RedisPassword123!
    volumes:
      - ./app/logs:/app/logs
      - ./app/uploads:/app/uploads
    networks:
      - app-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis缓存
  redis:
    image: redis:7.0-alpine
    container_name: redis-cache
    command: redis-server --requirepass RedisPassword123!
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    networks:
      - app-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M

  # 监控代理
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - app-network
    restart: unless-stopped

networks:
  app-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  redis-data:
    driver: local
```

#### Kubernetes应用部署
```yaml
# Kubernetes应用部署清单

# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: company-app
---
# ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: company-app
data:
  NODE_ENV: "production"
  DB_HOST: "192.168.10.21"
  REDIS_HOST: "192.168.10.40"
---
# Secret
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: company-app
type: Opaque
data:
  db-password: U2VjdXJlUGFzc3dvcmQxMjMh  # base64编码
  redis-password: UmVkaXNQYXNzd29yZDEyMyE=
---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: company-app
  labels:
    app: web-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      containers:
      - name: web-app
        image: company/web-app:v1.2.0
        imagePullPolicy: Always
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: NODE_ENV
        - name: DB_HOST
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: DB_HOST
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: db-password
        resources:
          limits:
            memory: "2Gi"
            cpu: "1000m"
          requests:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: app-logs
          mountPath: /app/logs
      volumes:
      - name: app-logs
        persistentVolumeClaim:
          claimName: app-logs-pvc
---
# Service
apiVersion: v1
kind: Service
metadata:
  name: web-app-service
  namespace: company-app
spec:
  selector:
    app: web-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
---
# Ingress
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-app-ingress
  namespace: company-app
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - app.company.local
    secretName: app-tls
  rules:
  - host: app.company.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-app-service
            port:
              number: 80
---
# HPA (水平自动扩展)
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-app-hpa
  namespace: company-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 4. 测试验证

### 4.1 功能测试

#### 自动化测试脚本
```python
#!/usr/bin/env python3
# 自动化功能测试脚本

import requests
import psycopg2
import redis
import time
import json
from concurrent.futures import ThreadPoolExecutor
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class InfrastructureTest:
    def __init__(self):
        self.test_results = []
        
    def test_web_application(self):
        """测试Web应用可用性"""
        try:
            urls = [
                'http://192.168.10.31',
                'http://192.168.10.32',
                'https://app.company.local'
            ]
            
            for url in urls:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    logger.info(f"✓ Web应用测试通过: {url}")
                    self.test_results.append({'test': f'Web-{url}', 'status': 'PASS'})
                else:
                    logger.error(f"✗ Web应用测试失败: {url} - Status: {response.status_code}")
                    self.test_results.append({'test': f'Web-{url}', 'status': 'FAIL'})
                    
        except Exception as e:
            logger.error(f"Web应用测试异常: {str(e)}")
            self.test_results.append({'test': 'Web-Application', 'status': 'ERROR'})
    
    def test_database_connectivity(self):
        """测试数据库连接"""
        try:
            # PostgreSQL测试
            conn = psycopg2.connect(
                host='192.168.10.21',
                database='companydb',
                user='appuser',
                password='SecurePassword123!'
            )
            cursor = conn.cursor()
            cursor.execute('SELECT version();')
            version = cursor.fetchone()
            logger.info(f"✓ PostgreSQL连接测试通过: {version[0]}")
            self.test_results.append({'test': 'PostgreSQL-Primary', 'status': 'PASS'})
            conn.close()
            
            # PostgreSQL从库测试
            conn_slave = psycopg2.connect(
                host='192.168.10.22',
                database='companydb',
                user='readonly',
                password='ReadOnlyPass123!'
            )
            cursor_slave = conn_slave.cursor()
            cursor_slave.execute('SELECT pg_is_in_recovery();')
            is_slave = cursor_slave.fetchone()
            if is_slave[0]:
                logger.info("✓ PostgreSQL从库连接测试通过")
                self.test_results.append({'test': 'PostgreSQL-Slave', 'status': 'PASS'})
            conn_slave.close()
            
        except Exception as e:
            logger.error(f"数据库连接测试失败: {str(e)}")
            self.test_results.append({'test': 'Database-Connection', 'status': 'FAIL'})
    
    def test_redis_cache(self):
        """测试Redis缓存"""
        try:
            r = redis.Redis(
                host='192.168.10.40',
                port=6379,
                password='RedisPassword123!',
                decode_responses=True
            )
            
            # 测试写入
            r.set('test_key', 'test_value', ex=60)
            
            # 测试读取
            value = r.get('test_key')
            if value == 'test_value':
                logger.info("✓ Redis缓存测试通过")
                self.test_results.append({'test': 'Redis-Cache', 'status': 'PASS'})
            else:
                logger.error("✗ Redis缓存测试失败")
                self.test_results.append({'test': 'Redis-Cache', 'status': 'FAIL'})
                
            # 清理测试数据
            r.delete('test_key')
            
        except Exception as e:
            logger.error(f"Redis缓存测试失败: {str(e)}")
            self.test_results.append({'test': 'Redis-Cache', 'status': 'FAIL'})
    
    def test_load_balancer(self):
        """测试负载均衡"""
        try:
            url = 'https://app.company.local/api/health'
            server_responses = {}
            
            # 发送多个请求测试负载均衡
            for i in range(20):
                response = requests.get(url, timeout=5)
                server_id = response.headers.get('X-Server-ID', 'unknown')
                server_responses[server_id] = server_responses.get(server_id, 0) + 1
            
            # 验证请求分发到多个服务器
            if len(server_responses) > 1:
                logger.info(f"✓ 负载均衡测试通过: {server_responses}")
                self.test_results.append({'test': 'Load-Balancer', 'status': 'PASS'})
            else:
                logger.warning(f"负载均衡可能有问题: {server_responses}")
                self.test_results.append({'test': 'Load-Balancer', 'status': 'WARNING'})
                
        except Exception as e:
            logger.error(f"负载均衡测试失败: {str(e)}")
            self.test_results.append({'test': 'Load-Balancer', 'status': 'FAIL'})

    def test_ssl_certificates(self):
        """测试SSL证书"""
        import ssl
        import socket
        
        try:
            hostname = 'app.company.local'
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    logger.info(f"✓ SSL证书测试通过: {cert['subject']}")
                    self.test_results.append({'test': 'SSL-Certificate', 'status': 'PASS'})
                    
        except Exception as e:
            logger.error(f"SSL证书测试失败: {str(e)}")
            self.test_results.append({'test': 'SSL-Certificate', 'status': 'FAIL'})

    def run_all_tests(self):
        """运行所有测试"""
        logger.info("开始基础设施功能测试...")
        
        tests = [
            self.test_web_application,
            self.test_database_connectivity,
            self.test_redis_cache,
            self.test_load_balancer,
            self.test_ssl_certificates
        ]
        
        # 并行执行测试
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda test: test(), tests)
        
        # 生成测试报告
        self.generate_report()
        
    def generate_report(self):
        """生成测试报告"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['status'] == 'PASS')
        failed_tests = sum(1 for result in self.test_results if result['status'] == 'FAIL')
        error_tests = sum(1 for result in self.test_results if result['status'] == 'ERROR')
        warning_tests = sum(1 for result in self.test_results if result['status'] == 'WARNING')
        
        logger.info("=" * 50)
        logger.info("测试报告汇总")
        logger.info("=" * 50)
        logger.info(f"总测试数: {total_tests}")
        logger.info(f"通过: {passed_tests}")
        logger.info(f"失败: {failed_tests}")
        logger.info(f"错误: {error_tests}")
        logger.info(f"警告: {warning_tests}")
        logger.info(f"成功率: {(passed_tests/total_tests)*100:.1f}%")
        
        # 保存详细报告
        with open('infrastructure_test_report.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)

if __name__ == "__main__":
    tester = InfrastructureTest()
    tester.run_all_tests()
```

### 4.2 性能测试

#### 压力测试脚本
```bash
#!/bin/bash
# 基础设施性能测试脚本

# 1. Web应用性能测试
test_web_performance() {
    echo "开始Web应用性能测试..."
    
    # 使用Apache Bench进行压力测试
    ab -n 10000 -c 100 -H "Accept-Encoding: gzip,deflate" https://app.company.local/ > web_performance.log
    
    # 使用wrk进行更详细的测试
    wrk -t12 -c400 -d30s --timeout 10s https://app.company.local/ > web_performance_wrk.log
    
    echo "Web应用性能测试完成，结果保存到 web_performance*.log"
}

# 2. 数据库性能测试
test_database_performance() {
    echo "开始数据库性能测试..."
    
    # PostgreSQL性能测试
    pgbench -i -s 50 -h 192.168.10.21 -U postgres companydb
    pgbench -c 50 -j 2 -T 300 -h 192.168.10.21 -U postgres companydb > db_performance.log
    
    echo "数据库性能测试完成，结果保存到 db_performance.log"
}

# 3. 网络性能测试
test_network_performance() {
    echo "开始网络性能测试..."
    
    # 使用iperf3测试网络带宽
    # 在服务器端：iperf3 -s
    # 在客户端：
    iperf3 -c 192.168.10.21 -t 60 -P 4 > network_performance.log
    
    # 测试延迟
    ping -c 100 192.168.10.21 | tail -1 > network_latency.log
    
    echo "网络性能测试完成，结果保存到 network_*.log"
}

# 4. 存储性能测试
test_storage_performance() {
    echo "开始存储性能测试..."
    
    # 使用fio测试存储性能
    fio --name=randwrite --ioengine=libaio --iodepth=16 --rw=randwrite --bs=4k --direct=1 --size=1G --numjobs=4 --runtime=60 --group_reporting > storage_write_performance.log
    
    fio --name=randread --ioengine=libaio --iodepth=16 --rw=randread --bs=4k --direct=1 --size=1G --numjobs=4 --runtime=60 --group_reporting > storage_read_performance.log
    
    echo "存储性能测试完成，结果保存到 storage_*_performance.log"
}

# 5. 综合性能监控
monitor_system_performance() {
    echo "开始系统性能监控..."
    
    # 监控系统资源使用情况
    (
        echo "时间,CPU使用率,内存使用率,磁盘IO,网络IO"
        for i in {1..60}; do
            timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
            mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
            disk_io=$(iostat -x 1 1 | tail -1 | awk '{print $4+$5}')
            net_io=$(cat /proc/net/dev | grep eth0 | awk '{print $2+$10}')
            
            echo "$timestamp,$cpu_usage,$mem_usage,$disk_io,$net_io"
            sleep 1
        done
    ) > system_performance_monitor.csv
    
    echo "系统性能监控完成，结果保存到 system_performance_monitor.csv"
}

# 6. 生成性能测试报告
generate_performance_report() {
    echo "生成性能测试报告..."
    
    cat > performance_test_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>基础设施性能测试报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .metric { background: #f5f5f5; padding: 5px; margin: 5px 0; }
        .pass { color: green; } .fail { color: red; } .warning { color: orange; }
    </style>
</head>
<body>
    <h1>基础设施性能测试报告</h1>
    <p>测试时间: $(date)</p>
    
    <div class="section">
        <h2>Web应用性能</h2>
        <div class="metric">
            <strong>并发用户数:</strong> 100<br>
            <strong>总请求数:</strong> 10,000<br>
            <strong>平均响应时间:</strong> $(grep "Time per request" web_performance.log | head -1 | awk '{print $4}') ms<br>
            <strong>吞吐量:</strong> $(grep "Requests per second" web_performance.log | awk '{print $4}') req/s
        </div>
    </div>
    
    <div class="section">
        <h2>数据库性能</h2>
        <div class="metric">
            <strong>TPS:</strong> $(tail -5 db_performance.log | grep "tps" | awk '{print $3}')<br>
            <strong>平均延迟:</strong> $(tail -5 db_performance.log | grep "latency average" | awk '{print $4}') ms
        </div>
    </div>
    
    <div class="section">
        <h2>网络性能</h2>
        <div class="metric">
            <strong>带宽:</strong> $(grep "sender" network_performance.log | awk '{print $(NF-1), $NF}')<br>
            <strong>平均延迟:</strong> $(tail -1 network_latency.log | awk -F'/' '{print $5}') ms
        </div>
    </div>
    
    <div class="section">
        <h2>存储性能</h2>
        <div class="metric">
            <strong>随机写IOPS:</strong> $(grep "IOPS=" storage_write_performance.log | awk -F'IOPS=' '{print $2}' | awk -F',' '{print $1}')<br>
            <strong>随机读IOPS:</strong> $(grep "IOPS=" storage_read_performance.log | awk -F'IOPS=' '{print $2}' | awk -F',' '{print $1}')
        </div>
    </div>
</body>
</html>
EOF
    
    echo "性能测试报告已生成: performance_test_report.html"
}

# 7. 执行所有性能测试
echo "开始基础设施性能测试套件..."
test_web_performance &
test_database_performance &
test_network_performance &
test_storage_performance &

# 等待所有后台任务完成
wait

monitor_system_performance
generate_performance_report

echo "所有性能测试完成！"
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*负责人：部署实施团队*