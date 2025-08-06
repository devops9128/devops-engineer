# 管理阶段 - IT基础设施管理

## 阶段概述
管理阶段是IT基础设施生命周期中最长的阶段，涵盖日常运维、持续优化、变更管理和灾难恢复等核心活动，确保系统长期稳定运行并持续满足业务发展需求。

## 1. 日常运维管理

### 1.1 运维组织架构

#### 运维团队结构
```
IT运维部门组织架构:
┌─────────────────────────────────────────────────────────┐
│                   IT运维总监                           │
│                 (IT Operations Director)               │
└─────────────────┬───────────────────────────────────────┘
                  │
          ┌───────┼───────┐
          │       │       │
    ┌─────▼─┐ ┌───▼───┐ ┌─▼─────┐
    │系统运维│ │网络运维│ │安全运维│
    │  组    │ │  组    │ │  组    │
    └───┬───┘ └───┬───┘ └───┬───┘
        │         │         │
    ┌───▼───┐ ┌───▼───┐ ┌───▼───┐
    │服务器 │ │网络设备│ │安全设备│
    │运维工程│ │运维工程│ │运维工程│
    │师(3人)│ │师(2人)│ │师(2人)│
    └───────┘ └───────┘ └───────┘
        │         │         │
    ┌───▼───┐ ┌───▼───┐ ┌───▼───┐
    │数据库 │ │监控运维│ │应急响应│
    │运维工程│ │工程师 │ │工程师 │
    │师(2人)│ │(2人)  │ │(1人)  │
    └───────┘ └───────┘ └───────┘
```

#### 岗位职责定义
```yaml
运维岗位职责:
  IT运维总监:
    主要职责:
      - 制定IT运维策略和规划
      - 管理运维团队和预算
      - 与业务部门协调沟通
      - 重大事件决策和指挥
    技能要求:
      - 10年以上IT管理经验
      - ITIL认证
      - 项目管理能力
      - 业务理解能力
      
  系统运维工程师:
    主要职责:
      - 服务器系统维护
      - 虚拟化平台管理
      - 系统性能优化
      - 故障诊断处理
    技能要求:
      - Linux/Windows系统管理
      - VMware/Docker容器技术
      - 脚本编程能力
      - 故障排除经验
      
  网络运维工程师:
    主要职责:
      - 网络设备维护
      - 网络性能监控
      - 网络故障处理
      - 网络安全配置
    技能要求:
      - CCNP或同等认证
      - 路由交换技术
      - 防火墙配置
      - 网络协议分析
      
  数据库运维工程师:
    主要职责:
      - 数据库性能优化
      - 备份恢复管理
      - 数据安全保护
      - 容量规划管理
    技能要求:
      - PostgreSQL/MySQL专业技能
      - 数据库调优经验
      - 备份恢复技术
      - SQL开发能力
```

### 1.2 值班轮替制度

#### 7x24小时值班安排
```python
#!/usr/bin/env python3
# 值班排班管理系统

from datetime import datetime, timedelta
import json
import calendar

class OnCallScheduler:
    def __init__(self):
        self.engineers = {
            'primary': [
                {'name': '张工程师', 'level': 'senior', 'skills': ['linux', 'database']},
                {'name': '李工程师', 'level': 'senior', 'skills': ['network', 'security']},
                {'name': '王工程师', 'level': 'intermediate', 'skills': ['linux', 'docker']},
                {'name': '刘工程师', 'level': 'intermediate', 'skills': ['database', 'monitoring']}
            ],
            'backup': [
                {'name': '陈工程师', 'level': 'senior', 'skills': ['linux', 'network']},
                {'name': '赵工程师', 'level': 'intermediate', 'skills': ['database', 'security']}
            ]
        }
        
        self.schedule_rules = {
            'shift_duration': 8,  # 8小时轮班
            'shifts_per_day': 3,  # 每天3班
            'max_consecutive_days': 7,  # 最多连续值班7天
            'min_rest_hours': 16,  # 最少休息16小时
            'weekend_extra_pay': 1.5,  # 周末加班费倍数
            'holiday_extra_pay': 2.0   # 节假日加班费倍数
        }
    
    def generate_monthly_schedule(self, year, month):
        """生成月度值班表"""
        
        # 获取当月天数
        days_in_month = calendar.monthrange(year, month)[1]
        
        schedule = {
            'year': year,
            'month': month,
            'shifts': []
        }
        
        # 班次定义
        shift_times = [
            {'shift': '早班', 'start': '08:00', 'end': '16:00'},
            {'shift': '中班', 'start': '16:00', 'end': '24:00'},
            {'shift': '夜班', 'start': '00:00', 'end': '08:00'}
        ]
        
        engineer_index = 0
        
        for day in range(1, days_in_month + 1):
            date_obj = datetime(year, month, day)
            
            for shift_info in shift_times:
                # 选择值班工程师
                primary_engineer = self.engineers['primary'][engineer_index % len(self.engineers['primary'])]
                backup_engineer = self.engineers['backup'][engineer_index % len(self.engineers['backup'])]
                
                shift_data = {
                    'date': date_obj.strftime('%Y-%m-%d'),
                    'weekday': date_obj.strftime('%A'),
                    'shift': shift_info['shift'],
                    'start_time': shift_info['start'],
                    'end_time': shift_info['end'],
                    'primary_engineer': primary_engineer['name'],
                    'backup_engineer': backup_engineer['name'],
                    'is_weekend': date_obj.weekday() >= 5,
                    'is_holiday': self.is_holiday(date_obj),
                    'contact_info': {
                        'primary_phone': self.get_engineer_phone(primary_engineer['name']),
                        'backup_phone': self.get_engineer_phone(backup_engineer['name']),
                        'escalation': 'IT运维总监'
                    }
                }
                
                schedule['shifts'].append(shift_data)
                engineer_index += 1
        
        return schedule
    
    def is_holiday(self, date_obj):
        """判断是否为节假日"""
        # 简化实现，实际应该集成节假日API
        holidays_2025 = [
            datetime(2025, 1, 1),   # 元旦
            datetime(2025, 2, 10),  # 春节
            datetime(2025, 2, 11),
            datetime(2025, 2, 12),
            datetime(2025, 2, 13),
            datetime(2025, 2, 14),
            datetime(2025, 2, 15),
            datetime(2025, 2, 16),
            datetime(2025, 4, 5),   # 清明节
            datetime(2025, 5, 1),   # 劳动节
            datetime(2025, 6, 10),  # 端午节
            datetime(2025, 9, 15),  # 中秋节
            datetime(2025, 10, 1),  # 国庆节
            datetime(2025, 10, 2),
            datetime(2025, 10, 3)
        ]
        
        return date_obj.date() in [h.date() for h in holidays_2025]
    
    def get_engineer_phone(self, name):
        """获取工程师联系电话"""
        # 简化实现，实际应该从HR系统获取
        phone_book = {
            '张工程师': '138-0000-0001',
            '李工程师': '138-0000-0002',
            '王工程师': '138-0000-0003',
            '刘工程师': '138-0000-0004',
            '陈工程师': '138-0000-0005',
            '赵工程师': '138-0000-0006'
        }
        return phone_book.get(name, '138-0000-0000')
    
    def export_schedule_to_file(self, schedule, filename):
        """导出值班表到文件"""
        
        # 导出JSON格式
        with open(f"{filename}.json", 'w', encoding='utf-8') as f:
            json.dump(schedule, f, indent=2, ensure_ascii=False)
        
        # 导出可读格式
        with open(f"{filename}.txt", 'w', encoding='utf-8') as f:
            f.write(f"IT运维值班表 - {schedule['year']}年{schedule['month']}月\n")
            f.write("=" * 60 + "\n\n")
            
            current_date = None
            for shift in schedule['shifts']:
                if current_date != shift['date']:
                    current_date = shift['date']
                    f.write(f"\n{shift['date']} ({shift['weekday']})\n")
                    f.write("-" * 40 + "\n")
                
                f.write(f"{shift['shift']} {shift['start_time']}-{shift['end_time']}: ")
                f.write(f"主值班: {shift['primary_engineer']} ({shift['contact_info']['primary_phone']}), ")
                f.write(f"备值班: {shift['backup_engineer']} ({shift['contact_info']['backup_phone']})")
                
                if shift['is_weekend'] or shift['is_holiday']:
                    f.write(" [加班]")
                
                f.write("\n")
        
        print(f"值班表已导出: {filename}.json, {filename}.txt")

# 使用示例
if __name__ == "__main__":
    scheduler = OnCallScheduler()
    
    # 生成2025年8月值班表
    august_schedule = scheduler.generate_monthly_schedule(2025, 8)
    scheduler.export_schedule_to_file(august_schedule, "oncall_schedule_2025_08")
```

#### 值班工作流程
```yaml
值班工作标准:
  值班前准备:
    检查事项:
      - [ ] 确认监控系统正常
      - [ ] 检查告警规则配置
      - [ ] 验证通讯工具可用
      - [ ] 确认升级联系人清单
      - [ ] 检查应急文档完整性
      - [ ] 确认值班设备状态
    
    交接事项:
      - [ ] 了解当前系统状态
      - [ ] 确认未解决问题
      - [ ] 核对进行中的变更
      - [ ] 检查计划维护任务
      - [ ] 确认特殊注意事项
  
  值班期间工作:
    主要任务:
      - 监控系统运行状态
      - 响应告警和故障
      - 处理用户请求
      - 执行例行巡检
      - 记录值班日志
      - 协调资源支持
    
    响应时间要求:
      - P0级故障: 5分钟内响应
      - P1级故障: 15分钟内响应
      - P2级故障: 30分钟内响应
      - 用户咨询: 1小时内响应
      - 例行巡检: 每2小时一次
  
  值班后总结:
    记录内容:
      - [ ] 值班期间事件记录
      - [ ] 处理的问题汇总
      - [ ] 发现的潜在风险
      - [ ] 改进建议
      - [ ] 遗留问题说明
    
    交接流程:
      - [ ] 口头交接当前状态
      - [ ] 移交未完成工作
      - [ ] 提交值班日志
      - [ ] 确认下班工程师到位
```

### 1.3 日常巡检制度

#### 自动化巡检脚本
```bash
#!/bin/bash
# IT基础设施日常巡检脚本

# 配置参数
PATROL_LOG="/var/log/daily-patrol.log"
REPORT_EMAIL="ops@company.local"
THRESHOLD_CPU=80
THRESHOLD_MEMORY=85
THRESHOLD_DISK=85

# 日志函数
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" | tee -a $PATROL_LOG
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" | tee -a $PATROL_LOG
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" | tee -a $PATROL_LOG
}

# 系统资源巡检
check_system_resources() {
    log_info "开始系统资源巡检..."
    
    local issues=()
    
    # CPU使用率检查
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//' | cut -d'%' -f1)
    if (( $(echo "$cpu_usage > $THRESHOLD_CPU" | bc -l) )); then
        issues+=("CPU使用率过高: ${cpu_usage}%")
    fi
    
    # 内存使用率检查
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    if (( $(echo "$mem_usage > $THRESHOLD_MEMORY" | bc -l) )); then
        issues+=("内存使用率过高: ${mem_usage}%")
    fi
    
    # 磁盘使用率检查
    while read line; do
        usage=$(echo $line | awk '{print $5}' | sed 's/%//')
        filesystem=$(echo $line | awk '{print $6}')
        if [ "$usage" -gt $THRESHOLD_DISK ]; then
            issues+=("磁盘使用率过高: $filesystem ${usage}%")
        fi
    done < <(df -h | grep -vE '^Filesystem|tmpfs|cdrom')
    
    # 系统负载检查
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    cpu_cores=$(nproc)
    if (( $(echo "$load_avg > $cpu_cores * 2" | bc -l) )); then
        issues+=("系统负载过高: $load_avg (CPU核心数: $cpu_cores)")
    fi
    
    if [ ${#issues[@]} -eq 0 ]; then
        log_info "✓ 系统资源状态正常"
    else
        for issue in "${issues[@]}"; do
            log_warning "⚠ $issue"
        done
    fi
}

# 服务状态巡检
check_service_status() {
    log_info "开始服务状态巡检..."
    
    local failed_services=()
    services=("nginx" "postgresql" "redis-server" "docker" "ssh")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            log_info "✓ $service 服务运行正常"
        else
            failed_services+=($service)
            log_error "✗ $service 服务未运行"
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        log_error "发现 ${#failed_services[@]} 个服务异常: ${failed_services[*]}"
        # 尝试重启失败的服务
        for service in "${failed_services[@]}"; do
            log_info "尝试重启服务: $service"
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                log_info "✓ $service 服务重启成功"
            else
                log_error "✗ $service 服务重启失败"
            fi
        done
    fi
}

# 网络连通性巡检
check_network_connectivity() {
    log_info "开始网络连通性巡检..."
    
    local failed_hosts=()
    # 关键主机和服务
    declare -A hosts=(
        ["网关"]="192.168.1.1"
        ["DNS服务器"]="192.168.1.10"
        ["数据库主服务器"]="192.168.10.21"
        ["数据库从服务器"]="192.168.10.22"
        ["Redis服务器"]="192.168.10.40"
        ["外网连接"]="8.8.8.8"
    )
    
    for name in "${!hosts[@]}"; do
        ip=${hosts[$name]}
        if ping -c 3 -W 5 $ip >/dev/null 2>&1; then
            log_info "✓ $name ($ip) 连通正常"
        else
            failed_hosts+=("$name ($ip)")
            log_error "✗ $name ($ip) 连接失败"
        fi
    done
    
    if [ ${#failed_hosts[@]} -gt 0 ]; then
        log_error "网络连通性异常: ${failed_hosts[*]}"
    fi
}

# Web应用健康检查
check_web_applications() {
    log_info "开始Web应用健康检查..."
    
    local failed_apps=()
    declare -A apps=(
        ["主应用"]="https://app.company.local/health"
        ["API服务"]="https://api.company.local/health"
        ["管理后台"]="https://admin.company.local/health"
    )
    
    for name in "${!apps[@]}"; do
        url=${apps[$name]}
        response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 10 $url)
        if [ "$response" = "200" ]; then
            log_info "✓ $name 健康检查通过"
        else
            failed_apps+=("$name (HTTP $response)")
            log_error "✗ $name 健康检查失败: HTTP $response"
        fi
    done
    
    if [ ${#failed_apps[@]} -gt 0 ]; then
        log_error "Web应用异常: ${failed_apps[*]}"
    fi
}

# 数据库连接检查
check_database_connections() {
    log_info "开始数据库连接检查..."
    
    # PostgreSQL检查
    if sudo -u postgres psql -c "SELECT 1;" >/dev/null 2>&1; then
        log_info "✓ PostgreSQL主库连接正常"
        
        # 检查连接数
        conn_count=$(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity;")
        log_info "PostgreSQL当前连接数: $conn_count"
        
        # 检查数据库大小
        db_size=$(sudo -u postgres psql -t -c "SELECT pg_size_pretty(pg_database_size('companydb'));")
        log_info "数据库大小: $db_size"
    else
        log_error "✗ PostgreSQL主库连接失败"
    fi
    
    # Redis检查
    if redis-cli -a "RedisPassword123!" ping >/dev/null 2>&1; then
        log_info "✓ Redis连接正常"
        
        # 检查内存使用
        redis_memory=$(redis-cli -a "RedisPassword123!" info memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
        log_info "Redis内存使用: $redis_memory"
    else
        log_error "✗ Redis连接失败"
    fi
}

# 备份状态检查
check_backup_status() {
    log_info "开始备份状态检查..."
    
    # 检查数据库备份
    latest_db_backup=$(ls -t /backup/database/ | head -1)
    if [ -n "$latest_db_backup" ]; then
        backup_date=$(stat -c %y "/backup/database/$latest_db_backup" | cut -d' ' -f1)
        today=$(date +%Y-%m-%d)
        
        if [ "$backup_date" = "$today" ]; then
            log_info "✓ 数据库备份正常 (最新: $latest_db_backup)"
        else
            log_warning "⚠ 数据库备份可能过期 (最新: $backup_date)"
        fi
    else
        log_error "✗ 未找到数据库备份文件"
    fi
    
    # 检查文件备份
    latest_file_backup=$(ls -t /backup/files/ | head -1)
    if [ -n "$latest_file_backup" ]; then
        backup_date=$(stat -c %y "/backup/files/$latest_file_backup" | cut -d' ' -f1)
        today=$(date +%Y-%m-%d)
        
        if [ "$backup_date" = "$today" ]; then
            log_info "✓ 文件备份正常 (最新: $latest_file_backup)"
        else
            log_warning "⚠ 文件备份可能过期 (最新: $backup_date)"
        fi
    else
        log_error "✗ 未找到文件备份"
    fi
}

# 日志分析
check_error_logs() {
    log_info "开始错误日志分析..."
    
    # 检查系统日志中的错误
    error_count=$(grep -c "ERROR\|FAILED\|CRITICAL" /var/log/syslog | tail -1)
    if [ "$error_count" -gt 0 ]; then
        log_warning "⚠ 系统日志中发现 $error_count 个错误"
        # 显示最近的5个错误
        grep "ERROR\|FAILED\|CRITICAL" /var/log/syslog | tail -5 | while read line; do
            log_warning "  $line"
        done
    else
        log_info "✓ 系统日志无明显错误"
    fi
    
    # 检查应用日志
    if [ -f /var/log/webapp/app.log ]; then
        app_errors=$(grep -c "ERROR\|Exception" /var/log/webapp/app.log | tail -1)
        if [ "$app_errors" -gt 0 ]; then
            log_warning "⚠ 应用日志中发现 $app_errors 个错误"
        else
            log_info "✓ 应用日志无明显错误"
        fi
    fi
}

# 安全检查
check_security_status() {
    log_info "开始安全状态检查..."
    
    # 检查失败登录尝试
    failed_logins=$(grep "Failed password" /var/log/auth.log | wc -l)
    if [ "$failed_logins" -gt 10 ]; then
        log_warning "⚠ 发现 $failed_logins 次失败登录尝试"
    else
        log_info "✓ 登录安全状态正常"
    fi
    
    # 检查防火墙状态
    if ufw status | grep -q "Status: active"; then
        log_info "✓ 防火墙状态正常"
    else
        log_warning "⚠ 防火墙可能未启用"
    fi
    
    # 检查磁盘空间（安全角度）
    if df -h | grep -E "9[0-9]%|100%"; then
        log_warning "⚠ 发现磁盘使用率过高，可能影响日志记录"
    else
        log_info "✓ 磁盘空间充足"
    fi
}

# 性能监控数据收集
collect_performance_metrics() {
    log_info "收集性能监控数据..."
    
    # 系统负载
    load_1min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    load_5min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $2}' | sed 's/,//')
    load_15min=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $3}')
    
    log_info "系统负载: 1分钟: $load_1min, 5分钟: $load_5min, 15分钟: $load_15min"
    
    # 内存详情
    mem_total=$(free -h | grep Mem | awk '{print $2}')
    mem_used=$(free -h | grep Mem | awk '{print $3}')
    mem_free=$(free -h | grep Mem | awk '{print $4}')
    
    log_info "内存状态: 总计: $mem_total, 已用: $mem_used, 可用: $mem_free"
    
    # 网络流量统计
    rx_bytes=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
    tx_bytes=$(cat /proc/net/dev | grep eth0 | awk '{print $10}')
    
    log_info "网络流量: 接收: $rx_bytes bytes, 发送: $tx_bytes bytes"
}

# 生成巡检报告
generate_patrol_report() {
    local report_date=$(date '+%Y-%m-%d')
    local report_file="/var/log/patrol-report-$report_date.html"
    
    cat > $report_file << EOF
<!DOCTYPE html>
<html>
<head>
    <title>IT基础设施日常巡检报告 - $report_date</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .ok { color: green; } .warning { color: orange; } .error { color: red; }
        .metric { background: #f9f9f9; padding: 5px; margin: 5px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IT基础设施日常巡检报告</h1>
        <p>巡检日期: $report_date</p>
        <p>巡检时间: $(date '+%H:%M:%S')</p>
        <p>巡检服务器: $(hostname)</p>
    </div>

    <div class="section">
        <h2>巡检汇总</h2>
        <div class="metric">
            <strong>巡检项目:</strong> 系统资源、服务状态、网络连通性、应用健康、数据库连接、备份状态、日志分析、安全检查<br>
            <strong>巡检结果:</strong> 详见下方各项检查结果<br>
            <strong>处理建议:</strong> 请关注标记为警告和错误的项目
        </div>
    </div>

    <div class="section">
        <h2>详细巡检日志</h2>
        <pre>$(tail -100 $PATROL_LOG)</pre>
    </div>

    <div class="section">
        <h2>系统资源状态</h2>
        <table>
            <tr><th>指标</th><th>当前值</th><th>阈值</th><th>状态</th></tr>
            <tr><td>CPU使用率</td><td>$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')</td><td>${THRESHOLD_CPU}%</td><td class="ok">正常</td></tr>
            <tr><td>内存使用率</td><td>$(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')</td><td>${THRESHOLD_MEMORY}%</td><td class="ok">正常</td></tr>
            <tr><td>系统负载</td><td>$(uptime | awk -F'load average:' '{print $2}')</td><td>CPU核心数x2</td><td class="ok">正常</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>下次巡检计划</h2>
        <p>下次巡检时间: $(date -d '+1 day' '+%Y-%m-%d %H:%M:%S')</p>
        <p>巡检负责人: $(whoami)</p>
    </div>
</body>
</html>
EOF
    
    log_info "巡检报告已生成: $report_file"
    
    # 发送邮件报告
    if command -v mail >/dev/null 2>&1; then
        echo "详细巡检报告请查看附件" | mail -s "IT基础设施巡检报告 - $report_date" -A $report_file $REPORT_EMAIL
        log_info "巡检报告已发送至: $REPORT_EMAIL"
    fi
}

# 主巡检函数
main_patrol() {
    log_info "========================================"
    log_info "开始IT基础设施日常巡检"
    log_info "========================================"
    
    check_system_resources
    check_service_status
    check_network_connectivity
    check_web_applications
    check_database_connections
    check_backup_status
    check_error_logs
    check_security_status
    collect_performance_metrics
    
    log_info "========================================"
    log_info "IT基础设施日常巡检完成"
    log_info "========================================"
    
    generate_patrol_report
}

# 执行巡检
main_patrol
```

## 2. 持续优化管理

### 2.1 性能优化管理

#### 性能监控分析系统
```python
#!/usr/bin/env python3
# 性能优化分析系统

import psutil
import time
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import json
import requests
from collections import deque

class PerformanceOptimizer:
    def __init__(self):
        self.metrics_history = {
            'cpu': deque(maxlen=1440),      # 24小时数据，每分钟采样
            'memory': deque(maxlen=1440),
            'disk_io': deque(maxlen=1440),
            'network_io': deque(maxlen=1440),
            'response_time': deque(maxlen=1440)
        }
        
        self.optimization_rules = {
            'cpu_optimization': {
                'threshold': 80,
                'actions': ['process_analysis', 'cpu_affinity', 'nice_adjustment']
            },
            'memory_optimization': {
                'threshold': 85,
                'actions': ['memory_cleanup', 'swap_optimization', 'cache_tuning']
            },
            'disk_optimization': {
                'threshold': 90,
                'actions': ['disk_cleanup', 'io_scheduler', 'file_compression']
            },
            'network_optimization': {
                'threshold': 80,
                'actions': ['connection_tuning', 'buffer_optimization', 'compression']
            }
        }
        
    def collect_performance_metrics(self):
        """收集性能指标"""
        
        # 系统指标
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        
        # 磁盘I/O
        disk_io = psutil.disk_io_counters()
        disk_io_rate = disk_io.read_bytes + disk_io.write_bytes
        
        # 网络I/O
        network_io = psutil.net_io_counters()
        network_io_rate = network_io.bytes_sent + network_io.bytes_recv
        
        # 应用响应时间
        response_time = self.measure_application_response_time()
        
        # 存储到历史记录
        timestamp = datetime.now()
        
        self.metrics_history['cpu'].append({
            'timestamp': timestamp,
            'value': cpu_percent
        })
        
        self.metrics_history['memory'].append({
            'timestamp': timestamp,
            'value': memory_percent
        })
        
        self.metrics_history['disk_io'].append({
            'timestamp': timestamp,
            'value': disk_io_rate
        })
        
        self.metrics_history['network_io'].append({
            'timestamp': timestamp,
            'value': network_io_rate
        })
        
        self.metrics_history['response_time'].append({
            'timestamp': timestamp,
            'value': response_time
        })
        
        return {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'disk_io': disk_io_rate,
            'network_io': network_io_rate,
            'response_time': response_time
        }
    
    def measure_application_response_time(self):
        """测量应用响应时间"""
        
        try:
            start_time = time.time()
            response = requests.get('https://app.company.local/api/health', timeout=10)
            end_time = time.time()
            
            if response.status_code == 200:
                return (end_time - start_time) * 1000  # 转换为毫秒
            else:
                return 99999  # 错误状态返回极大值
        except:
            return 99999
    
    def analyze_performance_trends(self):
        """分析性能趋势"""
        
        analysis_results = {}
        
        for metric_name, history in self.metrics_history.items():
            if len(history) < 60:  # 至少需要1小时数据
                continue
                
            values = [item['value'] for item in history]
            
            # 计算统计指标
            analysis_results[metric_name] = {
                'current': values[-1],
                'average_1h': np.mean(values[-60:]),  # 最近1小时平均值
                'average_24h': np.mean(values),       # 24小时平均值
                'max_24h': np.max(values),
                'min_24h': np.min(values),
                'trend': self.calculate_trend(values),
                'volatility': np.std(values),
                'peak_hours': self.identify_peak_hours(history)
            }
        
        return analysis_results
    
    def calculate_trend(self, values):
        """计算性能趋势"""
        
        if len(values) < 10:
            return 'insufficient_data'
        
        # 使用线性回归计算趋势
        x = np.arange(len(values))
        coefficients = np.polyfit(x, values, 1)
        slope = coefficients[0]
        
        if slope > 0.1:
            return 'increasing'
        elif slope < -0.1:
            return 'decreasing'
        else:
            return 'stable'
    
    def identify_peak_hours(self, history):
        """识别性能峰值时间段"""
        
        hourly_averages = {}
        
        for item in history:
            hour = item['timestamp'].hour
            if hour not in hourly_averages:
                hourly_averages[hour] = []
            hourly_averages[hour].append(item['value'])
        
        # 计算每小时平均值
        hourly_avg = {hour: np.mean(values) for hour, values in hourly_averages.items()}
        
        # 找出最高的3个小时
        peak_hours = sorted(hourly_avg.items(), key=lambda x: x[1], reverse=True)[:3]
        
        return [hour for hour, avg in peak_hours]
    
    def generate_optimization_recommendations(self, analysis_results):
        """生成优化建议"""
        
        recommendations = []
        
        for metric_name, analysis in analysis_results.items():
            current_value = analysis['current']
            trend = analysis['trend']
            peak_hours = analysis['peak_hours']
            
            # CPU优化建议
            if metric_name == 'cpu' and current_value > 80:
                if trend == 'increasing':
                    recommendations.append({
                        'type': 'cpu_optimization',
                        'priority': 'high',
                        'description': 'CPU使用率持续上升，建议进行进程分析和优化',
                        'actions': [
                            '分析CPU占用最高的进程',
                            '考虑增加CPU资源或优化算法',
                            '检查是否有死循环或低效代码',
                            '在低峰时段 {} 进行维护'.format(self.get_low_peak_hours(peak_hours))
                        ]
                    })
                else:
                    recommendations.append({
                        'type': 'cpu_monitoring',
                        'priority': 'medium',
                        'description': 'CPU使用率较高但趋势稳定，继续监控',
                        'actions': ['继续监控CPU使用情况', '准备扩容方案']
                    })
            
            # 内存优化建议
            if metric_name == 'memory' and current_value > 85:
                recommendations.append({
                    'type': 'memory_optimization',
                    'priority': 'high',
                    'description': '内存使用率过高，需要立即优化',
                    'actions': [
                        '清理不必要的缓存',
                        '重启内存泄漏的应用',
                        '增加swap空间',
                        '考虑增加物理内存'
                    ]
                })
            
            # 磁盘I/O优化建议
            if metric_name == 'disk_io' and analysis['volatility'] > 1000000:  # 高波动性
                recommendations.append({
                    'type': 'disk_optimization',
                    'priority': 'medium',
                    'description': '磁盘I/O波动较大，建议优化',
                    'actions': [
                        '优化数据库查询',
                        '调整I/O调度器',
                        '考虑使用SSD存储',
                        '实施数据分层存储'
                    ]
                })
            
            # 应用响应时间优化
            if metric_name == 'response_time' and current_value > 3000:  # 超过3秒
                recommendations.append({
                    'type': 'application_optimization',
                    'priority': 'high',
                    'description': '应用响应时间过长，严重影响用户体验',
                    'actions': [
                        '优化数据库查询',
                        '启用应用缓存',
                        '优化前端资源加载',
                        '考虑使用CDN',
                        '检查网络连接质量'
                    ]
                })
        
        # 资源规划建议
        if self.should_recommend_scaling(analysis_results):
            recommendations.append({
                'type': 'scaling_recommendation',
                'priority': 'high',
                'description': '建议进行资源扩容',
                'actions': [
                    '增加服务器实例',
                    '升级硬件配置',
                    '实施负载均衡',
                    '考虑云资源弹性扩展'
                ]
            })
        
        return recommendations
    
    def should_recommend_scaling(self, analysis_results):
        """判断是否需要扩容"""
        
        high_usage_count = 0
        
        for metric_name, analysis in analysis_results.items():
            if metric_name in ['cpu', 'memory']:
                if analysis['average_1h'] > 80:
                    high_usage_count += 1
        
        return high_usage_count >= 2
    
    def get_low_peak_hours(self, peak_hours):
        """获取低峰时段"""
        
        all_hours = set(range(24))
        peak_set = set(peak_hours)
        low_peak_hours = list(all_hours - peak_set)
        
        # 推荐凌晨时段
        night_hours = [h for h in low_peak_hours if 1 <= h <= 5]
        if night_hours:
            return f"{min(night_hours):02d}:00-{max(night_hours):02d}:00"
        else:
            return f"{min(low_peak_hours):02d}:00-{max(low_peak_hours):02d}:00"
    
    def implement_automatic_optimizations(self, recommendations):
        """实施自动优化措施"""
        
        implemented_actions = []
        
        for recommendation in recommendations:
            if recommendation['type'] == 'memory_optimization':
                # 自动清理系统缓存
                try:
                    import subprocess
                    subprocess.run(['sudo', 'sync'], check=True)
                    subprocess.run(['sudo', 'sysctl', 'vm.drop_caches=3'], check=True)
                    implemented_actions.append('已清理系统缓存')
                except:
                    pass
            
            elif recommendation['type'] == 'disk_optimization':
                # 自动清理临时文件
                try:
                    subprocess.run(['sudo', 'find', '/tmp', '-type', 'f', '-atime', '+7', '-delete'], check=True)
                    implemented_actions.append('已清理过期临时文件')
                except:
                    pass
        
        return implemented_actions
    
    def generate_optimization_report(self, analysis_results, recommendations, implemented_actions):
        """生成优化报告"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'performance_optimization_report_{timestamp}.html'
        
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>性能优化分析报告</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ background: #f9f9f9; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .recommendation {{ background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .high {{ border-left: 5px solid #dc3545; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>IT基础设施性能优化分析报告</h1>
        <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>分析周期: 24小时</p>
    </div>

    <div class="section">
        <h2>性能指标分析</h2>
        <table>
            <tr><th>指标</th><th>当前值</th><th>1小时均值</th><th>24小时均值</th><th>趋势</th><th>峰值时段</th></tr>
        '''
        
        for metric_name, analysis in analysis_results.items():
            html_content += f'''
            <tr>
                <td>{metric_name.upper()}</td>
                <td>{analysis['current']:.2f}</td>
                <td>{analysis['average_1h']:.2f}</td>
                <td>{analysis['average_24h']:.2f}</td>
                <td>{analysis['trend']}</td>
                <td>{', '.join([f'{h:02d}:00' for h in analysis['peak_hours']])}</td>
            </tr>
            '''
        
        html_content += '''
        </table>
    </div>

    <div class="section">
        <h2>优化建议</h2>
        '''
        
        for rec in recommendations:
            priority_class = rec['priority']
            html_content += f'''
            <div class="recommendation {priority_class}">
                <h3>{rec['type']} (优先级: {rec['priority']})</h3>
                <p>{rec['description']}</p>
                <ul>
            '''
            for action in rec['actions']:
                html_content += f'<li>{action}</li>'
            
            html_content += '''
                </ul>
            </div>
            '''
        
        html_content += f'''
    </div>

    <div class="section">
        <h2>已实施的自动优化</h2>
        <ul>
        '''
        
        for action in implemented_actions:
            html_content += f'<li>{action}</li>'
        
        html_content += '''
        </ul>
    </div>

    <div class="section">
        <h2>下一步行动计划</h2>
        <ol>
            <li>优先处理高优先级建议</li>
            <li>在低峰时段实施系统优化</li>
            <li>监控优化效果</li>
            <li>定期更新性能基线</li>
        </ol>
    </div>
</body>
</html>
        '''
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"性能优化报告已生成: {report_file}")
        return report_file
    
    def run_performance_optimization_cycle(self):
        """运行完整的性能优化周期"""
        
        print("开始性能优化分析...")
        
        # 收集性能指标
        current_metrics = self.collect_performance_metrics()
        print(f"当前性能指标: {current_metrics}")
        
        # 分析性能趋势
        analysis_results = self.analyze_performance_trends()
        print("性能趋势分析完成")
        
        # 生成优化建议
        recommendations = self.generate_optimization_recommendations(analysis_results)
        print(f"生成 {len(recommendations)} 条优化建议")
        
        # 实施自动优化
        implemented_actions = self.implement_automatic_optimizations(recommendations)
        print(f"已实施 {len(implemented_actions)} 项自动优化")
        
        # 生成报告
        report_file = self.generate_optimization_report(analysis_results, recommendations, implemented_actions)
        
        return {
            'analysis_results': analysis_results,
            'recommendations': recommendations,
            'implemented_actions': implemented_actions,
            'report_file': report_file
        }

# 使用示例
if __name__ == "__main__":
    optimizer = PerformanceOptimizer()
    
    # 模拟数据收集（实际运行中应该定期调用）
    for i in range(100):
        optimizer.collect_performance_metrics()
        time.sleep(1)  # 实际环境中可能是60秒
    
    # 运行优化分析
    results = optimizer.run_performance_optimization_cycle()
    print("性能优化分析完成！")
```

### 2.2 容量规划管理

#### 容量预测分析系统
```python
#!/usr/bin/env python3
# 容量预测分析系统

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
import json
import warnings
warnings.filterwarnings('ignore')

class CapacityPlanner:
    def __init__(self):
        self.historical_data = {
            'cpu': [],
            'memory': [],
            'storage': [],
            'network': [],
            'users': [],
            'transactions': []
        }
        
        self.growth_models = {}
        self.capacity_thresholds = {
            'cpu': 80,      # CPU使用率阈值
            'memory': 85,   # 内存使用率阈值
            'storage': 90,  # 存储使用率阈值
            'network': 80   # 网络带宽使用率阈值
        }
        
    def load_historical_data(self, data_source):
        """加载历史数据"""
        
        # 模拟加载过去12个月的数据
        base_date = datetime.now() - timedelta(days=365)
        
        for i in range(365):
            date = base_date + timedelta(days=i)
            
            # 模拟数据增长趋势
            growth_factor = 1 + (i / 365) * 0.3  # 年增长30%
            seasonal_factor = 1 + 0.1 * np.sin(2 * np.pi * i / 365)  # 季节性波动
            
            self.historical_data['cpu'].append({
                'date': date,
                'usage': min(50 + np.random.normal(0, 5) * growth_factor * seasonal_factor, 100)
            })
            
            self.historical_data['memory'].append({
                'date': date,
                'usage': min(60 + np.random.normal(0, 8) * growth_factor * seasonal_factor, 100)
            })
            
            self.historical_data['storage'].append({
                'date': date,
                'usage': min(40 + (i / 365) * 50 + np.random.normal(0, 3), 100)  # 存储稳定增长
            })
            
            self.historical_data['users'].append({
                'date': date,
                'count': max(100 + (i / 365) * 300 + np.random.normal(0, 10), 0)  # 用户数增长
            })
            
            self.historical_data['transactions'].append({
                'date': date,
                'count': max(1000 + (i / 365) * 5000 + np.random.normal(0, 100) * seasonal_factor, 0)
            })
        
        print("历史数据加载完成")
    
    def build_prediction_models(self):
        """构建预测模型"""
        
        for metric in ['cpu', 'memory', 'storage', 'users', 'transactions']:
            data = self.historical_data[metric]
            
            if len(data) < 30:
                continue
            
            # 准备数据
            df = pd.DataFrame(data)
            df['date'] = pd.to_datetime(df['date'])
            df['days'] = (df['date'] - df['date'].min()).dt.days
            
            X = df[['days']].values
            if metric in ['cpu', 'memory', 'storage']:
                y = df['usage'].values
            else:
                y = df['count'].values
            
            # 尝试不同的模型
            models = {}
            
            # 线性回归模型
            linear_model = LinearRegression()
            linear_model.fit(X, y)
            models['linear'] = {
                'model': linear_model,
                'score': linear_model.score(X, y)
            }
            
            # 多项式回归模型
            poly_features = PolynomialFeatures(degree=2)
            X_poly = poly_features.fit_transform(X)
            poly_model = LinearRegression()
            poly_model.fit(X_poly, y)
            models['polynomial'] = {
                'model': poly_model,
                'transformer': poly_features,
                'score': poly_model.score(X_poly, y)
            }
            
            # 选择最佳模型
            best_model_name = max(models.keys(), key=lambda k: models[k]['score'])
            self.growth_models[metric] = {
                'type': best_model_name,
                'model': models[best_model_name],
                'baseline_date': df['date'].min(),
                'r2_score': models[best_model_name]['score']
            }
            
            print(f"{metric} 预测模型构建完成 (R²: {models[best_model_name]['score']:.3f})")
    
    def predict_future_capacity(self, months_ahead=12):
        """预测未来容量需求"""
        
        predictions = {}
        base_date = datetime.now()
        
        for metric, model_info in self.growth_models.items():
            model_type = model_info['type']
            model_data = model_info['model']
            baseline_date = model_info['baseline_date']
            
            future_predictions = []
            
            for month in range(1, months_ahead + 1):
                future_date = base_date + timedelta(days=30 * month)
                days_from_baseline = (future_date - baseline_date).days
                
                X_future = np.array([[days_from_baseline]])
                
                if model_type == 'linear':
                    predicted_value = model_data['model'].predict(X_future)[0]
                elif model_type == 'polynomial':
                    X_future_poly = model_data['transformer'].transform(X_future)
                    predicted_value = model_data['model'].predict(X_future_poly)[0]
                
                future_predictions.append({
                    'date': future_date,
                    'predicted_value': max(0, predicted_value),
                    'month': month
                })
            
            predictions[metric] = future_predictions
        
        return predictions
    
    def analyze_capacity_requirements(self, predictions):
        """分析容量需求"""
        
        capacity_analysis = {}
        
        for metric, prediction_data in predictions.items():
            if metric not in self.capacity_thresholds:
                continue
            
            threshold = self.capacity_thresholds[metric]
            analysis = {
                'current_usage': prediction_data[0]['predicted_value'],
                'threshold': threshold,
                'months_to_threshold': None,
                'recommended_action': None,
                'urgency': 'low'
            }
            
            # 计算到达阈值的时间
            for pred in prediction_data:
                if pred['predicted_value'] >= threshold:
                    analysis['months_to_threshold'] = pred['month']
                    break
            
            # 确定紧急程度和建议
            if analysis['months_to_threshold']:
                if analysis['months_to_threshold'] <= 3:
                    analysis['urgency'] = 'high'
                    analysis['recommended_action'] = '立即扩容'
                elif analysis['months_to_threshold'] <= 6:
                    analysis['urgency'] = 'medium'
                    analysis['recommended_action'] = '计划扩容'
                else:
                    analysis['urgency'] = 'low'
                    analysis['recommended_action'] = '监控观察'
            else:
                analysis['recommended_action'] = '当前容量充足'
            
            capacity_analysis[metric] = analysis
        
        return capacity_analysis
    
    def calculate_scaling_recommendations(self, capacity_analysis, predictions):
        """计算扩容建议"""
        
        scaling_recommendations = []
        
        # CPU扩容建议
        if 'cpu' in capacity_analysis and capacity_analysis['cpu']['urgency'] in ['high', 'medium']:
            current_cpu = capacity_analysis['cpu']['current_usage']
            target_usage = 70  # 目标使用率70%
            scaling_factor = current_cpu / target_usage
            
            scaling_recommendations.append({
                'resource': 'CPU',
                'current_cores': 8,  # 假设当前8核
                'recommended_cores': int(8 * scaling_factor) + 2,
                'scaling_factor': scaling_factor,
                'justification': f'当前CPU使用率{current_cpu:.1f}%，预计{capacity_analysis["cpu"]["months_to_threshold"]}个月达到阈值',
                'cost_estimate': self.estimate_cpu_cost(int(8 * scaling_factor) + 2 - 8),
                'implementation_timeline': '2-4周'
            })
        
        # 内存扩容建议
        if 'memory' in capacity_analysis and capacity_analysis['memory']['urgency'] in ['high', 'medium']:
            current_memory = capacity_analysis['memory']['current_usage']
            target_usage = 75
            scaling_factor = current_memory / target_usage
            
            scaling_recommendations.append({
                'resource': '内存',
                'current_capacity': '64GB',
                'recommended_capacity': f'{int(64 * scaling_factor) + 16}GB',
                'scaling_factor': scaling_factor,
                'justification': f'当前内存使用率{current_memory:.1f}%，预计{capacity_analysis["memory"]["months_to_threshold"]}个月达到阈值',
                'cost_estimate': self.estimate_memory_cost(int(64 * scaling_factor) + 16 - 64),
                'implementation_timeline': '1-2周'
            })
        
        # 存储扩容建议
        if 'storage' in capacity_analysis and capacity_analysis['storage']['urgency'] in ['high', 'medium']:
            current_storage = capacity_analysis['storage']['current_usage']
            
            # 基于增长趋势计算所需存储
            storage_predictions = predictions['storage']
            future_12m = storage_predictions[-1]['predicted_value']
            additional_storage = max(100, (future_12m - current_storage) * 1.2)  # 20%缓冲
            
            scaling_recommendations.append({
                'resource': '存储',
                'current_capacity': '10TB',
                'recommended_addition': f'{additional_storage:.0f}GB',
                'total_capacity': f'{10*1024 + additional_storage:.0f}GB',
                'justification': f'预计12个月内存储使用率将达到{future_12m:.1f}%',
                'cost_estimate': self.estimate_storage_cost(additional_storage),
                'implementation_timeline': '1-3周'
            })
        
        # 网络带宽扩容建议
        if 'network' in predictions:
            network_predictions = predictions['network']
            if network_predictions:
                future_6m = network_predictions[5]['predicted_value']  # 6个月后
                
                if future_6m > 80:  # 预计6个月后超过80%
                    scaling_recommendations.append({
                        'resource': '网络带宽',
                        'current_bandwidth': '1Gbps',
                        'recommended_bandwidth': '2Gbps',
                        'scaling_factor': 2,
                        'justification': f'预计6个月内网络使用率将达到{future_6m:.1f}%',
                        'cost_estimate': self.estimate_network_cost(),
                        'implementation_timeline': '2-6周'
                    })
        
        return scaling_recommendations
    
    def estimate_cpu_cost(self, additional_cores):
        """估算CPU成本"""
        cost_per_core = 500  # 每核500元
        return additional_cores * cost_per_core
    
    def estimate_memory_cost(self, additional_gb):
        """估算内存成本"""
        cost_per_gb = 50  # 每GB 50元
        return additional_gb * cost_per_gb
    
    def estimate_storage_cost(self, additional_gb):
        """估算存储成本"""
        cost_per_gb = 3  # 每GB 3元
        return additional_gb * cost_per_gb
    
    def estimate_network_cost(self):
        """估算网络升级成本"""
        return 50000  # 网络升级固定成本5万元
    
    def generate_capacity_planning_report(self, predictions, capacity_analysis, scaling_recommendations):
        """生成容量规划报告"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'capacity_planning_report_{timestamp}.html'
        
        html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>IT基础设施容量规划报告</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ background: #f9f9f9; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .recommendation {{ background: #e7f3ff; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high {{ border-left: 5px solid #dc3545; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .cost {{ font-weight: bold; color: #e67e22; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>IT基础设施容量规划报告</h1>
        <p>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>预测周期: 未来12个月</p>
        <p>分析基于: 过去12个月历史数据</p>
    </div>

    <div class="section">
        <h2>容量现状分析</h2>
        <table>
            <tr><th>资源类型</th><th>当前使用率</th><th>阈值</th><th>到达阈值时间</th><th>紧急程度</th><th>建议行动</th></tr>
        '''
        
        for metric, analysis in capacity_analysis.items():
            urgency_class = analysis['urgency']
            months_to_threshold = analysis['months_to_threshold'] if analysis['months_to_threshold'] else 'N/A'
            
            html_content += f'''
            <tr class="{urgency_class}">
                <td>{metric.upper()}</td>
                <td>{analysis['current_usage']:.1f}%</td>
                <td>{analysis['threshold']}%</td>
                <td>{months_to_threshold} 个月</td>
                <td>{analysis['urgency']}</td>
                <td>{analysis['recommended_action']}</td>
            </tr>
            '''
        
        html_content += '''
        </table>
    </div>

    <div class="section">
        <h2>扩容建议</h2>
        '''
        
        total_cost = 0
        for rec in scaling_recommendations:
            total_cost += rec.get('cost_estimate', 0)
            html_content += f'''
            <div class="recommendation">
                <h3>{rec['resource']} 扩容建议</h3>
                <p><strong>理由:</strong> {rec['justification']}</p>
                <p><strong>当前配置:</strong> {rec.get('current_capacity', rec.get('current_cores', 'N/A'))}</p>
                <p><strong>建议配置:</strong> {rec.get('recommended_capacity', rec.get('recommended_cores', rec.get('recommended_bandwidth', 'N/A')))}</p>
                <p><strong>实施时间:</strong> {rec['implementation_timeline']}</p>
                <p class="cost"><strong>预估成本:</strong> ¥{rec.get('cost_estimate', 0):,}</p>
            </div>
            '''
        
        html_content += f'''
    </div>

    <div class="section">
        <h2>投资预算汇总</h2>
        <div class="metric">
            <h3>总投资预算: <span class="cost">¥{total_cost:,}</span></h3>
            <ul>
        '''
        
        for rec in scaling_recommendations:
            html_content += f'<li>{rec["resource"]}: ¥{rec.get("cost_estimate", 0):,}</li>'
        
        html_content += f'''
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>实施计划建议</h2>
        <ol>
            <li><strong>短期 (1-3个月):</strong> 实施高紧急度扩容项目</li>
            <li><strong>中期 (3-6个月):</strong> 执行中等紧急度扩容计划</li>
            <li><strong>长期 (6-12个月):</strong> 建立弹性扩容机制</li>
            <li><strong>持续监控:</strong> 每月更新容量预测模型</li>
        </ol>
    </div>

    <div class="section">
        <h2>风险评估</h2>
        <ul>
            <li>如不及时扩容，可能导致系统性能下降</li>
            <li>业务增长可能超出预期，需要额外缓冲</li>
            <li>硬件采购和部署需要一定周期</li>
            <li>建议预留20%容量缓冲以应对突发增长</li>
        </ul>
    </div>
</body>
</html>
        '''
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"容量规划报告已生成: {report_file}")
        return report_file
    
    def run_capacity_planning_analysis(self):
        """运行完整的容量规划分析"""
        
        print("开始容量规划分析...")
        
        # 加载历史数据
        self.load_historical_data('database')
        
        # 构建预测模型
        self.build_prediction_models()
        
        # 预测未来容量
        predictions = self.predict_future_capacity(12)
        
        # 分析容量需求
        capacity_analysis = self.analyze_capacity_requirements(predictions)
        
        # 计算扩容建议
        scaling_recommendations = self.calculate_scaling_recommendations(capacity_analysis, predictions)
        
        # 生成报告
        report_file = self.generate_capacity_planning_report(predictions, capacity_analysis, scaling_recommendations)
        
        print("容量规划分析完成！")
        
        return {
            'predictions': predictions,
            'capacity_analysis': capacity_analysis,
            'scaling_recommendations': scaling_recommendations,
            'report_file': report_file
        }

# 使用示例
if __name__ == "__main__":
    planner = CapacityPlanner()
    results = planner.run_capacity_planning_analysis()
    
    print(f"分析完成，共生成 {len(results['scaling_recommendations'])} 条扩容建议")
    total_cost = sum(rec.get('cost_estimate', 0) for rec in results['scaling_recommendations'])
    print(f"预估总投资: ¥{total_cost:,}")
```

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"id": "1", "content": "\u521b\u5efaIT\u57fa\u7840\u8bbe\u65bd\u7ba1\u7406\u603b\u4f53\u89c4\u5212\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "2", "content": "\u521b\u5efa\u89c4\u5212\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "3", "content": "\u521b\u5efa\u51c6\u5907\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "4", "content": "\u521b\u5efa\u914d\u7f6e\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "5", "content": "\u521b\u5efa\u90e8\u7f72\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "6", "content": "\u521b\u5efa\u843d\u5730\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}, {"id": "7", "content": "\u521b\u5efa\u7ba1\u7406\u9636\u6bb5\u8be6\u7ec6\u6587\u6863", "status": "completed", "priority": "high"}]