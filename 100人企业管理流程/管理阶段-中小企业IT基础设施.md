# 管理阶段 - 中小企业IT基础设施 (50-100人)

## 阶段概述
管理阶段是IT基础设施的持续运营阶段，重点关注日常运维、性能优化、安全管理、成本控制和服务持续改进，确保系统稳定高效运行并支撑业务发展。

## 1. 日常运维管理

### 1.1 运维体系架构

#### 运维管理框架
```yaml
运维管理层级:
  战略层:
    - IT服务战略规划
    - 技术发展路线图
    - 投资预算管理
    - 供应商关系管理
    
  管理层:
    - 服务水平管理(SLM)
    - 变更管理(Change Management)
    - 问题管理(Problem Management)
    - 知识管理(Knowledge Management)
    
  操作层:
    - 事件管理(Incident Management)
    - 配置管理(Configuration Management)
    - 发布管理(Release Management)
    - 监控和告警管理

运维流程设计:
  预防性运维:
    - 定期系统健康检查
    - 预防性维护计划
    - 容量规划和管理
    - 安全风险评估
    
  响应性运维:
    - 故障快速响应
    - 事件根因分析
    - 问题解决跟踪
    - 用户支持服务
    
  改进性运维:
    - 性能持续优化
    - 流程标准化
    - 自动化工具开发
    - 最佳实践推广
```

#### 运维组织架构
```bash
#!/bin/bash
# 运维组织架构配置脚本

# 创建运维角色定义
create_operations_roles() {
    echo "=== 定义运维角色职责 ==="
    
    cat > /etc/itil/roles_definition.yaml << 'EOF'
运维角色定义:
  IT运维经理:
    职责:
      - 制定运维策略和标准
      - 管理运维团队和资源
      - SLA协议制定和监督
      - 与业务部门沟通协调
    技能要求:
      - ITIL认证
      - 项目管理经验
      - 团队管理能力
      - 业务理解能力
    
  系统管理员:
    职责:
      - 服务器系统管理
      - 数据库管理维护
      - 系统性能监控
      - 安全策略实施
    技能要求:
      - Linux/Windows系统管理
      - 数据库管理(MySQL/PostgreSQL)
      - 虚拟化技术(VMware/KVM)
      - 脚本编程能力
    
  网络管理员:
    职责:
      - 网络设备管理
      - 网络性能优化
      - 网络安全管理
      - 故障排除
    技能要求:
      - 网络设备配置(思科/华为)
      - 网络协议深度理解
      - 防火墙和VPN管理
      - 网络监控工具使用
    
  桌面支持工程师:
    职责:
      - 用户设备支持
      - 软件安装配置
      - 用户培训指导
      - 现场技术支持
    技能要求:
      - Windows/macOS支持
      - 办公软件熟练
      - 硬件故障诊断
      - 用户沟通技巧
EOF
    
    echo "运维角色定义完成"
}

# 建立值班轮换制度
setup_duty_rotation() {
    echo "=== 建立值班轮换制度 ==="
    
    cat > /etc/itil/duty_schedule.py << 'EOF'
#!/usr/bin/env python3
# 值班轮换管理系统

import json
import datetime
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class DutyPerson:
    name: str
    phone: str
    email: str
    level: str  # L1, L2, L3
    skills: List[str]

class DutyScheduler:
    def __init__(self):
        self.duty_persons = [
            DutyPerson("张工程师", "138-0000-0001", "zhang@company.com", "L3", ["服务器", "数据库", "网络"]),
            DutyPerson("李工程师", "138-0000-0002", "li@company.com", "L2", ["网络", "安全"]),
            DutyPerson("王工程师", "138-0000-0003", "wang@company.com", "L2", ["服务器", "应用"]),
            DutyPerson("刘工程师", "138-0000-0004", "liu@company.com", "L1", ["桌面支持"])
        ]
    
    def generate_monthly_schedule(self, year: int, month: int) -> Dict:
        """生成月度值班表"""
        import calendar
        
        # 获取当月天数
        days_in_month = calendar.monthrange(year, month)[1]
        schedule = {}
        
        # 工作日值班(周一到周五 9:00-18:00)
        workday_persons = [p for p in self.duty_persons if p.level in ["L1", "L2"]]
        
        # 非工作时间值班(18:00-次日9:00, 周末全天)
        afterhours_persons = [p for p in self.duty_persons if p.level in ["L2", "L3"]]
        
        for day in range(1, days_in_month + 1):
            date = datetime.date(year, month, day)
            weekday = date.weekday()  # 0=周一, 6=周日
            
            if weekday < 5:  # 工作日
                schedule[str(date)] = {
                    "primary": workday_persons[day % len(workday_persons)].name,
                    "secondary": afterhours_persons[day % len(afterhours_persons)].name
                }
            else:  # 周末
                schedule[str(date)] = {
                    "primary": afterhours_persons[day % len(afterhours_persons)].name,
                    "secondary": afterhours_persons[(day + 1) % len(afterhours_persons)].name
                }
        
        return schedule
    
    def get_current_duty_person(self) -> Dict:
        """获取当前值班人员"""
        now = datetime.datetime.now()
        schedule = self.generate_monthly_schedule(now.year, now.month)
        today_schedule = schedule.get(str(now.date()), {})
        
        # 判断是否工作时间
        is_workhours = (now.weekday() < 5 and 9 <= now.hour < 18)
        
        if is_workhours:
            duty_person_name = today_schedule.get("primary")
        else:
            duty_person_name = today_schedule.get("secondary")
        
        # 获取值班人员详细信息
        duty_person = next((p for p in self.duty_persons if p.name == duty_person_name), None)
        
        return {
            "name": duty_person.name if duty_person else "未安排",
            "phone": duty_person.phone if duty_person else "",
            "email": duty_person.email if duty_person else "",
            "level": duty_person.level if duty_person else "",
            "is_workhours": is_workhours
        }

# 使用示例
if __name__ == "__main__":
    scheduler = DutyScheduler()
    current_duty = scheduler.get_current_duty_person()
    print(f"当前值班人员: {json.dumps(current_duty, indent=2, ensure_ascii=False)}")
    
    # 生成本月值班表
    now = datetime.datetime.now()
    monthly_schedule = scheduler.generate_monthly_schedule(now.year, now.month)
    print(f"\n{now.year}年{now.month}月值班表:")
    for date, duty in monthly_schedule.items():
        print(f"{date}: 主值班-{duty['primary']}, 备值班-{duty['secondary']}")
EOF
    
    chmod +x /etc/itil/duty_schedule.py
    echo "值班轮换制度建立完成"
}

# 创建运维SOP标准
create_sop_standards() {
    echo "=== 创建运维SOP标准 ==="
    
    mkdir -p /etc/itil/sop
    
    # 系统监控SOP
    cat > /etc/itil/sop/system_monitoring.md << 'EOF'
# 系统监控标准操作程序 (SOP)

## 目的
建立标准化的系统监控流程，确保及时发现和处理系统异常。

## 适用范围
适用于所有生产环境服务器和关键业务系统。

## 操作流程

### 日常监控检查 (每日 9:00)
1. **登录监控系统**
   - 访问 Zabbix 监控界面
   - 检查仪表板整体状态
   - 确认所有监控项正常

2. **系统资源检查**
   - CPU使用率 < 80%
   - 内存使用率 < 85%
   - 磁盘使用率 < 80%
   - 网络吞吐量正常

3. **服务状态检查**
   - Web服务 (Apache/Nginx)
   - 数据库服务 (MySQL)
   - 邮件服务 (Postfix)
   - 文件服务 (Samba/NFS)

4. **日志检查**
   - 系统错误日志
   - 应用错误日志
   - 安全日志
   - 异常访问记录

### 告警处理流程
1. **告警接收**
   - 通过邮件/短信接收告警
   - 确认告警的严重级别
   - 记录告警时间和内容

2. **初步诊断**
   - 登录相关系统检查
   - 确认问题影响范围
   - 评估处理紧急程度

3. **问题处理**
   - 按照预定的处理程序操作
   - 记录处理过程和结果
   - 确认问题是否解决

4. **后续跟踪**
   - 监控系统恢复情况
   - 分析问题根本原因
   - 更新知识库和文档

## 升级机制
- L1问题: 30分钟内无法解决，升级到L2
- L2问题: 2小时内无法解决，升级到L3
- 紧急问题: 立即通知值班经理

## 记录要求
所有监控检查和问题处理过程必须记录在运维日志中。
EOF
    
    # 备份恢复SOP
    cat > /etc/itil/sop/backup_recovery.md << 'EOF'
# 备份与恢复标准操作程序 (SOP)

## 备份策略

### 日备份 (每日 23:00)
1. **数据库备份**
   ```bash
   mysqldump -u backup_user -p --all-databases --single-transaction > /backup/daily/mysql_$(date +%Y%m%d).sql
   ```

2. **应用数据备份**
   ```bash
   tar -czf /backup/daily/webapp_$(date +%Y%m%d).tar.gz /var/www/html
   ```

3. **配置文件备份**
   ```bash
   tar -czf /backup/daily/configs_$(date +%Y%m%d).tar.gz /etc
   ```

### 周备份 (每周日 01:00)
1. **完整系统备份**
   ```bash
   rsync -av --exclude=/proc --exclude=/sys --exclude=/dev / /backup/weekly/system_$(date +%Y%m%d)/
   ```

### 月备份 (每月1日 02:00)
1. **归档备份**
   - 将月度数据压缩归档
   - 传输到异地存储
   - 验证备份完整性

## 恢复流程

### 数据库恢复
1. **停止应用服务**
   ```bash
   systemctl stop apache2
   ```

2. **恢复数据库**
   ```bash
   mysql -u root -p < /backup/mysql_backup.sql
   ```

3. **验证数据完整性**
   ```bash
   mysql -u root -p -e "SELECT COUNT(*) FROM important_table;"
   ```

4. **启动应用服务**
   ```bash
   systemctl start apache2
   ```

### 系统恢复
1. **准备恢复环境**
2. **恢复系统文件**
3. **重新配置服务**
4. **测试系统功能**

## 验证程序
每月第一个周六进行备份恢复测试，确保备份文件可用性。
EOF
    
    echo "运维SOP标准创建完成"
}

# 主函数
main() {
    case $1 in
        "roles")
            create_operations_roles
            ;;
        "duty")
            setup_duty_rotation
            ;;
        "sop")
            create_sop_standards
            ;;
        "all")
            create_operations_roles
            setup_duty_rotation
            create_sop_standards
            ;;
        *)
            echo "使用方法: $0 {roles|duty|sop|all}"
            ;;
    esac
}

main "$@"
```

### 1.2 自动化运维

#### 自动化监控脚本
```python
#!/usr/bin/env python3
# 自动化运维监控系统

import os
import sys
import json
import psutil
import smtplib
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AutomatedMonitoring:
    def __init__(self, config_file: str = "/etc/monitoring/config.json"):
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.alerts_sent = {}  # 防止重复告警
        
    def load_config(self, config_file: str) -> Dict:
        """加载监控配置"""
        default_config = {
            "thresholds": {
                "cpu_warning": 80,
                "cpu_critical": 90,
                "memory_warning": 85,
                "memory_critical": 95,
                "disk_warning": 80,
                "disk_critical": 90,
                "load_warning": 2.0,
                "load_critical": 4.0
            },
            "smtp": {
                "host": "smtp.office365.com",
                "port": 587,
                "username": "alert@company.com",
                "password": "your_password"
            },
            "recipients": ["admin@company.com", "it-team@company.com"],
            "check_interval": 300,  # 5分钟
            "alert_cooldown": 1800  # 30分钟内不重复告警
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            return default_config
    
    def setup_logging(self):
        """设置日志"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/automated_monitoring.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def check_system_resources(self) -> Dict:
        """检查系统资源使用情况"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # 内存使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # 磁盘使用率
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": (usage.used / usage.total) * 100
                    }
                except PermissionError:
                    continue
            
            # 系统负载
            load_avg = os.getloadavg()
            
            # 网络连接数
            connections = len(psutil.net_connections())
            
            # 运行的进程数
            process_count = len(psutil.pids())
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_available": memory.available,
                "disk_usage": disk_usage,
                "load_average": {
                    "1min": load_avg[0],
                    "5min": load_avg[1],
                    "15min": load_avg[2]
                },
                "network_connections": connections,
                "process_count": process_count
            }
            
        except Exception as e:
            self.logger.error(f"系统资源检查失败: {str(e)}")
            return {}
    
    def check_services(self) -> Dict:
        """检查系统服务状态"""
        services_to_check = [
            "apache2", "nginx", "mysql", "postgresql",
            "postfix", "ssh", "cron", "rsyslog"
        ]
        
        service_status = {}
        
        for service in services_to_check:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True
                )
                service_status[service] = {
                    "active": result.returncode == 0,
                    "status": result.stdout.strip()
                }
            except Exception as e:
                service_status[service] = {
                    "active": False,
                    "status": f"检查失败: {str(e)}"
                }
        
        return service_status
    
    def check_disk_space(self) -> Dict:
        """检查磁盘空间并清理临时文件"""
        cleanup_actions = []
        
        # 检查需要清理的目录
        cleanup_dirs = [
            "/tmp",
            "/var/tmp", 
            "/var/log",
            "/var/cache/apt"
        ]
        
        for directory in cleanup_dirs:
            if os.path.exists(directory):
                try:
                    # 计算目录大小
                    total_size = 0
                    for dirpath, dirnames, filenames in os.walk(directory):
                        for filename in filenames:
                            filepath = os.path.join(dirpath, filename)
                            try:
                                total_size += os.path.getsize(filepath)
                            except (OSError, IOError):
                                continue
                    
                    if total_size > 1024 * 1024 * 100:  # 大于100MB
                        cleanup_actions.append({
                            "directory": directory,
                            "size_mb": total_size / (1024 * 1024),
                            "action_needed": True
                        })
                        
                except Exception as e:
                    self.logger.error(f"检查目录 {directory} 失败: {str(e)}")
        
        return {"cleanup_actions": cleanup_actions}
    
    def analyze_performance(self, metrics: Dict) -> List[Dict]:
        """分析性能指标并生成告警"""
        alerts = []
        thresholds = self.config["thresholds"]
        
        # CPU告警
        if metrics.get("cpu_percent", 0) > thresholds["cpu_critical"]:
            alerts.append({
                "level": "CRITICAL",
                "type": "CPU",
                "message": f"CPU使用率过高: {metrics['cpu_percent']:.1f}%",
                "value": metrics["cpu_percent"],
                "threshold": thresholds["cpu_critical"]
            })
        elif metrics.get("cpu_percent", 0) > thresholds["cpu_warning"]:
            alerts.append({
                "level": "WARNING", 
                "type": "CPU",
                "message": f"CPU使用率较高: {metrics['cpu_percent']:.1f}%",
                "value": metrics["cpu_percent"],
                "threshold": thresholds["cpu_warning"]
            })
        
        # 内存告警
        if metrics.get("memory_percent", 0) > thresholds["memory_critical"]:
            alerts.append({
                "level": "CRITICAL",
                "type": "MEMORY",
                "message": f"内存使用率过高: {metrics['memory_percent']:.1f}%",
                "value": metrics["memory_percent"],
                "threshold": thresholds["memory_critical"]
            })
        elif metrics.get("memory_percent", 0) > thresholds["memory_warning"]:
            alerts.append({
                "level": "WARNING",
                "type": "MEMORY", 
                "message": f"内存使用率较高: {metrics['memory_percent']:.1f}%",
                "value": metrics["memory_percent"],
                "threshold": thresholds["memory_warning"]
            })
        
        # 磁盘告警
        for mountpoint, usage in metrics.get("disk_usage", {}).items():
            if usage["percent"] > thresholds["disk_critical"]:
                alerts.append({
                    "level": "CRITICAL",
                    "type": "DISK",
                    "message": f"磁盘空间不足 {mountpoint}: {usage['percent']:.1f}%",
                    "value": usage["percent"],
                    "threshold": thresholds["disk_critical"]
                })
            elif usage["percent"] > thresholds["disk_warning"]:
                alerts.append({
                    "level": "WARNING",
                    "type": "DISK",
                    "message": f"磁盘空间较低 {mountpoint}: {usage['percent']:.1f}%", 
                    "value": usage["percent"],
                    "threshold": thresholds["disk_warning"]
                })
        
        # 系统负载告警
        load_1min = metrics.get("load_average", {}).get("1min", 0)
        if load_1min > thresholds["load_critical"]:
            alerts.append({
                "level": "CRITICAL",
                "type": "LOAD",
                "message": f"系统负载过高: {load_1min:.2f}",
                "value": load_1min,
                "threshold": thresholds["load_critical"]
            })
        elif load_1min > thresholds["load_warning"]:
            alerts.append({
                "level": "WARNING",
                "type": "LOAD",
                "message": f"系统负载较高: {load_1min:.2f}",
                "value": load_1min,
                "threshold": thresholds["load_warning"]
            })
        
        return alerts
    
    def send_alert(self, alerts: List[Dict]):
        """发送告警邮件"""
        if not alerts:
            return
        
        # 检查告警冷却时间
        current_time = datetime.now()
        filtered_alerts = []
        
        for alert in alerts:
            alert_key = f"{alert['type']}_{alert['level']}"
            last_sent = self.alerts_sent.get(alert_key)
            
            if not last_sent or (current_time - last_sent).seconds > self.config["alert_cooldown"]:
                filtered_alerts.append(alert)
                self.alerts_sent[alert_key] = current_time
        
        if not filtered_alerts:
            return
        
        # 构建邮件内容
        subject = f"系统监控告警 - {len(filtered_alerts)}个问题"
        
        body = f"""
系统监控告警报告
生成时间: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
服务器: {os.uname().nodename}

检测到以下问题:

"""
        
        for i, alert in enumerate(filtered_alerts, 1):
            body += f"{i}. [{alert['level']}] {alert['message']}\n"
            body += f"   当前值: {alert['value']}\n"
            body += f"   阈值: {alert['threshold']}\n\n"
        
        body += """
请及时处理相关问题。

系统自动监控
        """
        
        try:
            # 发送邮件
            msg = MIMEMultipart()
            msg['From'] = self.config['smtp']['username']
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            server = smtplib.SMTP(self.config['smtp']['host'], self.config['smtp']['port'])
            server.starttls()
            server.login(self.config['smtp']['username'], self.config['smtp']['password'])
            
            for recipient in self.config['recipients']:
                msg['To'] = recipient
                server.send_message(msg)
                del msg['To']
            
            server.quit()
            self.logger.info(f"告警邮件已发送给 {len(self.config['recipients'])} 位收件人")
            
        except Exception as e:
            self.logger.error(f"告警邮件发送失败: {str(e)}")
    
    def auto_remediation(self, alerts: List[Dict]):
        """自动修复某些问题"""
        for alert in alerts:
            alert_type = alert['type']
            alert_level = alert['level']
            
            # 磁盘空间自动清理
            if alert_type == "DISK" and alert_level == "WARNING":
                self.logger.info("尝试自动清理磁盘空间...")
                try:
                    # 清理临时文件
                    subprocess.run(["find", "/tmp", "-type", "f", "-atime", "+7", "-delete"], 
                                 check=True)
                    
                    # 清理日志文件
                    subprocess.run(["find", "/var/log", "-name", "*.log.gz", "-mtime", "+30", "-delete"],
                                 check=True)
                    
                    # 清理APT缓存
                    subprocess.run(["apt-get", "clean"], check=True)
                    
                    self.logger.info("磁盘空间自动清理完成")
                    
                except Exception as e:
                    self.logger.error(f"磁盘自动清理失败: {str(e)}")
            
            # 内存压力缓解
            elif alert_type == "MEMORY" and alert_level == "WARNING":
                self.logger.info("尝试释放内存缓存...")
                try:
                    # 清理页面缓存
                    with open('/proc/sys/vm/drop_caches', 'w') as f:
                        f.write('1')
                    
                    self.logger.info("内存缓存清理完成")
                    
                except Exception as e:
                    self.logger.error(f"内存缓存清理失败: {str(e)}")
    
    def generate_daily_report(self) -> Dict:
        """生成日常监控报告"""
        metrics = self.check_system_resources()
        services = self.check_services()
        disk_check = self.check_disk_space()
        
        report = {
            "date": datetime.now().strftime('%Y-%m-%d'),
            "system_metrics": metrics,
            "service_status": services,
            "disk_analysis": disk_check,
            "summary": {
                "cpu_avg": metrics.get("cpu_percent", 0),
                "memory_usage": metrics.get("memory_percent", 0),
                "services_running": sum(1 for s in services.values() if s.get("active", False)),
                "services_total": len(services),
                "disk_issues": len(disk_check.get("cleanup_actions", []))
            }
        }
        
        # 保存报告
        report_file = f"/var/log/monitoring/daily_report_{datetime.now().strftime('%Y%m%d')}.json"
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    def run_monitoring_cycle(self):
        """运行一次完整的监控周期"""
        self.logger.info("开始监控检查周期")
        
        try:
            # 检查系统指标
            metrics = self.check_system_resources()
            
            # 检查服务状态
            services = self.check_services()
            
            # 分析性能指标
            alerts = self.analyze_performance(metrics)
            
            # 检查服务异常
            for service, status in services.items():
                if not status.get("active", False):
                    alerts.append({
                        "level": "CRITICAL",
                        "type": "SERVICE",
                        "message": f"服务异常: {service} - {status.get('status', 'Unknown')}",
                        "value": service,
                        "threshold": "active"
                    })
            
            # 发送告警
            if alerts:
                self.send_alert(alerts)
                self.auto_remediation(alerts)
            
            # 记录检查结果
            self.logger.info(f"监控周期完成，发现 {len(alerts)} 个问题")
            
            return {
                "timestamp": datetime.now().isoformat(),
                "metrics": metrics,
                "services": services,
                "alerts": alerts
            }
            
        except Exception as e:
            self.logger.error(f"监控周期执行失败: {str(e)}")
            return {"error": str(e)}

# 主程序执行
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        # 守护进程模式
        import time
        
        monitor = AutomatedMonitoring()
        
        while True:
            try:
                monitor.run_monitoring_cycle()
                time.sleep(monitor.config["check_interval"])
            except KeyboardInterrupt:
                print("\n监控程序已停止")
                break
            except Exception as e:
                print(f"监控程序异常: {e}")
                time.sleep(60)  # 异常后等待1分钟再重试
    else:
        # 单次执行模式
        monitor = AutomatedMonitoring()
        result = monitor.run_monitoring_cycle()
        
        if result.get("error"):
            sys.exit(1)
        else:
            print("监控检查完成")
```

#### 批量部署和配置管理
```bash
#!/bin/bash
# 批量部署和配置管理脚本

# Ansible配置管理
setup_ansible_management() {
    echo "=== 配置Ansible自动化管理 ==="
    
    # 安装Ansible
    apt update
    apt install -y ansible sshpass
    
    # 创建Ansible目录结构
    mkdir -p /etc/ansible/{playbooks,roles,inventory,group_vars,host_vars}
    
    # 配置主机清单
    cat > /etc/ansible/inventory/hosts << 'EOF'
[webservers]
web1 ansible_host=192.168.1.100 ansible_user=admin
web2 ansible_host=192.168.1.101 ansible_user=admin

[dbservers]
db1 ansible_host=192.168.1.110 ansible_user=admin

[fileservers]
file1 ansible_host=192.168.1.120 ansible_user=admin

[workstations]
ws[01:50] ansible_host=192.168.1.[51:100] ansible_user=localadmin

[all:vars]
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF
    
    # 创建组变量
    cat > /etc/ansible/group_vars/all.yml << 'EOF'
# 全局变量配置
ntp_servers:
  - ntp1.aliyun.com
  - ntp2.aliyun.com

dns_servers:
  - 8.8.8.8
  - 114.114.114.114

company_domain: company.local
admin_email: admin@company.com

# 安全配置
disable_root_login: true
ssh_port: 22
firewall_enabled: true

# 监控配置
zabbix_server: 192.168.1.200
monitoring_enabled: true
EOF
    
    # 创建基础系统配置playbook
    cat > /etc/ansible/playbooks/basic_setup.yml << 'EOF'
---
- name: 基础系统配置
  hosts: all
  become: yes
  
  tasks:
    - name: 更新软件包
      apt:
        update_cache: yes
        upgrade: dist
      when: ansible_os_family == "Debian"
    
    - name: 安装基础软件包
      apt:
        name:
          - curl
          - wget
          - vim
          - htop
          - net-tools
          - rsync
          - unzip
          - git
        state: present
      when: ansible_os_family == "Debian"
    
    - name: 配置NTP服务
      template:
        src: ntp.conf.j2
        dest: /etc/ntp.conf
        backup: yes
      notify: restart ntp
    
    - name: 配置DNS
      template:
        src: resolv.conf.j2
        dest: /etc/resolv.conf
        backup: yes
    
    - name: 创建管理员用户
      user:
        name: sysadmin
        groups: sudo
        shell: /bin/bash
        create_home: yes
    
    - name: 配置SSH安全
      lineinfile:
        dest: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        backup: yes
      with_items:
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^Port', line: 'Port 22' }
      notify: restart ssh
    
    - name: 启用UFW防火墙
      ufw:
        state: enabled
        policy: deny
        direction: incoming
    
    - name: 开放SSH端口
      ufw:
        rule: allow
        port: '22'
        proto: tcp
  
  handlers:
    - name: restart ntp
      service:
        name: ntp
        state: restarted
    
    - name: restart ssh
      service:
        name: ssh
        state: restarted
EOF
    
    # 创建Web服务器配置playbook
    cat > /etc/ansible/playbooks/webserver_setup.yml << 'EOF'
---
- name: Web服务器配置
  hosts: webservers
  become: yes
  
  vars:
    apache_packages:
      - apache2
      - libapache2-mod-php
      - php
      - php-mysql
      - php-gd
      - php-xml
    
  tasks:
    - name: 安装Apache和PHP
      apt:
        name: "{{ apache_packages }}"
        state: present
        update_cache: yes
    
    - name: 启用Apache模块
      apache2_module:
        name: "{{ item }}"
        state: present
      with_items:
        - rewrite
        - ssl
        - headers
      notify: restart apache
    
    - name: 配置Apache虚拟主机
      template:
        src: vhost.conf.j2
        dest: /etc/apache2/sites-available/company.conf
        backup: yes
      notify: restart apache
    
    - name: 启用虚拟主机
      command: a2ensite company.conf
      notify: restart apache
    
    - name: 禁用默认站点
      command: a2dissite 000-default.conf
      notify: restart apache
    
    - name: 设置文档根目录权限
      file:
        path: /var/www/html
        owner: www-data
        group: www-data
        mode: '0755'
        recurse: yes
    
    - name: 配置PHP
      lineinfile:
        dest: /etc/php/8.1/apache2/php.ini
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        backup: yes
      with_items:
        - { regexp: '^upload_max_filesize', line: 'upload_max_filesize = 64M' }
        - { regexp: '^post_max_size', line: 'post_max_size = 64M' }
        - { regexp: '^memory_limit', line: 'memory_limit = 256M' }
        - { regexp: '^max_execution_time', line: 'max_execution_time = 300' }
      notify: restart apache
    
    - name: 启动并启用Apache服务
      service:
        name: apache2
        state: started
        enabled: yes
  
  handlers:
    - name: restart apache
      service:
        name: apache2
        state: restarted
EOF
    
    # 创建工作站配置playbook
    cat > /etc/ansible/playbooks/workstation_setup.yml << 'EOF'
---
- name: 工作站标准化配置
  hosts: workstations
  become: yes
  
  tasks:
    - name: 安装办公软件
      apt:
        name:
          - libreoffice
          - firefox
          - thunderbird
          - gimp
          - vlc
          - filezilla
        state: present
        update_cache: yes
      when: ansible_os_family == "Debian"
    
    - name: 配置自动更新
      apt:
        name: unattended-upgrades
        state: present
    
    - name: 配置自动更新策略
      template:
        src: 50unattended-upgrades.j2
        dest: /etc/apt/apt.conf.d/50unattended-upgrades
        backup: yes
    
    - name: 安装中文语言包
      apt:
        name:
          - language-pack-zh-hans
          - fonts-wqy-microhei
          - fonts-wqy-zenhei
        state: present
    
    - name: 配置时区
      timezone:
        name: Asia/Shanghai
    
    - name: 安装Zabbix Agent
      apt:
        deb: https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu22.04_all.deb
      
    - name: 更新软件包列表
      apt:
        update_cache: yes
    
    - name: 安装Zabbix Agent
      apt:
        name: zabbix-agent
        state: present
    
    - name: 配置Zabbix Agent
      template:
        src: zabbix_agentd.conf.j2
        dest: /etc/zabbix/zabbix_agentd.conf
        backup: yes
      notify: restart zabbix-agent
    
    - name: 启动Zabbix Agent
      service:
        name: zabbix-agent
        state: started
        enabled: yes
  
  handlers:
    - name: restart zabbix-agent
      service:
        name: zabbix-agent
        state: restarted
EOF
    
    # 创建模板文件目录
    mkdir -p /etc/ansible/templates
    
    # NTP配置模板
    cat > /etc/ansible/templates/ntp.conf.j2 << 'EOF'
# NTP服务器配置
{% for server in ntp_servers %}
server {{ server }} iburst
{% endfor %}

# 本地时钟作为备用
server 127.127.1.0
fudge 127.127.1.0 stratum 10

# 限制访问
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited
restrict 127.0.0.1
restrict ::1
EOF
    
    # DNS配置模板
    cat > /etc/ansible/templates/resolv.conf.j2 << 'EOF'
# DNS配置 - 由Ansible管理
domain {{ company_domain }}
search {{ company_domain }}

{% for server in dns_servers %}
nameserver {{ server }}
{% endfor %}
EOF
    
    # 执行基础配置
    echo "执行基础系统配置..."
    ansible-playbook -i /etc/ansible/inventory/hosts /etc/ansible/playbooks/basic_setup.yml
    
    echo "Ansible自动化管理配置完成"
}

# 批量软件部署
batch_software_deployment() {
    echo "=== 批量软件部署 ==="
    
    # 创建软件部署脚本
    cat > /usr/local/bin/deploy_software.py << 'EOF'
#!/usr/bin/env python3
# 批量软件部署脚本

import os
import sys
import json
import subprocess
from typing import Dict, List

class SoftwareDeployer:
    def __init__(self, config_file: str):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
    
    def deploy_to_servers(self, software_list: List[str], server_group: str):
        """部署软件到服务器组"""
        playbook_content = f"""
---
- name: 批量软件部署
  hosts: {server_group}
  become: yes
  
  tasks:
"""
        
        for software in software_list:
            playbook_content += f"""
    - name: 安装 {software}
      apt:
        name: {software}
        state: present
        update_cache: yes
      when: ansible_os_family == "Debian"
"""
        
        # 写入临时playbook
        with open('/tmp/deploy_software.yml', 'w') as f:
            f.write(playbook_content)
        
        # 执行部署
        result = subprocess.run([
            'ansible-playbook', 
            '-i', '/etc/ansible/inventory/hosts',
            '/tmp/deploy_software.yml'
        ], capture_output=True, text=True)
        
        return result.returncode == 0, result.stdout, result.stderr
    
    def deploy_custom_package(self, package_path: str, server_group: str):
        """部署自定义软件包"""
        playbook_content = f"""
---
- name: 部署自定义软件包
  hosts: {server_group}
  become: yes
  
  tasks:
    - name: 复制软件包
      copy:
        src: {package_path}
        dest: /tmp/custom_package.deb
    
    - name: 安装自定义软件包
      apt:
        deb: /tmp/custom_package.deb
        state: present
    
    - name: 清理临时文件
      file:
        path: /tmp/custom_package.deb
        state: absent
"""
        
        with open('/tmp/deploy_custom.yml', 'w') as f:
            f.write(playbook_content)
        
        result = subprocess.run([
            'ansible-playbook',
            '-i', '/etc/ansible/inventory/hosts', 
            '/tmp/deploy_custom.yml'
        ], capture_output=True, text=True)
        
        return result.returncode == 0, result.stdout, result.stderr

# 使用示例
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("使用方法: deploy_software.py <server_group> <software1,software2,...>")
        sys.exit(1)
    
    server_group = sys.argv[1]
    software_list = sys.argv[2].split(',')
    
    deployer = SoftwareDeployer('/etc/ansible/software_config.json')
    success, stdout, stderr = deployer.deploy_to_servers(software_list, server_group)
    
    if success:
        print("软件部署成功")
        print(stdout)
    else:
        print("软件部署失败")
        print(stderr)
        sys.exit(1)
EOF
    
    chmod +x /usr/local/bin/deploy_software.py
    
    echo "批量软件部署工具配置完成"
}

# 配置标准化管理
standardization_management() {
    echo "=== 配置标准化管理 ==="
    
    # 创建配置文件版本控制
    mkdir -p /etc/config_management
    cd /etc/config_management
    git init
    
    # 配置Git用户
    git config user.name "System Administrator"
    git config user.email "admin@company.com"
    
    # 创建配置收集脚本
    cat > collect_configs.sh << 'EOF'
#!/bin/bash
# 配置文件收集脚本

BACKUP_DIR="/etc/config_management/configs"
DATE=$(date +%Y%m%d_%H%M%S)

# 创建备份目录
mkdir -p $BACKUP_DIR

# 收集系统配置文件
echo "收集系统配置文件..."

# 网络配置
cp -r /etc/network/ $BACKUP_DIR/network_$DATE
cp /etc/hosts $BACKUP_DIR/hosts_$DATE
cp /etc/resolv.conf $BACKUP_DIR/resolv.conf_$DATE

# 服务配置
cp -r /etc/apache2/ $BACKUP_DIR/apache2_$DATE 2>/dev/null || true
cp -r /etc/nginx/ $BACKUP_DIR/nginx_$DATE 2>/dev/null || true
cp -r /etc/mysql/ $BACKUP_DIR/mysql_$DATE 2>/dev/null || true

# SSH配置
cp -r /etc/ssh/ $BACKUP_DIR/ssh_$DATE

# 防火墙配置
ufw status verbose > $BACKUP_DIR/ufw_status_$DATE

# Cron任务
crontab -l > $BACKUP_DIR/crontab_$DATE 2>/dev/null || true

# 提交到Git
cd /etc/config_management
git add .
git commit -m "配置备份 - $DATE"

echo "配置收集完成: $BACKUP_DIR"
EOF
    
    chmod +x collect_configs.sh
    
    # 添加到定时任务
    echo "0 2 * * * /etc/config_management/collect_configs.sh" | crontab -
    
    echo "配置标准化管理设置完成"
}

# 主函数
main() {
    case $1 in
        "ansible")
            setup_ansible_management
            ;;
        "deploy")
            batch_software_deployment
            ;;
        "standard")
            standardization_management
            ;;
        "all")
            setup_ansible_management
            batch_software_deployment
            standardization_management
            ;;
        *)
            echo "使用方法: $0 {ansible|deploy|standard|all}"
            ;;
    esac
}

main "$@"
```

## 2. 性能监控与优化

### 2.1 性能监控体系

#### 全面性能监控配置
```yaml
性能监控架构:
  数据收集层:
    系统指标:
      - CPU使用率和负载
      - 内存使用情况
      - 磁盘I/O性能
      - 网络吞吐量
      - 进程资源使用
    
    应用指标:
      - Web服务器响应时间
      - 数据库查询性能
      - 应用错误率
      - 用户会话数
      - 业务交易量
    
    业务指标:
      - 用户活跃度
      - 功能使用频率
      - 业务流程耗时
      - 数据处理量
      - 系统可用性

  数据处理层:
    实时处理:
      - 流式数据处理
      - 实时告警触发
      - 异常检测
      - 趋势分析
    
    批量处理:
      - 历史数据分析
      - 容量规划
      - 性能基线建立
      - 报表生成

  展示应用层:
    监控仪表板:
      - 实时监控大屏
      - 管理层报表
      - 技术指标视图
      - 业务指标视图
    
    告警通知:
      - 多级告警机制
      - 多渠道通知
      - 告警抑制和聚合
      - 自动处理流程
```

#### Grafana监控仪表板
```python
#!/usr/bin/env python3
# Grafana仪表板自动化配置

import json
import requests
from typing import Dict, List

class GrafanaDashboardManager:
    def __init__(self, grafana_url: str, api_token: str):
        self.grafana_url = grafana_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
    
    def create_datasource(self, name: str, ds_type: str, url: str, database: str = None) -> Dict:
        """创建数据源"""
        datasource_config = {
            "name": name,
            "type": ds_type,
            "url": url,
            "access": "proxy",
            "isDefault": False
        }
        
        if database:
            datasource_config["database"] = database
        
        response = requests.post(
            f"{self.grafana_url}/api/datasources",
            headers=self.headers,
            json=datasource_config
        )
        
        return response.json()
    
    def create_sme_overview_dashboard(self) -> Dict:
        """创建中小企业概览仪表板"""
        dashboard = {
            "dashboard": {
                "id": None,
                "title": "中小企业IT基础设施概览",
                "tags": ["sme", "overview"],
                "timezone": "Asia/Shanghai",
                "panels": [
                    {
                        "id": 1,
                        "title": "系统概览",
                        "type": "stat",
                        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                        "targets": [
                            {
                                "expr": "up",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "displayName": "在线服务器",
                                "unit": "short"
                            }
                        }
                    },
                    {
                        "id": 2,
                        "title": "CPU使用率",
                        "type": "gauge",
                        "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                        "targets": [
                            {
                                "expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "min": 0,
                                "max": 100,
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 70},
                                        {"color": "red", "value": 90}
                                    ]
                                }
                            }
                        }
                    },
                    {
                        "id": 3,
                        "title": "内存使用率",
                        "type": "gauge", 
                        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                        "targets": [
                            {
                                "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "min": 0,
                                "max": 100,
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 75},
                                        {"color": "red", "value": 90}
                                    ]
                                }
                            }
                        }
                    },
                    {
                        "id": 4,
                        "title": "磁盘使用率",
                        "type": "gauge",
                        "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                        "targets": [
                            {
                                "expr": "100 - ((node_filesystem_avail_bytes{mountpoint=\"/\"} * 100) / node_filesystem_size_bytes{mountpoint=\"/\"})",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "min": 0,
                                "max": 100,
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 75},
                                        {"color": "red", "value": 85}
                                    ]
                                }
                            }
                        }
                    },
                    {
                        "id": 5,
                        "title": "网络流量",
                        "type": "timeseries",
                        "gridPos": {"h": 6, "w": 12, "x": 0, "y": 4},
                        "targets": [
                            {
                                "expr": "rate(node_network_receive_bytes_total{device!=\"lo\"}[5m])",
                                "legendFormat": "入站 - {{device}}",
                                "refId": "A"
                            },
                            {
                                "expr": "rate(node_network_transmit_bytes_total{device!=\"lo\"}[5m])",
                                "legendFormat": "出站 - {{device}}", 
                                "refId": "B"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "binBps"
                            }
                        }
                    },
                    {
                        "id": 6,
                        "title": "系统负载",
                        "type": "timeseries",
                        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 4},
                        "targets": [
                            {
                                "expr": "node_load1",
                                "legendFormat": "1分钟负载",
                                "refId": "A"
                            },
                            {
                                "expr": "node_load5",
                                "legendFormat": "5分钟负载",
                                "refId": "B"
                            },
                            {
                                "expr": "node_load15",
                                "legendFormat": "15分钟负载",
                                "refId": "C"
                            }
                        ]
                    },
                    {
                        "id": 7,
                        "title": "TOP进程(按CPU)",
                        "type": "table",
                        "gridPos": {"h": 6, "w": 12, "x": 0, "y": 10},
                        "targets": [
                            {
                                "expr": "topk(10, 100 - (avg by (instance, job, mode) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100))",
                                "format": "table",
                                "refId": "A"
                            }
                        ]
                    },
                    {
                        "id": 8,
                        "title": "服务状态",
                        "type": "table",
                        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 10},
                        "targets": [
                            {
                                "expr": "up{job=~\".*\"}",
                                "format": "table",
                                "refId": "A"
                            }
                        ]
                    }
                ],
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "refresh": "30s"
            },
            "overwrite": True
        }
        
        response = requests.post(
            f"{self.grafana_url}/api/dashboards/db",
            headers=self.headers,
            json=dashboard
        )
        
        return response.json()
    
    def create_business_dashboard(self) -> Dict:
        """创建业务监控仪表板"""
        dashboard = {
            "dashboard": {
                "id": None,
                "title": "业务系统监控",
                "tags": ["business", "application"],
                "timezone": "Asia/Shanghai",
                "panels": [
                    {
                        "id": 1,
                        "title": "Web应用响应时间",
                        "type": "timeseries",
                        "gridPos": {"h": 6, "w": 12, "x": 0, "y": 0},
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                                "legendFormat": "95th percentile",
                                "refId": "A"
                            },
                            {
                                "expr": "histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
                                "legendFormat": "50th percentile",
                                "refId": "B"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "s"
                            }
                        }
                    },
                    {
                        "id": 2,
                        "title": "HTTP请求速率",
                        "type": "timeseries",
                        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 0},
                        "targets": [
                            {
                                "expr": "sum(rate(http_requests_total[5m])) by (method, status)",
                                "legendFormat": "{{method}} - {{status}}",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "reqps"
                            }
                        }
                    },
                    {
                        "id": 3,
                        "title": "数据库查询性能",
                        "type": "timeseries",
                        "gridPos": {"h": 6, "w": 12, "x": 0, "y": 6},
                        "targets": [
                            {
                                "expr": "mysql_global_status_queries",
                                "legendFormat": "查询总数",
                                "refId": "A"
                            },
                            {
                                "expr": "mysql_global_status_slow_queries",
                                "legendFormat": "慢查询",
                                "refId": "B"
                            }
                        ]
                    },
                    {
                        "id": 4,
                        "title": "用户会话数",
                        "type": "stat",
                        "gridPos": {"h": 6, "w": 12, "x": 12, "y": 6},
                        "targets": [
                            {
                                "expr": "sum(active_sessions)",
                                "refId": "A"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "displayName": "活跃会话",
                                "unit": "short"
                            }
                        }
                    }
                ],
                "time": {
                    "from": "now-3h",
                    "to": "now"
                },
                "refresh": "1m"
            },
            "overwrite": True
        }
        
        response = requests.post(
            f"{self.grafana_url}/api/dashboards/db",
            headers=self.headers,
            json=dashboard
        )
        
        return response.json()
    
    def setup_alerting(self):
        """配置告警规则"""
        alert_rules = [
            {
                "alert": "HighCPUUsage",
                "expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100) > 90",
                "for": "5m",
                "labels": {
                    "severity": "critical",
                    "team": "infrastructure"
                },
                "annotations": {
                    "summary": "服务器CPU使用率过高",
                    "description": "服务器 {{ $labels.instance }} CPU使用率超过90%，当前值：{{ $value }}%"
                }
            },
            {
                "alert": "HighMemoryUsage", 
                "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 95",
                "for": "5m",
                "labels": {
                    "severity": "critical",
                    "team": "infrastructure"
                },
                "annotations": {
                    "summary": "服务器内存使用率过高",
                    "description": "服务器 {{ $labels.instance }} 内存使用率超过95%，当前值：{{ $value }}%"
                }
            },
            {
                "alert": "DiskSpaceLow",
                "expr": "100 - ((node_filesystem_avail_bytes{mountpoint=\"/\"} * 100) / node_filesystem_size_bytes{mountpoint=\"/\"}) > 85",
                "for": "10m",
                "labels": {
                    "severity": "warning",
                    "team": "infrastructure"
                },
                "annotations": {
                    "summary": "磁盘空间不足",
                    "description": "服务器 {{ $labels.instance }} 根分区使用率超过85%，当前值：{{ $value }}%"
                }
            },
            {
                "alert": "ServiceDown",
                "expr": "up == 0",
                "for": "1m",
                "labels": {
                    "severity": "critical",
                    "team": "infrastructure"
                },
                "annotations": {
                    "summary": "服务不可用",
                    "description": "服务 {{ $labels.job }} 在 {{ $labels.instance }} 上不可用"
                }
            }
        ]
        
        # 这里应该配置到Prometheus的告警规则文件中
        # 实际部署时需要将规则写入到Prometheus配置
        
        return alert_rules

# 使用示例
if __name__ == "__main__":
    # 配置Grafana连接
    grafana_manager = GrafanaDashboardManager(
        grafana_url="http://localhost:3000",
        api_token="your_grafana_api_token"
    )
    
    # 创建数据源
    grafana_manager.create_datasource(
        name="Prometheus",
        ds_type="prometheus", 
        url="http://localhost:9090"
    )
    
    # 创建仪表板
    grafana_manager.create_sme_overview_dashboard()
    grafana_manager.create_business_dashboard()
    
    # 配置告警
    alert_rules = grafana_manager.setup_alerting()
    
    print("Grafana仪表板配置完成")
```

### 2.2 性能优化策略

#### 系统性能调优
```bash
#!/bin/bash
# 系统性能优化脚本

# 系统内核参数优化
optimize_kernel_parameters() {
    echo "=== 优化系统内核参数 ==="
    
    # 备份原配置
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d)
    
    # 创建性能优化配置
    cat >> /etc/sysctl.conf << 'EOF'

# 性能优化配置 - 中小企业
# 网络性能优化
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_congestion_control = bbr

# 内存管理优化
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 65536

# 文件系统优化
fs.file-max = 655360
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 256

# 进程管理优化
kernel.pid_max = 4194304
kernel.threads-max = 4194304

# 安全相关优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15
EOF
    
    # 应用配置
    sysctl -p
    
    echo "内核参数优化完成"
}

# 磁盘I/O优化
optimize_disk_io() {
    echo "=== 优化磁盘I/O性能 ==="
    
    # 检测磁盘类型
    for disk in $(lsblk -d -o NAME | grep -v NAME); do
        if [ -f "/sys/block/$disk/queue/rotational" ]; then
            rotational=$(cat /sys/block/$disk/queue/rotational)
            
            if [ "$rotational" -eq 0 ]; then
                # SSD优化
                echo "优化SSD: $disk"
                echo noop > /sys/block/$disk/queue/scheduler
                echo 1 > /sys/block/$disk/queue/iosched/fifo_batch
            else
                # HDD优化
                echo "优化HDD: $disk"
                echo deadline > /sys/block/$disk/queue/scheduler
                echo 64 > /sys/block/$disk/queue/nr_requests
            fi
        fi
    done
    
    # 优化文件系统挂载选项
    sed -i 's/defaults/defaults,noatime,nodiratime/' /etc/fstab
    
    # 启用文件系统缓存
    echo 'vm.dirty_writeback_centisecs = 1500' >> /etc/sysctl.conf
    echo 'vm.dirty_expire_centisecs = 3000' >> /etc/sysctl.conf
    
    echo "磁盘I/O优化完成"
}

# 数据库性能优化
optimize_database() {
    echo "=== 优化数据库性能 ==="
    
    # MySQL优化配置
    if systemctl is-active mysql >/dev/null 2>&1; then
        cat > /etc/mysql/conf.d/performance.cnf << 'EOF'
[mysqld]
# 基础配置
max_connections = 200
max_connect_errors = 100000
max_allowed_packet = 64M
table_open_cache = 4000
table_definition_cache = 2000

# InnoDB优化
innodb_buffer_pool_size = 2G
innodb_buffer_pool_instances = 2
innodb_log_file_size = 256M
innodb_log_buffer_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_thread_concurrency = 8
innodb_read_io_threads = 4
innodb_write_io_threads = 4

# 查询缓存
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 4M

# 临时表配置
tmp_table_size = 256M
max_heap_table_size = 256M
join_buffer_size = 2M
sort_buffer_size = 2M

# 慢查询日志
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 1

# 二进制日志
binlog_cache_size = 1M
max_binlog_cache_size = 2G
max_binlog_size = 1G
expire_logs_days = 7
EOF
        
        systemctl restart mysql
        echo "MySQL优化完成"
    fi
    
    # PostgreSQL优化配置
    if systemctl is-active postgresql >/dev/null 2>&1; then
        PG_VERSION=$(sudo -u postgres psql -c "SELECT version();" | grep PostgreSQL | sed 's/.*PostgreSQL \([0-9]\+\).*/\1/')
        PG_CONF="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
        
        if [ -f "$PG_CONF" ]; then
            cp "$PG_CONF" "$PG_CONF.backup.$(date +%Y%m%d)"
            
            # PostgreSQL性能优化
            cat >> "$PG_CONF" << 'EOF'

# 性能优化配置
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 16MB
maintenance_work_mem = 256MB
checkpoint_completion_target = 0.7
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
seq_page_cost = 1
max_connections = 200
EOF
            
            systemctl restart postgresql
            echo "PostgreSQL优化完成"
        fi
    fi
}

# Web服务器优化
optimize_web_server() {
    echo "=== 优化Web服务器性能 ==="
    
    # Apache优化
    if systemctl is-active apache2 >/dev/null 2>&1; then
        # 启用性能模块
        a2enmod deflate expires headers rewrite ssl
        
        cat > /etc/apache2/conf-available/performance.conf << 'EOF'
# Apache性能优化配置

# 工作模式配置
<IfModule mpm_prefork_module>
    StartServers 8
    MinSpareServers 5
    MaxSpareServers 20
    ServerLimit 256
    MaxRequestWorkers 256
    MaxConnectionsPerChild 10000
</IfModule>

<IfModule mpm_worker_module>
    StartServers 3
    MinSpareThreads 75
    MaxSpareThreads 250
    ThreadsPerChild 25
    MaxRequestWorkers 400
    MaxConnectionsPerChild 10000
</IfModule>

# 压缩配置
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript application/json application/xml
    DeflateCompressionLevel 6
    SetOutputFilter DEFLATE
    SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-gzip dont-vary
    SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary
</IfModule>

# 缓存配置
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType application/pdf "access plus 1 month"
    ExpiresByType text/javascript "access plus 1 month"
</IfModule>

# 头部优化
<IfModule mod_headers.c>
    Header unset ETag
    FileETag None
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>

# 连接保持
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15

# 服务器标识
ServerTokens Prod
ServerSignature Off
EOF
        
        a2enconf performance
        systemctl reload apache2
        echo "Apache优化完成"
    fi
    
    # Nginx优化
    if systemctl is-active nginx >/dev/null 2>&1; then
        cat > /etc/nginx/conf.d/performance.conf << 'EOF'
# Nginx性能优化配置

# 工作进程配置
worker_processes auto;
worker_connections 1024;
worker_rlimit_nofile 65535;

# 事件模型
events {
    use epoll;
    multi_accept on;
}

# HTTP配置优化
http {
    # 基础配置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;
    
    # 缓冲区优化
    client_body_buffer_size 128k;
    client_max_body_size 64m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    
    # 超时配置
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;
    
    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/json
        application/xml+rss
        application/atom+xml
        image/svg+xml;
    
    # 文件缓存
    location ~* \.(jpg|jpeg|gif|png|css|js|ico|xml)$ {
        access_log off;
        log_not_found off;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # 隐藏版本信息
    server_tokens off;
}
EOF
        
        nginx -t && systemctl reload nginx
        echo "Nginx优化完成"
    fi
}

# PHP性能优化
optimize_php() {
    echo "=== 优化PHP性能 ==="
    
    # 查找PHP配置文件
    PHP_INI=$(php --ini | grep "Loaded Configuration File" | cut -d: -f2 | xargs)
    
    if [ -f "$PHP_INI" ]; then
        cp "$PHP_INI" "$PHP_INI.backup.$(date +%Y%m%d)"
        
        # 优化PHP配置
        sed -i 's/memory_limit = .*/memory_limit = 256M/' "$PHP_INI"
        sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
        sed -i 's/max_input_time = .*/max_input_time = 300/' "$PHP_INI"
        sed -i 's/upload_max_filesize = .*/upload_max_filesize = 64M/' "$PHP_INI"
        sed -i 's/post_max_size = .*/post_max_size = 64M/' "$PHP_INI"
        sed -i 's/max_file_uploads = .*/max_file_uploads = 20/' "$PHP_INI"
        
        # 启用OPcache
        cat >> "$PHP_INI" << 'EOF'

; OPcache优化配置
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.max_wasted_percentage=5
opcache.use_cwd=1
opcache.validate_timestamps=1
opcache.revalidate_freq=2
opcache.fast_shutdown=1
opcache.save_comments=1
opcache.load_comments=1
EOF
        
        systemctl reload apache2 2>/dev/null || systemctl reload nginx 2>/dev/null || systemctl reload php7.4-fpm 2>/dev/null
        echo "PHP优化完成"
    fi
}

# Redis缓存优化
optimize_redis_cache() {
    echo "=== 配置Redis缓存 ==="
    
    # 安装Redis
    apt update
    apt install -y redis-server
    
    # Redis配置优化
    cat > /etc/redis/redis.conf.d/performance.conf << 'EOF'
# Redis性能优化配置
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# 网络优化
tcp-keepalive 300
timeout 300

# 内存优化
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64

# 持久化优化
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes

# 日志配置
loglevel notice
logfile /var/log/redis/redis-server.log
EOF
    
    systemctl restart redis-server
    systemctl enable redis-server
    
    echo "Redis缓存配置完成"
}

# 性能监控设置
setup_performance_monitoring() {
    echo "=== 设置性能监控 ==="
    
    # 安装性能监控工具
    apt install -y iotop htop iftop nethogs sysstat
    
    # 启用系统统计收集
    systemctl enable sysstat
    systemctl start sysstat
    
    # 创建性能监控脚本
    cat > /usr/local/bin/performance_check.sh << 'EOF'
#!/bin/bash
# 性能检查脚本

LOG_FILE="/var/log/performance_check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] 性能检查开始" >> $LOG_FILE

# CPU使用率
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
echo "[$DATE] CPU使用率: ${CPU_USAGE}%" >> $LOG_FILE

# 内存使用率
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.2f"), $3/$2 * 100.0}')
echo "[$DATE] 内存使用率: ${MEMORY_USAGE}%" >> $LOG_FILE

# 磁盘使用率
DISK_USAGE=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
echo "[$DATE] 磁盘使用率: ${DISK_USAGE}%" >> $LOG_FILE

# 系统负载
LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}')
echo "[$DATE] 系统负载: ${LOAD_AVG}" >> $LOG_FILE

# 网络连接数
CONNECTIONS=$(netstat -an | wc -l)
echo "[$DATE] 网络连接数: ${CONNECTIONS}" >> $LOG_FILE

echo "[$DATE] 性能检查完成" >> $LOG_FILE
echo "" >> $LOG_FILE
EOF
    
    chmod +x /usr/local/bin/performance_check.sh
    
    # 添加到定时任务
    echo "*/5 * * * * /usr/local/bin/performance_check.sh" | crontab -
    
    echo "性能监控设置完成"
}

# 主函数
main() {
    case $1 in
        "kernel")
            optimize_kernel_parameters
            ;;
        "disk")
            optimize_disk_io
            ;;
        "database")
            optimize_database
            ;;
        "web")
            optimize_web_server
            ;;
        "php")
            optimize_php
            ;;
        "redis")
            optimize_redis_cache
            ;;
        "monitor")
            setup_performance_monitoring
            ;;
        "all")
            optimize_kernel_parameters
            optimize_disk_io
            optimize_database
            optimize_web_server
            optimize_php
            optimize_redis_cache
            setup_performance_monitoring
            ;;
        *)
            echo "使用方法: $0 {kernel|disk|database|web|php|redis|monitor|all}"
            echo ""
            echo "可用选项:"
            echo "  kernel   - 优化系统内核参数"
            echo "  disk     - 优化磁盘I/O性能"
            echo "  database - 优化数据库性能"
            echo "  web      - 优化Web服务器"
            echo "  php      - 优化PHP配置"
            echo "  redis    - 配置Redis缓存"
            echo "  monitor  - 设置性能监控"
            echo "  all      - 执行所有优化"
            ;;
    esac
}

main "$@"
```

由于token限制，我将在新文档中继续创建管理阶段的其余内容。

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"content": "\u521b\u5efa50-100\u4eba\u4f01\u4e1aIT\u57fa\u7840\u8bbe\u65bd\u7ba1\u7406\u603b\u89c8\u6587\u6863", "status": "completed", "priority": "high", "id": "1"}, {"content": "\u521b\u5efa\u89c4\u5212\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba)", "status": "completed", "priority": "high", "id": "2"}, {"content": "\u521b\u5efa\u51c6\u5907\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba)", "status": "completed", "priority": "high", "id": "3"}, {"content": "\u521b\u5efa\u914d\u7f6e\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba)", "status": "completed", "priority": "high", "id": "4"}, {"content": "\u521b\u5efa\u90e8\u7f72\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba)", "status": "completed", "priority": "high", "id": "5"}, {"content": "\u521b\u5efa\u843d\u5730\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba)", "status": "completed", "priority": "high", "id": "6"}, {"content": "\u521b\u5efa\u7ba1\u7406\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba) - \u90e8\u5206\u5b8c\u6210", "status": "in_progress", "priority": "high", "id": "7"}, {"content": "\u521b\u5efa\u7ba1\u7406\u9636\u6bb5\u8be6\u7ec6\u6587\u6863(50-100\u4eba) - \u7ee7\u7eed\u90e8\u5206", "status": "pending", "priority": "high", "id": "9"}, {"content": "\u521b\u5efa\u7ba1\u7406\u5de5\u5177\u63a8\u8350\u6587\u6863(50-100\u4eba)", "status": "pending", "priority": "high", "id": "8"}]