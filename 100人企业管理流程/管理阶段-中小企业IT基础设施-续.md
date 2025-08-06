# 管理阶段 - 中小企业IT基础设施 (50-100人) - 续

## 3. 安全管理

### 3.1 信息安全治理

#### 安全管理体系
```yaml
安全治理架构:
  战略层:
    安全策略:
      - 信息安全方针
      - 安全目标和原则
      - 风险承受能力
      - 合规要求

    安全组织:
      - 安全委员会
      - 安全经理职责
      - 安全团队结构
      - 外部安全服务

  管理层:
    安全流程:
      - 风险评估流程
      - 事件响应流程
      - 变更管理流程
      - 供应商管理流程

    安全标准:
      - 访问控制标准
      - 数据分类标准
      - 系统安全基线
      - 安全培训标准

  操作层:
    安全控制:
      - 技术控制措施
      - 管理控制措施
      - 物理控制措施
      - 人员安全控制

    安全监控:
      - 安全事件监控
      - 漏洞管理
      - 威胁检测
      - 安全审计
```

#### 安全策略实施
```python
#!/usr/bin/env python3
# 企业安全策略管理系统

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class SecurityPolicy:
    id: str
    name: str
    category: str
    description: str
    requirements: List[str]
    implementation_guide: str
    compliance_check: str
    last_review: datetime
    next_review: datetime
    status: str

class SecurityPolicyManager:
    def __init__(self):
        self.policies = {}
        self.setup_logging()
        self.load_default_policies()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/security_policy.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_default_policies(self):
        """加载默认安全策略"""
        default_policies = [
            SecurityPolicy(
                id="PWD-001",
                name="密码安全策略",
                category="访问控制",
                description="规定用户密码的复杂性和管理要求",
                requirements=[
                    "密码长度至少8位",
                    "包含大小写字母、数字和特殊字符",
                    "90天强制更换",
                    "不能重复使用最近5次密码",
                    "账户锁定：5次失败尝试后锁定30分钟"
                ],
                implementation_guide="配置AD密码策略，启用密码历史记录",
                compliance_check="检查域控制器密码策略配置",
                last_review=datetime.now(),
                next_review=datetime.now() + timedelta(days=365),
                status="active"
            ),
            SecurityPolicy(
                id="ACC-001", 
                name="访问控制策略",
                category="访问控制",
                description="规定系统和数据的访问权限管理",
                requirements=[
                    "最小权限原则",
                    "基于角色的访问控制(RBAC)",
                    "定期权限审查(季度)",
                    "用户访问申请和批准流程",
                    "特权账户单独管理"
                ],
                implementation_guide="配置RBAC系统，建立权限管理流程",
                compliance_check="审查用户权限分配记录",
                last_review=datetime.now(),
                next_review=datetime.now() + timedelta(days=365),
                status="active"
            ),
            SecurityPolicy(
                id="DAT-001",
                name="数据分类和保护策略", 
                category="数据保护",
                description="规定数据分类标准和相应保护措施",
                requirements=[
                    "数据分类：公开、内部、机密、绝密",
                    "不同级别数据采用不同加密强度",
                    "机密数据禁止外发",
                    "数据访问记录审计",
                    "数据备份和恢复要求"
                ],
                implementation_guide="建立数据分类标签，配置DLP系统",
                compliance_check="检查数据分类标签和加密状态",
                last_review=datetime.now(),
                next_review=datetime.now() + timedelta(days=365),
                status="active"
            ),
            SecurityPolicy(
                id="NET-001",
                name="网络安全策略",
                category="网络安全", 
                description="规定网络访问和通信安全要求",
                requirements=[
                    "网络分段和隔离",
                    "防火墙规则最小化开放",
                    "VPN强制加密",
                    "WiFi WPA3加密",
                    "网络流量监控"
                ],
                implementation_guide="配置防火墙策略，部署网络监控",
                compliance_check="检查防火墙规则和网络配置",
                last_review=datetime.now(),
                next_review=datetime.now() + timedelta(days=365),
                status="active"
            ),
            SecurityPolicy(
                id="INC-001",
                name="安全事件响应策略",
                category="事件响应",
                description="规定安全事件的检测、响应和处理流程",
                requirements=[
                    "安全事件分类和优先级",
                    "事件响应团队和职责",
                    "事件处理时限要求",
                    "事件记录和报告要求",
                    "事后分析和改进措施"
                ],
                implementation_guide="建立SIEM系统，制定响应流程",
                compliance_check="检查事件响应记录和处理时效",
                last_review=datetime.now(),
                next_review=datetime.now() + timedelta(days=365),
                status="active"
            )
        ]
        
        for policy in default_policies:
            self.policies[policy.id] = policy
    
    def check_policy_compliance(self, policy_id: str) -> Dict:
        """检查策略合规性"""
        policy = self.policies.get(policy_id)
        if not policy:
            return {"error": "策略不存在"}
        
        compliance_results = {
            "policy_id": policy_id,
            "policy_name": policy.name,
            "check_date": datetime.now().isoformat(),
            "compliance_status": "unknown",
            "findings": [],
            "recommendations": []
        }
        
        # 根据策略类型执行不同的合规检查
        if policy.category == "访问控制":
            compliance_results.update(self._check_access_control_compliance(policy))
        elif policy.category == "数据保护":
            compliance_results.update(self._check_data_protection_compliance(policy))
        elif policy.category == "网络安全":
            compliance_results.update(self._check_network_security_compliance(policy))
        elif policy.category == "事件响应":
            compliance_results.update(self._check_incident_response_compliance(policy))
        
        return compliance_results
    
    def _check_access_control_compliance(self, policy: SecurityPolicy) -> Dict:
        """检查访问控制合规性"""
        findings = []
        recommendations = []
        
        try:
            # 检查密码策略
            if policy.id == "PWD-001":
                # 检查系统密码策略配置
                import subprocess
                result = subprocess.run(['net', 'accounts'], capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout
                    if "Minimum password length: 8" not in output:
                        findings.append("密码长度要求未满足")
                        recommendations.append("设置最小密码长度为8位")
                    
                    if "Maximum password age (days): 90" not in output:
                        findings.append("密码有效期配置不当")
                        recommendations.append("设置密码90天过期")
            
            # 检查用户权限
            elif policy.id == "ACC-001":
                # 检查特权用户数量
                admin_users = self._get_admin_users()
                if len(admin_users) > 5:
                    findings.append(f"管理员账户过多: {len(admin_users)}个")
                    recommendations.append("审查并减少不必要的管理员权限")
        
        except Exception as e:
            findings.append(f"合规检查异常: {str(e)}")
        
        compliance_status = "compliant" if not findings else "non-compliant"
        
        return {
            "compliance_status": compliance_status,
            "findings": findings,
            "recommendations": recommendations
        }
    
    def _check_data_protection_compliance(self, policy: SecurityPolicy) -> Dict:
        """检查数据保护合规性"""
        findings = []
        recommendations = []
        
        try:
            # 检查数据加密状态
            encrypted_dirs = ["/var/lib/mysql", "/home", "/opt/sensitive_data"]
            for directory in encrypted_dirs:
                if os.path.exists(directory):
                    # 简化检查：实际应该检查文件系统加密状态
                    if not self._is_directory_encrypted(directory):
                        findings.append(f"目录未加密: {directory}")
                        recommendations.append(f"启用目录加密: {directory}")
            
            # 检查备份策略
            backup_dirs = ["/backup", "/var/backups"]
            backup_found = any(os.path.exists(d) for d in backup_dirs)
            if not backup_found:
                findings.append("未发现数据备份目录")
                recommendations.append("建立数据备份机制")
        
        except Exception as e:
            findings.append(f"数据保护检查异常: {str(e)}")
        
        compliance_status = "compliant" if not findings else "non-compliant"
        
        return {
            "compliance_status": compliance_status,
            "findings": findings,
            "recommendations": recommendations
        }
    
    def _check_network_security_compliance(self, policy: SecurityPolicy) -> Dict:
        """检查网络安全合规性"""
        findings = []
        recommendations = []
        
        try:
            # 检查防火墙状态
            import subprocess
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if result.returncode == 0:
                if "Status: active" not in result.stdout:
                    findings.append("防火墙未启用")
                    recommendations.append("启用UFW防火墙")
            
            # 检查SSH配置
            ssh_config = "/etc/ssh/sshd_config"
            if os.path.exists(ssh_config):
                with open(ssh_config, 'r') as f:
                    config_content = f.read()
                    if "PermitRootLogin no" not in config_content:
                        findings.append("SSH允许root登录")
                        recommendations.append("禁用SSH root登录")
                    
                    if "PasswordAuthentication no" not in config_content:
                        findings.append("SSH允许密码认证")
                        recommendations.append("配置SSH密钥认证")
        
        except Exception as e:
            findings.append(f"网络安全检查异常: {str(e)}")
        
        compliance_status = "compliant" if not findings else "non-compliant"
        
        return {
            "compliance_status": compliance_status,
            "findings": findings,
            "recommendations": recommendations
        }
    
    def _check_incident_response_compliance(self, policy: SecurityPolicy) -> Dict:
        """检查事件响应合规性"""
        findings = []
        recommendations = []
        
        try:
            # 检查日志配置
            log_configs = [
                "/etc/rsyslog.conf",
                "/etc/audit/auditd.conf"
            ]
            
            for config_file in log_configs:
                if not os.path.exists(config_file):
                    findings.append(f"日志配置文件不存在: {config_file}")
                    recommendations.append(f"配置系统日志: {config_file}")
            
            # 检查监控工具
            monitoring_services = ["zabbix-agent", "prometheus-node-exporter"]
            import subprocess
            
            for service in monitoring_services:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    findings.append(f"监控服务未运行: {service}")
                    recommendations.append(f"启动监控服务: {service}")
        
        except Exception as e:
            findings.append(f"事件响应检查异常: {str(e)}")
        
        compliance_status = "compliant" if not findings else "non-compliant"
        
        return {
            "compliance_status": compliance_status,
            "findings": findings,
            "recommendations": recommendations
        }
    
    def _get_admin_users(self) -> List[str]:
        """获取管理员用户列表"""
        try:
            import subprocess
            result = subprocess.run(['getent', 'group', 'sudo'], capture_output=True, text=True)
            if result.returncode == 0:
                group_info = result.stdout.strip()
                if ':' in group_info:
                    users = group_info.split(':')[-1].split(',')
                    return [user.strip() for user in users if user.strip()]
        except Exception:
            pass
        return []
    
    def _is_directory_encrypted(self, directory: str) -> bool:
        """检查目录是否加密（简化实现）"""
        # 实际实现应该检查文件系统类型和加密状态
        # 这里简化为检查是否存在加密标识文件
        return os.path.exists(os.path.join(directory, ".encrypted"))
    
    def generate_compliance_report(self) -> Dict:
        """生成合规性报告"""
        report = {
            "report_date": datetime.now().isoformat(),
            "total_policies": len(self.policies),
            "compliance_summary": {
                "compliant": 0,
                "non_compliant": 0,
                "unknown": 0
            },
            "policy_results": [],
            "overall_score": 0
        }
        
        compliant_count = 0
        
        for policy_id in self.policies:
            compliance_result = self.check_policy_compliance(policy_id)
            report["policy_results"].append(compliance_result)
            
            status = compliance_result.get("compliance_status", "unknown")
            report["compliance_summary"][status] += 1
            
            if status == "compliant":
                compliant_count += 1
        
        # 计算合规得分
        if len(self.policies) > 0:
            report["overall_score"] = round((compliant_count / len(self.policies)) * 100, 2)
        
        # 保存报告
        report_file = f"/var/log/compliance_report_{datetime.now().strftime('%Y%m%d')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

# 使用示例
if __name__ == "__main__":
    manager = SecurityPolicyManager()
    
    # 生成合规性报告
    report = manager.generate_compliance_report()
    
    print("=== 安全合规性报告 ===")
    print(f"总策略数: {report['total_policies']}")
    print(f"合规得分: {report['overall_score']}%")
    print(f"合规策略: {report['compliance_summary']['compliant']}")
    print(f"不合规策略: {report['compliance_summary']['non_compliant']}")
    
    # 显示不合规项目
    for result in report["policy_results"]:
        if result["compliance_status"] == "non-compliant":
            print(f"\n策略: {result['policy_name']}")
            for finding in result["findings"]:
                print(f"  问题: {finding}")
            for recommendation in result["recommendations"]:
                print(f"  建议: {recommendation}")
```

### 3.2 威胁检测与响应

#### 安全监控中心(SOC)
```bash
#!/bin/bash
# 安全监控中心(SOC)部署脚本

# 部署ELK Stack用于日志分析
deploy_elk_stack() {
    echo "=== 部署ELK Stack安全监控 ==="
    
    # 安装Java
    apt update
    apt install -y openjdk-11-jdk
    
    # 添加Elastic仓库
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
    
    apt update
    
    # 安装Elasticsearch
    apt install -y elasticsearch
    
    # 配置Elasticsearch
    cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
cluster.name: security-monitoring
node.name: soc-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF
    
    # 启动Elasticsearch
    systemctl enable elasticsearch
    systemctl start elasticsearch
    
    # 安装Logstash
    apt install -y logstash
    
    # 配置Logstash管道
    cat > /etc/logstash/conf.d/security-logs.conf << 'EOF'
input {
  beats {
    port => 5044
  }
  
  file {
    path => "/var/log/auth.log"
    type => "auth"
    start_position => "beginning"
  }
  
  file {
    path => "/var/log/apache2/access.log"
    type => "web_access"
    start_position => "beginning"
  }
  
  file {
    path => "/var/log/apache2/error.log"
    type => "web_error" 
    start_position => "beginning"
  }
}

filter {
  if [type] == "auth" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}: %{GREEDYDATA:message}" }
    }
    
    if "Failed password" in [message] {
      mutate {
        add_tag => ["failed_login"]
        add_field => { "alert_level" => "medium" }
      }
    }
    
    if "Invalid user" in [message] {
      mutate {
        add_tag => ["invalid_user"]
        add_field => { "alert_level" => "high" }
      }
    }
  }
  
  if [type] == "web_access" {
    grok {
      match => { "message" => "%{COMMONAPACHELOG}" }
    }
    
    if [response] >= 400 {
      mutate {
        add_tag => ["web_error"]
        add_field => { "alert_level" => "medium" }
      }
    }
    
    if [request] =~ /\.(php|asp|jsp)\?.*=.*\.\.|\/\.\.|select.*from|union.*select|script.*alert/ {
      mutate {
        add_tag => ["potential_attack"]
        add_field => { "alert_level" => "high" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
  
  if "failed_login" in [tags] or "potential_attack" in [tags] {
    email {
      to => "security@company.com"
      subject => "安全告警: %{alert_level} - %{tags}"
      body => "检测到安全事件:\n\n时间: %{@timestamp}\n主机: %{host}\n类型: %{tags}\n详情: %{message}"
      from => "soc@company.com"
      smtp_host => "smtp.office365.com"
      smtp_port => 587
      smtp_username => "soc@company.com"
      smtp_password => "your_password"
    }
  }
}
EOF
    
    systemctl enable logstash
    systemctl start logstash
    
    # 安装Kibana
    apt install -y kibana
    
    # 配置Kibana
    cat > /etc/kibana/kibana.yml << 'EOF'
server.port: 5601
server.host: "0.0.0.0"
server.name: "security-kibana"
elasticsearch.hosts: ["http://localhost:9200"]
kibana.index: ".kibana"
EOF
    
    systemctl enable kibana
    systemctl start kibana
    
    echo "ELK Stack部署完成，访问: http://localhost:5601"
}

# 部署Wazuh HIDS
deploy_wazuh_hids() {
    echo "=== 部署Wazuh主机入侵检测系统 ==="
    
    # 安装Wazuh仓库
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    
    apt update
    
    # 安装Wazuh Manager
    apt install -y wazuh-manager
    
    # 配置Wazuh Manager
    cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>security@company.com</email_to>
    <smtp_server>smtp.office365.com</smtp_server>
    <email_from>wazuh@company.com</email_from>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <disabled>no</disabled>
    <frequency>7200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <remove_old_diff>yes</remove_old_diff>

    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
    <directories check_all="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/home</directories>

    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/cis_debian_linux_rcl.txt</system_audit>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>udp</protocol>
  </remote>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>7</email_alert_level>
  </alerts>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>300</timeout>
  </active-response>

</ossec_config>
EOF
    
    # 创建防火墙自动响应脚本
    cat > /var/ossec/active-response/bin/firewall-drop.sh << 'EOF'
#!/bin/bash
# Wazuh自动防火墙阻断脚本

ACTION=$1
USER=$2
IP=$3

if [ "$ACTION" = "add" ]; then
    # 添加阻断规则
    ufw insert 1 deny from $IP
    echo "$(date) - Blocked IP: $IP" >> /var/log/wazuh-firewall.log
elif [ "$ACTION" = "delete" ]; then
    # 删除阻断规则
    ufw delete deny from $IP
    echo "$(date) - Unblocked IP: $IP" >> /var/log/wazuh-firewall.log
fi
EOF
    
    chmod +x /var/ossec/active-response/bin/firewall-drop.sh
    
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    
    echo "Wazuh HIDS部署完成"
}

# 配置安全事件响应自动化
setup_security_automation() {
    echo "=== 配置安全事件响应自动化 ==="
    
    # 创建安全事件处理脚本
    cat > /usr/local/bin/security_incident_handler.py << 'EOF'
#!/usr/bin/env python3
# 安全事件自动响应处理器

import os
import sys
import json
import time
import smtplib
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class SecurityIncidentHandler:
    def __init__(self):
        self.config = self.load_config()
        self.incident_log = "/var/log/security_incidents.log"
    
    def load_config(self):
        return {
            "email": {
                "smtp_server": "smtp.office365.com",
                "smtp_port": 587,
                "username": "security@company.com",
                "password": "your_password",
                "recipients": ["admin@company.com", "it-manager@company.com"]
            },
            "thresholds": {
                "failed_login_threshold": 5,
                "time_window": 300,  # 5分钟
                "auto_block_enabled": True
            }
        }
    
    def handle_failed_login(self, ip_address: str, count: int):
        """处理登录失败事件"""
        incident = {
            "type": "failed_login",
            "ip_address": ip_address,
            "count": count,
            "timestamp": datetime.now().isoformat(),
            "severity": "medium" if count < 10 else "high"
        }
        
        self.log_incident(incident)
        
        if count >= self.config["thresholds"]["failed_login_threshold"]:
            if self.config["thresholds"]["auto_block_enabled"]:
                self.block_ip(ip_address)
                incident["action_taken"] = f"自动阻断IP: {ip_address}"
            
            self.send_alert(incident)
    
    def handle_web_attack(self, ip_address: str, attack_type: str, request_details: str):
        """处理Web攻击事件"""
        incident = {
            "type": "web_attack",
            "ip_address": ip_address,
            "attack_type": attack_type,
            "details": request_details,
            "timestamp": datetime.now().isoformat(),
            "severity": "high"
        }
        
        self.log_incident(incident)
        
        if self.config["thresholds"]["auto_block_enabled"]:
            self.block_ip(ip_address)
            incident["action_taken"] = f"自动阻断IP: {ip_address}"
        
        self.send_alert(incident)
    
    def handle_malware_detection(self, file_path: str, malware_name: str):
        """处理恶意软件检测事件"""
        incident = {
            "type": "malware_detection",
            "file_path": file_path,
            "malware_name": malware_name,
            "timestamp": datetime.now().isoformat(),
            "severity": "critical"
        }
        
        self.log_incident(incident)
        
        # 隔离恶意文件
        quarantine_path = f"/quarantine/{os.path.basename(file_path)}_{int(time.time())}"
        try:
            os.makedirs("/quarantine", exist_ok=True)
            subprocess.run(["mv", file_path, quarantine_path], check=True)
            incident["action_taken"] = f"文件已隔离到: {quarantine_path}"
        except Exception as e:
            incident["action_taken"] = f"文件隔离失败: {str(e)}"
        
        self.send_alert(incident)
    
    def handle_system_intrusion(self, details: str):
        """处理系统入侵事件"""
        incident = {
            "type": "system_intrusion",
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "severity": "critical"
        }
        
        self.log_incident(incident)
        
        # 启动应急响应流程
        self.initiate_emergency_response()
        incident["action_taken"] = "已启动应急响应流程"
        
        self.send_alert(incident)
    
    def block_ip(self, ip_address: str):
        """阻断IP地址"""
        try:
            subprocess.run(["ufw", "insert", "1", "deny", "from", ip_address], check=True)
            self.log_action(f"已阻断IP: {ip_address}")
        except Exception as e:
            self.log_action(f"阻断IP失败 {ip_address}: {str(e)}")
    
    def initiate_emergency_response(self):
        """启动应急响应流程"""
        # 发送紧急通知
        # 在实际环境中，这里可能包括：
        # - 通知安全团队
        # - 启动事件响应计划
        # - 收集证据
        # - 隔离受影响系统
        self.log_action("应急响应流程已启动")
    
    def send_alert(self, incident: dict):
        """发送安全告警"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['username']
            msg['Subject'] = f"安全告警 - {incident['type']} ({incident['severity']})"
            
            body = f"""
安全事件告警

事件类型: {incident['type']}
严重级别: {incident['severity']}
发生时间: {incident['timestamp']}

详细信息:
{json.dumps(incident, indent=2, ensure_ascii=False)}

请立即查看和处理此安全事件。

自动安全监控系统
            """
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], 
                                self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], 
                        self.config['email']['password'])
            
            for recipient in self.config['email']['recipients']:
                msg['To'] = recipient
                server.send_message(msg)
                del msg['To']
            
            server.quit()
            self.log_action(f"告警邮件已发送: {incident['type']}")
            
        except Exception as e:
            self.log_action(f"告警邮件发送失败: {str(e)}")
    
    def log_incident(self, incident: dict):
        """记录安全事件"""
        with open(self.incident_log, 'a') as f:
            f.write(f"{json.dumps(incident)}\n")
    
    def log_action(self, action: str):
        """记录处理动作"""
        timestamp = datetime.now().isoformat()
        with open(self.incident_log, 'a') as f:
            f.write(f"{timestamp} - ACTION: {action}\n")

# 命令行接口
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法: security_incident_handler.py <event_type> [args...]")
        sys.exit(1)
    
    handler = SecurityIncidentHandler()
    event_type = sys.argv[1]
    
    if event_type == "failed_login":
        if len(sys.argv) >= 4:
            ip_address = sys.argv[2]
            count = int(sys.argv[3])
            handler.handle_failed_login(ip_address, count)
    
    elif event_type == "web_attack":
        if len(sys.argv) >= 5:
            ip_address = sys.argv[2]
            attack_type = sys.argv[3]
            request_details = sys.argv[4]
            handler.handle_web_attack(ip_address, attack_type, request_details)
    
    elif event_type == "malware":
        if len(sys.argv) >= 4:
            file_path = sys.argv[2]
            malware_name = sys.argv[3]
            handler.handle_malware_detection(file_path, malware_name)
    
    elif event_type == "intrusion":
        if len(sys.argv) >= 3:
            details = sys.argv[2]
            handler.handle_system_intrusion(details)
    
    else:
        print(f"未知事件类型: {event_type}")
        sys.exit(1)
EOF
    
    chmod +x /usr/local/bin/security_incident_handler.py
    
    echo "安全事件响应自动化配置完成"
}

# 网络流量分析
setup_network_monitoring() {
    echo "=== 配置网络流量监控 ==="
    
    # 安装网络监控工具
    apt install -y ntopng suricata
    
    # 配置ntopng
    cat > /etc/ntopng/ntopng.conf << 'EOF'
-d=/var/lib/ntopng/ntopng.db
-P=/var/lib/ntopng/ntopng.pid
-i=eth0
-P=3000
-u=ntopng
-g=ntopng
--local-networks="192.168.1.0/24"
--interface-name=eth0@Internal
EOF
    
    systemctl enable ntopng
    systemctl start ntopng
    
    # 配置Suricata IDS
    cat > /etc/suricata/suricata.yaml << 'EOF'
# Suricata配置文件
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: /var/log/suricata/

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: no
            http-body: yes
            http-body-printable: yes
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 100kb
            decompress-depth: 100kb
          double-decode-path: no
          double-decode-query: no

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

pcap:
  - interface: eth0

pcap-file:
  checksum-checks: auto

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

threshold-file: /etc/suricata/threshold.config

host-mode: auto
EOF
    
    # 启动Suricata
    systemctl enable suricata
    systemctl start suricata
    
    echo "网络流量监控配置完成"
    echo "ntopng访问地址: http://localhost:3000"
}

# 主函数
main() {
    case $1 in
        "elk")
            deploy_elk_stack
            ;;
        "wazuh")
            deploy_wazuh_hids
            ;;
        "automation")
            setup_security_automation
            ;;
        "network")
            setup_network_monitoring
            ;;
        "all")
            deploy_elk_stack
            deploy_wazuh_hids
            setup_security_automation
            setup_network_monitoring
            ;;
        *)
            echo "使用方法: $0 {elk|wazuh|automation|network|all}"
            echo ""
            echo "可用选项:"
            echo "  elk        - 部署ELK Stack日志分析"
            echo "  wazuh      - 部署Wazuh HIDS"
            echo "  automation - 配置安全事件自动响应"
            echo "  network    - 配置网络流量监控"
            echo "  all        - 部署所有安全监控组件"
            ;;
    esac
}

main "$@"
```

## 4. 成本控制与优化

### 4.1 IT成本管理

#### 成本分析和预算控制
```python
#!/usr/bin/env python3
# IT成本管理和分析系统

import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import matplotlib.pyplot as plt
import seaborn as sns

class ITCostManager:
    def __init__(self):
        self.cost_categories = {
            "hardware": "硬件设备",
            "software": "软件许可",
            "cloud": "云服务",
            "personnel": "人力成本",
            "maintenance": "维护服务",
            "training": "培训费用",
            "utilities": "水电网络",
            "other": "其他费用"
        }
        self.cost_data = []
        self.budget_limits = {}
        
    def add_cost_item(self, category: str, item_name: str, amount: float, 
                     date: str, description: str = "", vendor: str = ""):
        """添加成本项目"""
        cost_item = {
            "id": len(self.cost_data) + 1,
            "category": category,
            "item_name": item_name,
            "amount": amount,
            "date": date,
            "description": description,
            "vendor": vendor,
            "created_at": datetime.now().isoformat()
        }
        self.cost_data.append(cost_item)
        return cost_item["id"]
    
    def set_budget_limit(self, category: str, annual_limit: float):
        """设置预算限制"""
        self.budget_limits[category] = annual_limit
    
    def get_monthly_costs(self, year: int, month: int) -> Dict:
        """获取月度成本"""
        monthly_costs = {}
        total_monthly_cost = 0
        
        for item in self.cost_data:
            item_date = datetime.fromisoformat(item["date"])
            if item_date.year == year and item_date.month == month:
                category = item["category"]
                if category not in monthly_costs:
                    monthly_costs[category] = 0
                monthly_costs[category] += item["amount"]
                total_monthly_cost += item["amount"]
        
        return {
            "year": year,
            "month": month,
            "categories": monthly_costs,
            "total": total_monthly_cost
        }
    
    def get_annual_costs(self, year: int) -> Dict:
        """获取年度成本"""
        annual_costs = {}
        total_annual_cost = 0
        monthly_breakdown = []
        
        for month in range(1, 13):
            monthly_data = self.get_monthly_costs(year, month)
            monthly_breakdown.append(monthly_data)
            
            for category, amount in monthly_data["categories"].items():
                if category not in annual_costs:
                    annual_costs[category] = 0
                annual_costs[category] += amount
                total_annual_cost += amount
        
        return {
            "year": year,
            "categories": annual_costs,
            "total": total_annual_cost,
            "monthly_breakdown": monthly_breakdown
        }
    
    def check_budget_status(self, year: int) -> Dict:
        """检查预算状态"""
        annual_costs = self.get_annual_costs(year)
        budget_status = {}
        
        for category, limit in self.budget_limits.items():
            actual_cost = annual_costs["categories"].get(category, 0)
            usage_percentage = (actual_cost / limit) * 100 if limit > 0 else 0
            remaining_budget = limit - actual_cost
            
            status = "正常"
            if usage_percentage > 90:
                status = "超预算"
            elif usage_percentage > 80:
                status = "接近上限"
            elif usage_percentage > 60:
                status = "警告"
            
            budget_status[category] = {
                "limit": limit,
                "actual": actual_cost,
                "remaining": remaining_budget,
                "usage_percentage": round(usage_percentage, 2),
                "status": status
            }
        
        return budget_status
    
    def analyze_cost_trends(self, months: int = 12) -> Dict:
        """分析成本趋势"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=months * 30)
        
        trends = {}
        monthly_totals = []
        
        for i in range(months):
            month_date = start_date + timedelta(days=i * 30)
            monthly_cost = self.get_monthly_costs(month_date.year, month_date.month)
            monthly_totals.append(monthly_cost["total"])
            
            for category, amount in monthly_cost["categories"].items():
                if category not in trends:
                    trends[category] = []
                trends[category].append(amount)
        
        # 计算趋势方向
        trend_analysis = {}
        for category, values in trends.items():
            if len(values) >= 2:
                recent_avg = sum(values[-3:]) / len(values[-3:])
                early_avg = sum(values[:3]) / len(values[:3])
                
                if recent_avg > early_avg * 1.1:
                    direction = "上升"
                elif recent_avg < early_avg * 0.9:
                    direction = "下降"
                else:
                    direction = "稳定"
                
                trend_analysis[category] = {
                    "direction": direction,
                    "recent_average": round(recent_avg, 2),
                    "early_average": round(early_avg, 2),
                    "change_percentage": round(((recent_avg - early_avg) / early_avg) * 100, 2) if early_avg > 0 else 0
                }
        
        return {
            "period_months": months,
            "monthly_totals": monthly_totals,
            "category_trends": trend_analysis,
            "overall_trend": "上升" if monthly_totals[-1] > monthly_totals[0] else "下降" if monthly_totals[-1] < monthly_totals[0] else "稳定"
        }
    
    def generate_cost_optimization_recommendations(self) -> List[Dict]:
        """生成成本优化建议"""
        recommendations = []
        current_year = datetime.now().year
        annual_costs = self.get_annual_costs(current_year)
        budget_status = self.check_budget_status(current_year)
        
        # 分析各类别成本
        for category, amount in annual_costs["categories"].items():
            category_name = self.cost_categories.get(category, category)
            
            if category == "software":
                if amount > 100000:  # 软件成本超过10万
                    recommendations.append({
                        "category": category,
                        "priority": "高",
                        "suggestion": f"{category_name}成本较高({amount:,.0f}元)，建议评估开源替代方案",
                        "potential_savings": amount * 0.3,  # 预计节省30%
                        "implementation": "审查软件许可使用情况，考虑开源方案"
                    })
            
            elif category == "cloud":
                if amount > 50000:  # 云服务成本超过5万
                    recommendations.append({
                        "category": category,
                        "priority": "中",
                        "suggestion": f"{category_name}成本({amount:,.0f}元)可通过优化资源配置降低",
                        "potential_savings": amount * 0.2,  # 预计节省20%
                        "implementation": "右键配置云资源，启用自动缩放和预留实例"
                    })
            
            elif category == "hardware":
                # 检查硬件更新周期
                recommendations.append({
                    "category": category,
                    "priority": "低",
                    "suggestion": f"建议制定{category_name}标准化采购策略",
                    "potential_savings": amount * 0.15,  # 预计节省15%
                    "implementation": "统一硬件规格，批量采购获得更好价格"
                })
        
        # 检查预算超支
        for category, status_info in budget_status.items():
            if status_info["status"] == "超预算":
                recommendations.append({
                    "category": category,
                    "priority": "紧急",
                    "suggestion": f"{self.cost_categories.get(category)}预算超支{status_info['usage_percentage']-100:.1f}%",
                    "potential_savings": status_info["actual"] - status_info["limit"],
                    "implementation": "立即审查并削减不必要开支"
                })
        
        return sorted(recommendations, key=lambda x: {"紧急": 4, "高": 3, "中": 2, "低": 1}[x["priority"]], reverse=True)
    
    def export_cost_report(self, year: int, format: str = "json") -> str:
        """导出成本报告"""
        annual_costs = self.get_annual_costs(year)
        budget_status = self.check_budget_status(year)
        trends = self.analyze_cost_trends()
        recommendations = self.generate_cost_optimization_recommendations()
        
        report = {
            "report_date": datetime.now().isoformat(),
            "year": year,
            "summary": {
                "total_cost": annual_costs["total"],
                "budget_utilization": sum(s["usage_percentage"] for s in budget_status.values()) / len(budget_status) if budget_status else 0,
                "over_budget_categories": [k for k, v in budget_status.items() if v["status"] == "超预算"]
            },
            "annual_costs": annual_costs,
            "budget_status": budget_status,
            "trends": trends,
            "optimization_recommendations": recommendations
        }
        
        if format == "json":
            filename = f"it_cost_report_{year}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename

# 使用示例和测试数据
def setup_sample_data():
    """设置示例数据"""
    cost_manager = ITCostManager()
    
    # 设置预算限制
    cost_manager.set_budget_limit("hardware", 600000)    # 硬件60万
    cost_manager.set_budget_limit("software", 400000)    # 软件40万
    cost_manager.set_budget_limit("cloud", 120000)       # 云服务12万
    cost_manager.set_budget_limit("personnel", 800000)   # 人力80万
    cost_manager.set_budget_limit("maintenance", 100000) # 维护10万
    
    # 添加示例成本数据
    sample_costs = [
        # 硬件成本
        ("hardware", "Dell服务器", 35000, "2024-01-15", "Web服务器", "Dell"),
        ("hardware", "华为交换机", 8000, "2024-02-10", "核心交换机", "华为"),
        ("hardware", "联想台式机", 120000, "2024-03-05", "办公电脑30台", "联想"),
        ("hardware", "惠普打印机", 15000, "2024-04-12", "网络打印机5台", "惠普"),
        
        # 软件成本
        ("software", "Microsoft 365", 60000, "2024-01-01", "100用户年度许可", "Microsoft"),
        ("software", "CRM系统", 80000, "2024-02-01", "客户管理系统", "Salesforce"),
        ("software", "ERP系统", 150000, "2024-03-01", "企业资源规划", "用友"),
        ("software", "安全软件", 25000, "2024-04-01", "企业防病毒", "卡巴斯基"),
        
        # 云服务成本
        ("cloud", "阿里云ECS", 8000, "2024-01-01", "云服务器月费", "阿里云"),
        ("cloud", "阿里云RDS", 3000, "2024-01-01", "云数据库月费", "阿里云"),
        ("cloud", "腾讯云CDN", 2000, "2024-01-01", "内容分发网络", "腾讯云"),
        
        # 人力成本
        ("personnel", "IT经理工资", 15000, "2024-01-01", "月工资", ""),
        ("personnel", "系统管理员工资", 12000, "2024-01-01", "月工资", ""),
        ("personnel", "网络管理员工资", 10000, "2024-01-01", "月工资", ""),
        
        # 维护成本
        ("maintenance", "服务器维保", 20000, "2024-01-01", "年度维保服务", "Dell"),
        ("maintenance", "网络设备维保", 15000, "2024-02-01", "年度维保服务", "华为"),
        
        # 培训费用
        ("training", "CISSP培训", 8000, "2024-03-01", "安全认证培训", "培训机构"),
        ("training", "云计算培训", 12000, "2024-04-01", "AWS认证培训", "AWS"),
    ]
    
    for category, name, amount, date, desc, vendor in sample_costs:
        cost_manager.add_cost_item(category, name, amount, date, desc, vendor)
    
    return cost_manager

if __name__ == "__main__":
    # 创建测试实例
    manager = setup_sample_data()
    
    # 生成成本报告
    current_year = datetime.now().year
    report_file = manager.export_cost_report(current_year)
    
    print(f"=== IT成本管理报告 ({current_year}年) ===")
    
    # 显示年度成本
    annual_costs = manager.get_annual_costs(current_year)
    print(f"\n年度总成本: {annual_costs['total']:,.0f} 元")
    
    print("\n各类别成本:")
    for category, amount in annual_costs["categories"].items():
        category_name = manager.cost_categories.get(category, category)
        print(f"  {category_name}: {amount:,.0f} 元")
    
    # 显示预算状态
    budget_status = manager.check_budget_status(current_year)
    print("\n预算执行情况:")
    for category, status in budget_status.items():
        category_name = manager.cost_categories.get(category, category)
        print(f"  {category_name}: {status['usage_percentage']:.1f}% ({status['status']})")
        print(f"    预算: {status['limit']:,.0f} 元, 实际: {status['actual']:,.0f} 元")
    
    # 显示优化建议
    recommendations = manager.generate_cost_optimization_recommendations()
    print("\n成本优化建议:")
    for i, rec in enumerate(recommendations[:5], 1):  # 显示前5个建议
        print(f"  {i}. [{rec['priority']}] {rec['suggestion']}")
        print(f"     预计节省: {rec['potential_savings']:,.0f} 元")
        print(f"     实施方案: {rec['implementation']}")
    
    print(f"\n详细报告已保存到: {report_file}")
```

### 4.2 资源优化

#### 云资源优化
```bash
#!/bin/bash
# 云资源成本优化脚本

# 云服务成本分析
analyze_cloud_costs() {
    echo "=== 分析云服务成本 ==="
    
    # 创建云成本分析脚本
    cat > /usr/local/bin/cloud_cost_analyzer.py << 'EOF'
#!/usr/bin/env python3
# 云服务成本分析工具

import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List

class CloudCostAnalyzer:
    def __init__(self, cloud_provider: str):
        self.provider = cloud_provider
        self.cost_data = []
    
    def analyze_aliyun_costs(self, access_key: str, secret_key: str) -> Dict:
        """分析阿里云成本"""
        # 注意：实际使用时需要安装阿里云SDK
        # pip install alibabacloud-bssopenapi20171214
        
        try:
            from alibabacloud_bssopenapi20171214.client import Client
            from alibabacloud_bssopenapi20171214 import models
            from alibabacloud_tea_openapi import models as open_api_models
            
            config = open_api_models.Config(
                access_key_id=access_key,
                access_key_secret=secret_key,
                endpoint='business.ap-southeast-1.aliyuncs.com'
            )
            
            client = Client(config)
            
            # 查询月度账单
            request = models.QueryAccountBillRequest(
                billing_cycle=datetime.now().strftime('%Y-%m'),
                granularity='MONTHLY'
            )
            
            response = client.query_account_bill(request)
            
            return {
                "provider": "阿里云",
                "total_cost": response.body.data.total_cost,
                "billing_cycle": response.body.data.billing_cycle,
                "items": response.body.data.items
            }
            
        except Exception as e:
            return {"error": f"阿里云成本分析失败: {str(e)}"}
    
    def analyze_aws_costs(self, access_key: str, secret_key: str, region: str) -> Dict:
        """分析AWS成本"""
        # 注意：实际使用时需要安装AWS SDK
        # pip install boto3
        
        try:
            import boto3
            
            client = boto3.client(
                'ce',  # Cost Explorer
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            
            # 获取当月成本
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now().replace(day=1)).strftime('%Y-%m-%d')
            
            response = client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='MONTHLY',
                Metrics=['BlendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )
            
            return {
                "provider": "AWS",
                "period": f"{start_date} to {end_date}",
                "results": response['ResultsByTime']
            }
            
        except Exception as e:
            return {"error": f"AWS成本分析失败: {str(e)}"}
    
    def generate_optimization_recommendations(self, cost_data: Dict) -> List[Dict]:
        """生成优化建议"""
        recommendations = []
        
        if cost_data.get("provider") == "阿里云":
            # 阿里云优化建议
            recommendations.extend([
                {
                    "service": "ECS实例",
                    "suggestion": "分析实例使用率，关闭低使用率实例",
                    "potential_saving": "20-40%",
                    "priority": "高"
                },
                {
                    "service": "存储服务",
                    "suggestion": "使用对象存储IA/Archive降低存储成本",
                    "potential_saving": "50-80%",
                    "priority": "中"
                },
                {
                    "service": "网络带宽",
                    "suggestion": "优化带宽配置，使用CDN加速",
                    "potential_saving": "10-30%",
                    "priority": "中"
                }
            ])
        
        elif cost_data.get("provider") == "AWS":
            # AWS优化建议
            recommendations.extend([
                {
                    "service": "EC2实例",
                    "suggestion": "使用预留实例或Spot实例降低成本",
                    "potential_saving": "30-70%",
                    "priority": "高"
                },
                {
                    "service": "S3存储",
                    "suggestion": "配置生命周期策略，自动转移到便宜存储类",
                    "potential_saving": "40-80%",
                    "priority": "高"
                },
                {
                    "service": "RDS数据库",
                    "suggestion": "使用预留容量，优化实例规格",
                    "potential_saving": "20-50%",
                    "priority": "中"
                }
            ])
        
        return recommendations

# 模拟使用示例
if __name__ == "__main__":
    analyzer = CloudCostAnalyzer("aliyun")
    
    # 模拟成本数据
    mock_cost_data = {
        "provider": "阿里云",
        "total_cost": 25000,
        "billing_cycle": "2024-08",
        "services": {
            "ECS": 15000,
            "RDS": 5000,
            "OSS": 2000,
            "CDN": 1500,
            "其他": 1500
        }
    }
    
    recommendations = analyzer.generate_optimization_recommendations(mock_cost_data)
    
    print("=== 云服务成本优化建议 ===")
    for rec in recommendations:
        print(f"服务: {rec['service']}")
        print(f"建议: {rec['suggestion']}")
        print(f"预计节省: {rec['potential_saving']}")
        print(f"优先级: {rec['priority']}")
        print()
EOF
    
    chmod +x /usr/local/bin/cloud_cost_analyzer.py
    
    echo "云成本分析工具创建完成"
}

# 资源使用优化
optimize_resource_usage() {
    echo "=== 优化资源使用 ==="
    
    # 创建资源监控和优化脚本
    cat > /usr/local/bin/resource_optimizer.sh << 'EOF'
#!/bin/bash
# 系统资源优化脚本

# 检查并清理不必要的服务
optimize_services() {
    echo "=== 优化系统服务 ==="
    
    # 不必要的服务列表（根据具体环境调整）
    UNNECESSARY_SERVICES=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "whoopsie"
        "snapd"
    )
    
    for service in "${UNNECESSARY_SERVICES[@]}"; do
        if systemctl is-enabled $service >/dev/null 2>&1; then
            echo "禁用服务: $service"
            systemctl disable $service
            systemctl stop $service
        fi
    done
}

# 优化内存使用
optimize_memory() {
    echo "=== 优化内存使用 ==="
    
    # 清理页面缓存
    echo 1 > /proc/sys/vm/drop_caches
    
    # 检查内存占用最高的进程
    echo "内存占用TOP 10进程:"
    ps aux --sort=-%mem | head -11
    
    # 检查是否有内存泄漏
    MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.2f"), $3/$2 * 100.0}')
    if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then
        echo "警告: 内存使用率过高 ($MEMORY_USAGE%)"
        
        # 重启占用内存过多的非关键服务
        HIGH_MEM_SERVICES=$(ps aux --sort=-%mem | awk 'NR>1 && $4>10 {print $11}' | head -5)
        for service in $HIGH_MEM_SERVICES; do
            if [[ "$service" != "mysqld" && "$service" != "apache2" ]]; then
                echo "重启高内存使用服务: $service"
                systemctl restart $service 2>/dev/null || true
            fi
        done
    fi
}

# 优化磁盘使用
optimize_disk() {
    echo "=== 优化磁盘使用 ==="
    
    # 清理系统临时文件
    echo "清理临时文件..."
    find /tmp -type f -atime +7 -delete 2>/dev/null || true
    find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
    
    # 清理日志文件
    echo "清理旧日志文件..."
    find /var/log -name "*.log" -mtime +30 -delete 2>/dev/null || true
    find /var/log -name "*.gz" -mtime +90 -delete 2>/dev/null || true
    
    # 清理APT缓存
    apt clean
    apt autoremove -y
    
    # 清理Docker镜像（如果安装了Docker）
    if command -v docker >/dev/null 2>&1; then
        echo "清理Docker未使用的镜像..."
        docker system prune -f 2>/dev/null || true
    fi
    
    # 检查磁盘使用情况
    echo "磁盘使用情况:"
    df -h | grep -E '^/dev/'
    
    # 找出占用空间最大的目录
    echo "占用空间最大的目录 TOP 10:"
    du -h /var /opt /home /usr 2>/dev/null | sort -hr | head -10
}

# 优化网络配置
optimize_network() {
    echo "=== 优化网络配置 ==="
    
    # 检查网络连接数
    CONNECTIONS=$(netstat -an | wc -l)
    echo "当前网络连接数: $CONNECTIONS"
    
    if [ $CONNECTIONS -gt 1000 ]; then
        echo "警告: 网络连接数过多，检查是否有异常连接"
        netstat -an | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
    fi
    
    # 优化网络参数（如果尚未优化）
    if ! grep -q "net.core.rmem_max" /etc/sysctl.conf; then
        echo "应用网络优化参数..."
        cat >> /etc/sysctl.conf << 'NETWORK_EOF'

# 网络性能优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
NETWORK_EOF
        sysctl -p
    fi
}

# 数据库优化
optimize_database() {
    echo "=== 优化数据库性能 ==="
    
    if systemctl is-active mysql >/dev/null 2>&1; then
        echo "优化MySQL数据库..."
        
        # 分析慢查询
        if [ -f /var/log/mysql/slow.log ]; then
            SLOW_QUERIES=$(wc -l < /var/log/mysql/slow.log)
            echo "慢查询数量: $SLOW_QUERIES"
            
            if [ $SLOW_QUERIES -gt 100 ]; then
                echo "警告: 慢查询过多，建议优化SQL语句"
            fi
        fi
        
        # 检查数据库表优化
        mysql -u root -p -e "
            SELECT table_schema, table_name, 
                   ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'DB Size in MB' 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
            ORDER BY (data_length + index_length) DESC 
            LIMIT 10;" 2>/dev/null || echo "需要MySQL root密码进行数据库分析"
        
        # 检查MySQL进程列表
        mysql -u root -p -e "SHOW PROCESSLIST;" 2>/dev/null | head -20 || true
    fi
}

# 主执行函数
main() {
    echo "开始系统资源优化 - $(date)"
    
    optimize_services
    optimize_memory
    optimize_disk
    optimize_network
    optimize_database
    
    echo "系统资源优化完成 - $(date)"
    
    # 生成优化报告
    cat > /var/log/resource_optimization_$(date +%Y%m%d).log << REPORT_EOF
系统资源优化报告
生成时间: $(date)

系统负载: $(uptime)
内存使用: $(free -h | grep Mem)
磁盘使用: $(df -h / | tail -1)
网络连接: $(netstat -an | wc -l) 个连接

优化操作已完成，详细日志请查看系统日志。
REPORT_EOF
    
    echo "优化报告保存到: /var/log/resource_optimization_$(date +%Y%m%d).log"
}

# 执行优化
main "$@"
EOF
    
    chmod +x /usr/local/bin/resource_optimizer.sh
    
    # 添加到定时任务（每周执行一次）
    echo "0 2 * * 0 /usr/local/bin/resource_optimizer.sh" | crontab -
    
    echo "资源优化脚本创建完成，已加入周定时任务"
}

# 软件许可优化
optimize_software_licenses() {
    echo "=== 优化软件许可成本 ==="
    
    # 创建许可证管理脚本
    cat > /usr/local/bin/license_manager.py << 'EOF'
#!/usr/bin/env python3
# 软件许可证管理和优化工具

import json
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class LicenseManager:
    def __init__(self):
        self.licenses = []
        self.load_licenses()
    
    def load_licenses(self):
        """加载许可证数据"""
        try:
            with open('/etc/licenses/license_inventory.json', 'r') as f:
                self.licenses = json.load(f)
        except FileNotFoundError:
            # 创建示例许可证数据
            self.licenses = [
                {
                    "software": "Microsoft Office 365",
                    "type": "subscription",
                    "total_licenses": 100,
                    "used_licenses": 85,
                    "cost_per_license": 50,
                    "renewal_date": "2024-12-31",
                    "vendor": "Microsoft",
                    "category": "productivity"
                },
                {
                    "software": "Adobe Creative Suite",
                    "type": "subscription", 
                    "total_licenses": 10,
                    "used_licenses": 7,
                    "cost_per_license": 200,
                    "renewal_date": "2024-10-15",
                    "vendor": "Adobe",
                    "category": "design"
                },
                {
                    "software": "AutoCAD",
                    "type": "perpetual",
                    "total_licenses": 5,
                    "used_licenses": 5,
                    "cost_per_license": 1500,
                    "renewal_date": "2025-03-01",
                    "vendor": "Autodesk",
                    "category": "engineering"
                }
            ]
            self.save_licenses()
    
    def save_licenses(self):
        """保存许可证数据"""
        import os
        os.makedirs('/etc/licenses', exist_ok=True)
        with open('/etc/licenses/license_inventory.json', 'w') as f:
            json.dump(self.licenses, f, indent=2)
    
    def analyze_license_utilization(self) -> Dict:
        """分析许可证使用率"""
        analysis = {
            "total_licenses": 0,
            "used_licenses": 0,
            "unused_licenses": 0,
            "utilization_rate": 0,
            "annual_cost": 0,
            "wasted_cost": 0,
            "by_category": {},
            "underutilized": []
        }
        
        for license in self.licenses:
            total = license["total_licenses"]
            used = license["used_licenses"]
            unused = total - used
            cost = license["cost_per_license"]
            category = license["category"]
            
            analysis["total_licenses"] += total
            analysis["used_licenses"] += used
            analysis["unused_licenses"] += unused
            
            if license["type"] == "subscription":
                annual_cost = total * cost * 12
                wasted_cost = unused * cost * 12
            else:
                annual_cost = total * cost / 5  # 假设永久许可5年摊销
                wasted_cost = unused * cost / 5
            
            analysis["annual_cost"] += annual_cost
            analysis["wasted_cost"] += wasted_cost
            
            # 按类别统计
            if category not in analysis["by_category"]:
                analysis["by_category"][category] = {
                    "total": 0, "used": 0, "cost": 0, "waste": 0
                }
            
            analysis["by_category"][category]["total"] += total
            analysis["by_category"][category]["used"] += used
            analysis["by_category"][category]["cost"] += annual_cost
            analysis["by_category"][category]["waste"] += wasted_cost
            
            # 识别利用率低的软件
            utilization = (used / total) * 100 if total > 0 else 0
            if utilization < 70:  # 利用率低于70%
                analysis["underutilized"].append({
                    "software": license["software"], 
                    "utilization": round(utilization, 1),
                    "unused_licenses": unused,
                    "wasted_annual_cost": round(wasted_cost, 2)
                })
        
        if analysis["total_licenses"] > 0:
            analysis["utilization_rate"] = round(
                (analysis["used_licenses"] / analysis["total_licenses"]) * 100, 2
            )
        
        return analysis
    
    def find_expiring_licenses(self, days_ahead: int = 90) -> List[Dict]:
        """查找即将到期的许可证"""
        expiring = []
        cutoff_date = datetime.now() + timedelta(days=days_ahead)
        
        for license in self.licenses:
            renewal_date = datetime.strptime(license["renewal_date"], "%Y-%m-%d")
            days_until_expiry = (renewal_date - datetime.now()).days
            
            if days_until_expiry <= days_ahead:
                expiring.append({
                    **license,
                    "days_until_expiry": days_until_expiry,
                    "renewal_cost": license["total_licenses"] * license["cost_per_license"]
                })
        
        return sorted(expiring, key=lambda x: x["days_until_expiry"])
    
    def generate_optimization_recommendations(self) -> List[Dict]:
        """生成许可证优化建议"""
        recommendations = []
        analysis = self.analyze_license_utilization()
        
        # 针对利用率低的软件
        for item in analysis["underutilized"]:
            if item["utilization"] < 50:
                priority = "高"
                action = "考虑减少许可证数量或寻找替代方案"
            else:
                priority = "中"
                action = "监控使用情况，适当调整许可证数量"
            
            recommendations.append({
                "type": "利用率优化",
                "software": item["software"],
                "priority": priority,
                "current_utilization": f"{item['utilization']}%",
                "potential_savings": item["wasted_annual_cost"],
                "recommendation": action
            })
        
        # 检查是否有开源替代方案
        opensource_alternatives = {
            "Microsoft Office 365": {"alternative": "LibreOffice + Nextcloud", "savings": 0.8},
            "Adobe Creative Suite": {"alternative": "GIMP + Inkscape", "savings": 0.9},
            "AutoCAD": {"alternative": "FreeCAD + QCAD", "savings": 0.95}
        }
        
        for license in self.licenses:
            software = license["software"]
            if software in opensource_alternatives:
                alt = opensource_alternatives[software]
                annual_cost = license["total_licenses"] * license["cost_per_license"] * (12 if license["type"] == "subscription" else 0.2)
                potential_savings = annual_cost * alt["savings"]
                
                recommendations.append({
                    "type": "开源替代",
                    "software": software,
                    "priority": "中",
                    "alternative": alt["alternative"],
                    "potential_savings": round(potential_savings, 2),
                    "recommendation": f"评估{alt['alternative']}作为替代方案"
                })
        
        # 许可证整合建议
        categories = analysis["by_category"]
        for category, data in categories.items():
            if data["total"] > 50 and data["waste"] > 10000:
                recommendations.append({
                    "type": "许可证整合",
                    "category": category,
                    "priority": "中",
                    "current_waste": data["waste"],
                    "potential_savings": data["waste"] * 0.3,
                    "recommendation": f"整合{category}类软件许可证，统一采购获得更好价格"
                })
        
        return sorted(recommendations, 
                     key=lambda x: {"高": 3, "中": 2, "低": 1}[x["priority"]], 
                     reverse=True)
    
    def export_license_report(self) -> str:
        """导出许可证报告"""
        analysis = self.analyze_license_utilization()
        expiring = self.find_expiring_licenses()
        recommendations = self.generate_optimization_recommendations()
        
        report = {
            "report_date": datetime.now().isoformat(),
            "license_analysis": analysis,
            "expiring_licenses": expiring,
            "optimization_recommendations": recommendations,
            "summary": {
                "total_annual_cost": round(analysis["annual_cost"], 2),
                "potential_savings": round(analysis["wasted_cost"], 2),
                "utilization_rate": analysis["utilization_rate"],
                "licenses_expiring_soon": len(expiring)
            }
        }
        
        filename = f"license_report_{datetime.now().strftime('%Y%m%d')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename

# 使用示例
if __name__ == "__main__":
    manager = LicenseManager()
    
    print("=== 软件许可证分析报告 ===")
    
    # 使用率分析
    analysis = manager.analyze_license_utilization()
    print(f"\n许可证使用率: {analysis['utilization_rate']}%")
    print(f"年度许可成本: {analysis['annual_cost']:,.0f} 元")
    print(f"浪费成本: {analysis['wasted_cost']:,.0f} 元")
    
    # 即将到期的许可证
    expiring = manager.find_expiring_licenses(90)
    if expiring:
        print(f"\n90天内到期的许可证 ({len(expiring)}个):")
        for license in expiring:
            print(f"  {license['software']}: {license['days_until_expiry']}天后到期")
    
    # 优化建议
    recommendations = manager.generate_optimization_recommendations()
    print(f"\n优化建议 (前5项):")
    for i, rec in enumerate(recommendations[:5], 1):
        print(f"  {i}. [{rec['priority']}] {rec['software'] if 'software' in rec else rec['category']}")
        print(f"     建议: {rec['recommendation']}")
        if 'potential_savings' in rec:
            print(f"     预计节省: {rec['potential_savings']:,.0f} 元")
    
    # 导出详细报告
    report_file = manager.export_license_report()
    print(f"\n详细报告已保存到: {report_file}")
EOF
    
    chmod +x /usr/local/bin/license_manager.py
    
    echo "软件许可证管理工具创建完成"
}

# 主函数
main() {
    case $1 in
        "cloud")
            analyze_cloud_costs
            ;;
        "resource")
            optimize_resource_usage
            ;;
        "license") 
            optimize_software_licenses
            ;;
        "all")
            analyze_cloud_costs
            optimize_resource_usage
            optimize_software_licenses
            ;;
        *)
            echo "使用方法: $0 {cloud|resource|license|all}"
            echo ""
            echo "可用选项:"
            echo "  cloud    - 分析云服务成本"
            echo "  resource - 优化系统资源使用"
            echo "  license  - 优化软件许可成本"
            echo "  all      - 执行所有成本优化"
            ;;
    esac
}

main "$@"
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*适用规模：50-100人中小企业*  
*负责人：IT管理团队*