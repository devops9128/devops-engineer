# 落地阶段 - IT基础设施管理

## 阶段概述
落地阶段是系统正式投入生产使用的关键时期，包括正式上线、运行监控、问题处理和性能优化等核心活动，确保系统稳定运行并满足业务需求。

## 1. 正式上线管理

### 1.1 上线准备检查清单

#### 技术准备验证
```yaml
上线前技术检查清单:
  基础设施检查:
    - [ ] 所有服务器运行正常
    - [ ] 网络连通性测试通过
    - [ ] 存储系统工作正常
    - [ ] 负载均衡配置正确
    - [ ] SSL证书有效且配置正确
    - [ ] 防火墙规则配置完成
    - [ ] DNS解析配置正确
    
  应用系统检查:
    - [ ] 所有应用服务启动成功
    - [ ] 数据库连接测试通过
    - [ ] 缓存系统工作正常
    - [ ] API接口测试通过
    - [ ] 文件上传下载功能正常
    - [ ] 用户认证系统正常
    
  监控系统检查:
    - [ ] 监控系统采集数据正常
    - [ ] 告警规则配置完成
    - [ ] 告警通知渠道测试通过
    - [ ] 日志收集系统正常
    - [ ] 性能监控仪表板就绪
    
  备份系统检查:
    - [ ] 自动备份任务配置完成
    - [ ] 备份数据完整性验证
    - [ ] 恢复流程测试通过
    - [ ] 异地备份配置正确
```

#### 业务准备验证
```yaml
上线前业务检查清单:
  用户培训:
    - [ ] 管理员培训完成
    - [ ] 终端用户培训完成
    - [ ] 操作手册发布
    - [ ] 常见问题FAQ准备
    
  流程准备:
    - [ ] 业务流程文档更新
    - [ ] 应急响应流程确认
    - [ ] 变更管理流程就绪
    - [ ] 故障处理流程明确
    
  支持准备:
    - [ ] 技术支持团队就位
    - [ ] 7x24小时值班安排
    - [ ] 供应商支持热线确认
    - [ ] 升级联系人清单准备
```

### 1.2 上线实施流程

#### 分阶段上线策略
```bash
#!/bin/bash
# 分阶段上线自动化脚本

# 阶段1: 内部用户测试 (10%流量)
phase1_rollout() {
    echo "=== 阶段1: 内部用户测试开始 ==="
    
    # 配置负载均衡器，将10%流量导向新系统
    curl -X POST "https://lb.company.local/api/config" \
         -H "Authorization: Bearer $LB_API_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{
           "traffic_split": {
             "new_system": 10,
             "old_system": 90
           },
           "target_users": ["internal"]
         }'
    
    # 监控关键指标
    monitor_metrics 30  # 监控30分钟
    
    if check_health_status; then
        echo "✓ 阶段1成功，准备进入阶段2"
        return 0
    else
        echo "✗ 阶段1失败，执行回滚"
        rollback_phase1
        return 1
    fi
}

# 阶段2: 部分用户测试 (30%流量)  
phase2_rollout() {
    echo "=== 阶段2: 部分用户测试开始 ==="
    
    curl -X POST "https://lb.company.local/api/config" \
         -H "Authorization: Bearer $LB_API_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{
           "traffic_split": {
             "new_system": 30,
             "old_system": 70
           }
         }'
    
    monitor_metrics 60  # 监控60分钟
    
    if check_health_status; then
        echo "✓ 阶段2成功，准备进入阶段3"
        return 0
    else
        echo "✗ 阶段2失败，执行回滚"
        rollback_phase2
        return 1
    fi
}

# 阶段3: 全量上线 (100%流量)
phase3_rollout() {
    echo "=== 阶段3: 全量上线开始 ==="
    
    curl -X POST "https://lb.company.local/api/config" \
         -H "Authorization: Bearer $LB_API_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{
           "traffic_split": {
             "new_system": 100,
             "old_system": 0
           }
         }'
    
    monitor_metrics 120  # 监控120分钟
    
    if check_health_status; then
        echo "✓ 全量上线成功"
        notify_stakeholders "上线成功"
        return 0
    else
        echo "✗ 全量上线失败，执行紧急回滚"
        emergency_rollback
        return 1
    fi
}

# 健康状态检查
check_health_status() {
    local error_rate=$(get_error_rate)
    local response_time=$(get_avg_response_time)
    local cpu_usage=$(get_cpu_usage)
    local memory_usage=$(get_memory_usage)
    
    echo "当前系统指标:"
    echo "  错误率: ${error_rate}%"
    echo "  平均响应时间: ${response_time}ms"
    echo "  CPU使用率: ${cpu_usage}%"
    echo "  内存使用率: ${memory_usage}%"
    
    # 健康状态阈值检查
    if (( $(echo "$error_rate > 5" | bc -l) )); then
        echo "✗ 错误率超过阈值(5%)"
        return 1
    fi
    
    if (( $(echo "$response_time > 3000" | bc -l) )); then
        echo "✗ 响应时间超过阈值(3000ms)"
        return 1
    fi
    
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        echo "✗ CPU使用率超过阈值(80%)"
        return 1
    fi
    
    if (( $(echo "$memory_usage > 85" | bc -l) )); then
        echo "✗ 内存使用率超过阈值(85%)"
        return 1
    fi
    
    echo "✓ 所有健康指标正常"
    return 0
}

# 执行分阶段上线
main() {
    echo "开始分阶段上线流程..."
    
    if phase1_rollout; then
        if phase2_rollout; then
            if phase3_rollout; then
                echo "🎉 上线流程全部完成！"
                cleanup_old_system
            fi
        fi
    fi
}

# 执行主流程
main
```

#### 数据迁移管理
```sql
-- 数据迁移脚本示例

-- 1. 创建迁移日志表
CREATE TABLE migration_log (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status VARCHAR(50),
    error_message TEXT,
    rows_migrated INTEGER DEFAULT 0
);

-- 2. 用户数据迁移
DO $$
DECLARE
    migration_name VARCHAR(255) := '用户数据迁移';
    start_time TIMESTAMP := CURRENT_TIMESTAMP;
    migrated_count INTEGER := 0;
    error_msg TEXT := '';
BEGIN
    -- 记录迁移开始
    INSERT INTO migration_log (migration_name, start_time, status) 
    VALUES (migration_name, start_time, 'RUNNING');
    
    -- 执行迁移
    BEGIN
        -- 迁移用户基本信息
        INSERT INTO new_users (
            user_id, username, email, phone, 
            created_at, updated_at, status
        )
        SELECT 
            id, login_name, email_address, phone_number,
            create_time, modify_time, user_status
        FROM old_users 
        WHERE migrate_flag = 0;
        
        GET DIAGNOSTICS migrated_count = ROW_COUNT;
        
        -- 更新迁移标志
        UPDATE old_users SET migrate_flag = 1 WHERE migrate_flag = 0;
        
        -- 更新迁移日志
        UPDATE migration_log 
        SET end_time = CURRENT_TIMESTAMP, 
            status = 'COMPLETED',
            rows_migrated = migrated_count
        WHERE migration_name = migration_name 
        AND start_time = start_time;
        
        RAISE NOTICE '用户数据迁移完成，共迁移 % 条记录', migrated_count;
        
    EXCEPTION WHEN OTHERS THEN
        error_msg := SQLERRM;
        
        -- 记录错误
        UPDATE migration_log 
        SET end_time = CURRENT_TIMESTAMP, 
            status = 'FAILED',
            error_message = error_msg
        WHERE migration_name = migration_name 
        AND start_time = start_time;
        
        RAISE EXCEPTION '用户数据迁移失败: %', error_msg;
    END;
END $$;

-- 3. 数据一致性检查
DO $$
DECLARE
    old_count INTEGER;
    new_count INTEGER;
    consistency_check BOOLEAN := TRUE;
BEGIN
    -- 检查用户数量一致性
    SELECT COUNT(*) INTO old_count FROM old_users WHERE migrate_flag = 1;
    SELECT COUNT(*) INTO new_count FROM new_users;
    
    IF old_count != new_count THEN
        consistency_check := FALSE;
        RAISE WARNING '用户数量不一致: 旧系统=%, 新系统=%', old_count, new_count;
    END IF;
    
    -- 检查关键字段一致性
    PERFORM 1 FROM old_users o 
    LEFT JOIN new_users n ON o.id = n.user_id 
    WHERE o.migrate_flag = 1 AND n.user_id IS NULL;
    
    IF FOUND THEN
        consistency_check := FALSE;
        RAISE WARNING '发现数据不一致的用户记录';
    END IF;
    
    IF consistency_check THEN
        RAISE NOTICE '✓ 数据一致性检查通过';
    ELSE
        RAISE EXCEPTION '✗ 数据一致性检查失败';
    END IF;
END $$;
```

### 1.3 用户切换管理

#### 用户分批切换策略
```python
#!/usr/bin/env python3
# 用户分批切换管理脚本

import time
import json
import requests
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UserMigrationManager:
    def __init__(self):
        self.api_base_url = "https://api.company.local"
        self.api_token = "your_api_token"
        self.migration_batches = []
        
    def create_migration_batches(self):
        """创建用户迁移批次"""
        
        # 批次1: IT部门用户 (优先迁移，熟悉系统)
        batch1 = {
            'batch_id': 1,
            'name': 'IT部门用户',
            'user_filter': {'department': 'IT'},
            'migration_time': datetime.now() + timedelta(hours=1),
            'rollback_threshold': {'error_rate': 10, 'timeout': 30}
        }
        
        # 批次2: 管理层用户
        batch2 = {
            'batch_id': 2,
            'name': '管理层用户',
            'user_filter': {'role': 'manager'},
            'migration_time': datetime.now() + timedelta(hours=4),
            'rollback_threshold': {'error_rate': 5, 'timeout': 60}
        }
        
        # 批次3: 销售部门用户
        batch3 = {
            'batch_id': 3,
            'name': '销售部门用户',
            'user_filter': {'department': 'Sales'},
            'migration_time': datetime.now() + timedelta(hours=8),
            'rollback_threshold': {'error_rate': 3, 'timeout': 120}
        }
        
        # 批次4: 其他部门用户
        batch4 = {
            'batch_id': 4,
            'name': '其他部门用户',
            'user_filter': {'department': ['HR', 'Finance', 'Operations']},
            'migration_time': datetime.now() + timedelta(days=1),
            'rollback_threshold': {'error_rate': 2, 'timeout': 180}
        }
        
        self.migration_batches = [batch1, batch2, batch3, batch4]
        logger.info(f"创建了 {len(self.migration_batches)} 个迁移批次")
        
    def migrate_user_batch(self, batch):
        """迁移指定批次的用户"""
        
        logger.info(f"开始迁移批次: {batch['name']}")
        
        try:
            # 1. 获取批次用户列表
            users = self.get_batch_users(batch['user_filter'])
            logger.info(f"批次 {batch['name']} 包含 {len(users)} 个用户")
            
            # 2. 更新用户路由配置
            for user in users:
                self.update_user_routing(user['user_id'], 'new_system')
                logger.debug(f"用户 {user['username']} 已切换到新系统")
            
            # 3. 监控迁移效果
            monitoring_result = self.monitor_batch_migration(batch, users)
            
            # 4. 判断是否需要回滚
            if self.should_rollback(monitoring_result, batch['rollback_threshold']):
                logger.warning(f"批次 {batch['name']} 需要回滚")
                self.rollback_user_batch(batch, users)
                return False
            else:
                logger.info(f"批次 {batch['name']} 迁移成功")
                self.mark_batch_completed(batch['batch_id'])
                return True
                
        except Exception as e:
            logger.error(f"批次 {batch['name']} 迁移失败: {str(e)}")
            self.rollback_user_batch(batch, users)
            return False
    
    def get_batch_users(self, user_filter):
        """根据过滤条件获取用户列表"""
        
        response = requests.post(
            f"{self.api_base_url}/users/filter",
            headers={'Authorization': f'Bearer {self.api_token}'},
            json=user_filter
        )
        
        if response.status_code == 200:
            return response.json()['users']
        else:
            raise Exception(f"获取用户列表失败: {response.text}")
    
    def update_user_routing(self, user_id, target_system):
        """更新用户路由配置"""
        
        response = requests.put(
            f"{self.api_base_url}/routing/user/{user_id}",
            headers={'Authorization': f'Bearer {self.api_token}'},
            json={'target_system': target_system}
        )
        
        if response.status_code != 200:
            raise Exception(f"更新用户路由失败: {response.text}")
    
    def monitor_batch_migration(self, batch, users):
        """监控批次迁移效果"""
        
        logger.info(f"开始监控批次 {batch['name']} 迁移效果...")
        
        monitoring_duration = batch['rollback_threshold']['timeout']
        start_time = time.time()
        
        metrics = {
            'error_count': 0,
            'total_requests': 0,
            'avg_response_time': 0,
            'user_complaints': 0
        }
        
        while time.time() - start_time < monitoring_duration:
            # 收集性能指标
            current_metrics = self.collect_metrics(users)
            
            metrics['error_count'] += current_metrics['error_count']
            metrics['total_requests'] += current_metrics['total_requests']
            metrics['avg_response_time'] = current_metrics['avg_response_time']
            metrics['user_complaints'] += current_metrics['user_complaints']
            
            # 每分钟记录一次指标
            logger.info(f"当前指标 - 错误率: {(metrics['error_count']/max(metrics['total_requests'], 1))*100:.2f}%, "
                       f"平均响应时间: {metrics['avg_response_time']}ms, "
                       f"用户投诉: {metrics['user_complaints']}")
            
            time.sleep(60)  # 每分钟检查一次
        
        return metrics
    
    def should_rollback(self, metrics, threshold):
        """判断是否需要回滚"""
        
        error_rate = (metrics['error_count'] / max(metrics['total_requests'], 1)) * 100
        
        if error_rate > threshold['error_rate']:
            logger.warning(f"错误率 {error_rate:.2f}% 超过阈值 {threshold['error_rate']}%")
            return True
        
        if metrics['avg_response_time'] > 5000:  # 5秒
            logger.warning(f"平均响应时间 {metrics['avg_response_time']}ms 过长")
            return True
        
        if metrics['user_complaints'] > 10:
            logger.warning(f"用户投诉数量 {metrics['user_complaints']} 过多")
            return True
        
        return False
    
    def rollback_user_batch(self, batch, users):
        """回滚用户批次"""
        
        logger.info(f"开始回滚批次: {batch['name']}")
        
        for user in users:
            self.update_user_routing(user['user_id'], 'old_system')
            logger.debug(f"用户 {user['username']} 已回滚到旧系统")
        
        # 发送回滚通知
        self.send_rollback_notification(batch, users)
        
    def execute_migration_plan(self):
        """执行完整的迁移计划"""
        
        logger.info("开始执行用户迁移计划...")
        
        for batch in self.migration_batches:
            # 等待到预定的迁移时间
            while datetime.now() < batch['migration_time']:
                logger.info(f"等待批次 {batch['name']} 迁移时间...")
                time.sleep(300)  # 每5分钟检查一次
            
            # 执行批次迁移
            success = self.migrate_user_batch(batch)
            
            if not success:
                logger.error(f"批次 {batch['name']} 迁移失败，暂停后续迁移")
                break
            
            # 批次间间隔
            logger.info("等待下一个批次...")
            time.sleep(3600)  # 1小时间隔
        
        logger.info("用户迁移计划执行完成")

if __name__ == "__main__":
    manager = UserMigrationManager()
    manager.create_migration_batches()
    manager.execute_migration_plan()
```

## 2. 运行监控管理

### 2.1 实时监控系统

#### 监控仪表板配置
```yaml
# Grafana监控仪表板配置
Grafana仪表板:
  系统概览仪表板:
    名称: "IT基础设施总览"
    刷新间隔: 30秒
    
    面板配置:
      服务状态面板:
        类型: "状态面板"
        数据源: "Prometheus"
        查询: |
          up{job=~"web-server|database|cache"}
        显示: 服务在线状态
        
      系统负载面板:
        类型: "时间序列图"
        数据源: "Prometheus"
        查询: |
          avg(node_load1{instance=~".*"})
          avg(node_load5{instance=~".*"})
          avg(node_load15{instance=~".*"})
        标题: "系统平均负载"
        
      CPU使用率面板:
        类型: "统计面板"
        数据源: "Prometheus"
        查询: |
          100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
        阈值: 
          - 绿色: 0-70%
          - 黄色: 70-85%
          - 红色: 85-100%
          
      内存使用率面板:
        类型: "量表"
        数据源: "Prometheus"
        查询: |
          (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100
        阈值: 
          - 绿色: 0-75%
          - 黄色: 75-90%
          - 红色: 90-100%
          
      磁盘使用率面板:
        类型: "柱状图"
        数据源: "Prometheus"
        查询: |
          100 - ((node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}) * 100)
          
      网络流量面板:
        类型: "时间序列图"
        数据源: "Prometheus"
        查询: |
          irate(node_network_receive_bytes_total{device!="lo"}[5m]) * 8
          irate(node_network_transmit_bytes_total{device!="lo"}[5m]) * 8
        单位: "bps"
        
      应用响应时间面板:
        类型: "时间序列图"
        数据源: "Prometheus"
        查询: |
          histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))
        标题: "95%响应时间"
        
      数据库连接数面板:
        类型: "单一统计"
        数据源: "Prometheus"
        查询: |
          postgresql_total_connections
          mysql_global_status_threads_connected
          
      错误率面板:
        类型: "时间序列图"
        数据源: "Prometheus"
        查询: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100
        阈值线: 5%

  告警规则配置:
    CPU使用率告警:
      表达式: |
        100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 85
      持续时间: 5分钟
      严重级别: 警告
      
    内存使用率告警:
      表达式: |
        (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
      持续时间: 3分钟
      严重级别: 严重
      
    磁盘空间告警:
      表达式: |
        100 - ((node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"} / node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}) * 100) > 85
      持续时间: 1分钟
      严重级别: 警告
      
    服务宕机告警:
      表达式: |
        up{job=~"web-server|database|cache"} == 0
      持续时间: 30秒
      严重级别: 紧急
      
    响应时间告警:
      表达式: |
        histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 3
      持续时间: 2分钟
      严重级别: 警告
```

#### 自动化监控脚本
```bash
#!/bin/bash
# 自动化监控检查脚本

# 配置参数
MONITORING_LOG="/var/log/infrastructure-monitoring.log"
ALERT_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
EMAIL_RECIPIENTS="admin@company.local,ops@company.local"

# 日志函数
log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a $MONITORING_LOG
}

# 发送告警
send_alert() {
    local title=$1
    local message=$2
    local severity=$3
    
    # 发送Slack通知
    curl -X POST $ALERT_WEBHOOK \
         -H 'Content-Type: application/json' \
         -d "{
           \"text\": \"$title\",
           \"attachments\": [{
             \"color\": \"danger\",
             \"fields\": [{
               \"title\": \"详细信息\",
               \"value\": \"$message\",
               \"short\": false
             }]
           }]
         }"
    
    # 发送邮件通知
    echo "$message" | mail -s "$title" $EMAIL_RECIPIENTS
    
    log_message "ALERT" "$title: $message"
}

# 检查服务状态
check_services() {
    local failed_services=()
    
    services=("nginx" "postgresql" "redis-server" "docker")
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            failed_services+=($service)
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        send_alert "服务状态异常" "以下服务未运行: ${failed_services[*]}" "HIGH"
        return 1
    else
        log_message "INFO" "所有关键服务运行正常"
        return 0
    fi
}

# 检查系统资源
check_system_resources() {
    local alerts=()
    
    # 检查CPU使用率
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    cpu_usage=${cpu_usage%.*}  # 去掉小数部分
    
    if [ "$cpu_usage" -gt 85 ]; then
        alerts+=("CPU使用率过高: ${cpu_usage}%")
    fi
    
    # 检查内存使用率
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    mem_usage=${mem_usage%.*}
    
    if [ "$mem_usage" -gt 90 ]; then
        alerts+=("内存使用率过高: ${mem_usage}%")
    fi
    
    # 检查磁盘使用率
    while read line; do
        usage=$(echo $line | awk '{print $5}' | sed 's/%//')
        filesystem=$(echo $line | awk '{print $6}')
        
        if [ "$usage" -gt 85 ]; then
            alerts+=("磁盘空间不足: $filesystem 使用率 ${usage}%")
        fi
    done < <(df -h | grep -vE '^Filesystem|tmpfs|cdrom')
    
    # 发送告警
    if [ ${#alerts[@]} -gt 0 ]; then
        alert_message=$(printf '%s\n' "${alerts[@]}")
        send_alert "系统资源告警" "$alert_message" "MEDIUM"
        return 1
    else
        log_message "INFO" "系统资源使用正常"
        return 0
    fi
}

# 检查网络连通性
check_network_connectivity() {
    local failed_hosts=()
    
    # 关键主机列表
    hosts=("192.168.1.1" "192.168.10.21" "192.168.10.22" "8.8.8.8")
    
    for host in "${hosts[@]}"; do
        if ! ping -c 3 -W 5 $host >/dev/null 2>&1; then
            failed_hosts+=($host)
        fi
    done
    
    if [ ${#failed_hosts[@]} -gt 0 ]; then
        send_alert "网络连通性异常" "无法连接到主机: ${failed_hosts[*]}" "HIGH"
        return 1
    else
        log_message "INFO" "网络连通性正常"
        return 0
    fi
}

# 检查Web应用健康状态
check_web_health() {
    local failed_checks=()
    
    # Web健康检查端点
    endpoints=(
        "https://app.company.local/health"
        "https://api.company.local/health"
        "https://admin.company.local/health"
    )
    
    for endpoint in "${endpoints[@]}"; do
        response=$(curl -s -w "%{http_code}" -o /dev/null --max-time 10 $endpoint)
        
        if [ "$response" != "200" ]; then
            failed_checks+=("$endpoint 返回状态码: $response")
        fi
    done
    
    if [ ${#failed_checks[@]} -gt 0 ]; then
        alert_message=$(printf '%s\n' "${failed_checks[@]}")
        send_alert "Web应用健康检查失败" "$alert_message" "HIGH"
        return 1
    else
        log_message "INFO" "Web应用健康检查通过"
        return 0
    fi
}

# 检查数据库状态
check_database_status() {
    local db_alerts=()
    
    # 检查PostgreSQL主库
    if ! sudo -u postgres psql -c "SELECT 1;" >/dev/null 2>&1; then
        db_alerts+=("PostgreSQL主库连接失败")
    fi
    
    # 检查PostgreSQL从库
    if ! sudo -u postgres psql -h 192.168.10.22 -c "SELECT 1;" >/dev/null 2>&1; then
        db_alerts+=("PostgreSQL从库连接失败")
    fi
    
    # 检查Redis
    if ! redis-cli -a "RedisPassword123!" ping >/dev/null 2>&1; then
        db_alerts+=("Redis连接失败")
    fi
    
    if [ ${#db_alerts[@]} -gt 0 ]; then
        alert_message=$(printf '%s\n' "${db_alerts[@]}")
        send_alert "数据库状态异常" "$alert_message" "HIGH"
        return 1
    else
        log_message "INFO" "数据库状态正常"
        return 0
    fi
}

# 生成监控报告
generate_monitoring_report() {
    local report_date=$(date '+%Y-%m-%d')
    local report_file="/var/log/daily-monitoring-report-$report_date.txt"
    
    cat > $report_file << EOF
=====================================
IT基础设施日常监控报告
日期: $report_date
=====================================

系统运行时间:
$(uptime)

系统负载:
$(cat /proc/loadavg)

内存使用情况:
$(free -h)

磁盘使用情况:
$(df -h)

网络接口状态:
$(ip addr show | grep -E "inet |state ")

服务运行状态:
$(systemctl is-active nginx postgresql redis-server docker)

最近错误日志 (最新10条):
$(tail -10 /var/log/syslog | grep -i error)

数据库连接数:
PostgreSQL: $(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity;")
Redis: $(redis-cli -a "RedisPassword123!" info clients | grep connected_clients)

备份状态:
$(ls -la /backup/ | tail -5)

=====================================
EOF
    
    log_message "INFO" "监控报告已生成: $report_file"
    
    # 发送报告邮件
    mail -s "IT基础设施日常监控报告 - $report_date" $EMAIL_RECIPIENTS < $report_file
}

# 主监控函数
main_monitoring() {
    log_message "INFO" "开始系统监控检查..."
    
    local check_results=0
    
    check_services || ((check_results++))
    check_system_resources || ((check_results++))
    check_network_connectivity || ((check_results++))
    check_web_health || ((check_results++))
    check_database_status || ((check_results++))
    
    if [ $check_results -eq 0 ]; then
        log_message "INFO" "所有监控检查通过"
    else
        log_message "WARNING" "发现 $check_results 个问题"
    fi
    
    # 生成日报告 (每天23:50执行)
    if [ "$(date '+%H:%M')" = "23:50" ]; then
        generate_monitoring_report
    fi
}

# 执行监控
main_monitoring
```

### 2.2 性能监控与优化

#### 性能基线建立
```python
#!/usr/bin/env python3
# 性能基线建立脚本

import psutil
import requests
import time
import json
import statistics
from datetime import datetime, timedelta
import mysql.connector
import psycopg2

class PerformanceBaseline:
    def __init__(self):
        self.metrics = {
            'system': {},
            'application': {},
            'database': {},
            'network': {}
        }
        
    def collect_system_metrics(self, duration_minutes=60):
        """收集系统性能指标"""
        
        print(f"开始收集系统指标，持续 {duration_minutes} 分钟...")
        
        cpu_samples = []
        memory_samples = []
        disk_samples = []
        
        samples = duration_minutes * 6  # 每10秒采样一次
        
        for i in range(samples):
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_samples.append(cpu_percent)
            
            # 内存使用率
            memory = psutil.virtual_memory()
            memory_samples.append(memory.percent)
            
            # 磁盘I/O
            disk_io = psutil.disk_io_counters()
            disk_samples.append({
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_time': disk_io.read_time,
                'write_time': disk_io.write_time
            })
            
            if i % 60 == 0:  # 每10分钟打印一次进度
                print(f"已完成 {i/samples*100:.1f}% 系统指标收集")
            
            time.sleep(10)
        
        # 计算统计信息
        self.metrics['system'] = {
            'cpu': {
                'mean': statistics.mean(cpu_samples),
                'median': statistics.median(cpu_samples),
                'max': max(cpu_samples),
                'min': min(cpu_samples),
                'stdev': statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0
            },
            'memory': {
                'mean': statistics.mean(memory_samples),
                'median': statistics.median(memory_samples),
                'max': max(memory_samples),
                'min': min(memory_samples),
                'stdev': statistics.stdev(memory_samples) if len(memory_samples) > 1 else 0
            },
            'disk_io': {
                'avg_read_bytes_per_sec': statistics.mean([s['read_bytes'] for s in disk_samples]),
                'avg_write_bytes_per_sec': statistics.mean([s['write_bytes'] for s in disk_samples]),
                'avg_read_time': statistics.mean([s['read_time'] for s in disk_samples]),
                'avg_write_time': statistics.mean([s['write_time'] for s in disk_samples])
            }
        }
        
        print("✓ 系统指标收集完成")
    
    def collect_application_metrics(self, duration_minutes=60):
        """收集应用性能指标"""
        
        print(f"开始收集应用指标，持续 {duration_minutes} 分钟...")
        
        response_times = []
        error_rates = []
        throughput_samples = []
        
        test_urls = [
            'https://app.company.local/api/health',
            'https://app.company.local/api/users',
            'https://app.company.local/api/dashboard'
        ]
        
        samples = duration_minutes * 6
        
        for i in range(samples):
            request_count = 0
            error_count = 0
            total_response_time = 0
            
            # 对每个URL发送请求
            for url in test_urls:
                try:
                    start_time = time.time()
                    response = requests.get(url, timeout=30)
                    end_time = time.time()
                    
                    response_time = (end_time - start_time) * 1000  # 转换为毫秒
                    response_times.append(response_time)
                    total_response_time += response_time
                    request_count += 1
                    
                    if response.status_code >= 400:
                        error_count += 1
                        
                except Exception as e:
                    error_count += 1
                    request_count += 1
            
            # 计算当前周期的错误率和吞吐量
            if request_count > 0:
                error_rate = (error_count / request_count) * 100
                error_rates.append(error_rate)
                
                throughput = request_count / 10  # 每秒请求数
                throughput_samples.append(throughput)
            
            if i % 60 == 0:
                print(f"已完成 {i/samples*100:.1f}% 应用指标收集")
            
            time.sleep(10)
        
        # 计算统计信息
        self.metrics['application'] = {
            'response_time': {
                'mean': statistics.mean(response_times),
                'median': statistics.median(response_times),
                'p95': sorted(response_times)[int(len(response_times) * 0.95)],
                'p99': sorted(response_times)[int(len(response_times) * 0.99)],
                'max': max(response_times),
                'min': min(response_times)
            },
            'error_rate': {
                'mean': statistics.mean(error_rates),
                'max': max(error_rates),
                'min': min(error_rates)
            },
            'throughput': {
                'mean': statistics.mean(throughput_samples),
                'max': max(throughput_samples),
                'min': min(throughput_samples)
            }
        }
        
        print("✓ 应用指标收集完成")
    
    def collect_database_metrics(self, duration_minutes=60):
        """收集数据库性能指标"""
        
        print(f"开始收集数据库指标，持续 {duration_minutes} 分钟...")
        
        pg_metrics = []
        redis_metrics = []
        
        samples = duration_minutes * 6
        
        for i in range(samples):
            try:
                # PostgreSQL指标
                pg_conn = psycopg2.connect(
                    host='192.168.10.21',
                    database='companydb',
                    user='postgres',
                    password='postgres_password'
                )
                pg_cursor = pg_conn.cursor()
                
                # 查询当前连接数
                pg_cursor.execute("SELECT count(*) FROM pg_stat_activity;")
                active_connections = pg_cursor.fetchone()[0]
                
                # 查询数据库大小
                pg_cursor.execute("SELECT pg_database_size('companydb');")
                db_size = pg_cursor.fetchone()[0]
                
                # 查询缓存命中率
                pg_cursor.execute("""
                    SELECT sum(blks_hit) * 100.0 / sum(blks_hit + blks_read) as cache_hit_ratio
                    FROM pg_stat_database;
                """)
                cache_hit_ratio = pg_cursor.fetchone()[0] or 0
                
                pg_metrics.append({
                    'active_connections': active_connections,
                    'db_size': db_size,
                    'cache_hit_ratio': float(cache_hit_ratio)
                })
                
                pg_conn.close()
                
                # Redis指标
                import redis
                redis_client = redis.Redis(
                    host='192.168.10.40',
                    port=6379,
                    password='RedisPassword123!',
                    decode_responses=True
                )
                
                redis_info = redis_client.info()
                redis_metrics.append({
                    'connected_clients': redis_info['connected_clients'],
                    'used_memory': redis_info['used_memory'],
                    'total_commands_processed': redis_info['total_commands_processed'],
                    'keyspace_hits': redis_info.get('keyspace_hits', 0),
                    'keyspace_misses': redis_info.get('keyspace_misses', 0)
                })
                
            except Exception as e:
                print(f"数据库指标收集错误: {e}")
            
            if i % 60 == 0:
                print(f"已完成 {i/samples*100:.1f}% 数据库指标收集")
            
            time.sleep(10)
        
        # 计算PostgreSQL统计信息
        if pg_metrics:
            self.metrics['database']['postgresql'] = {
                'avg_connections': statistics.mean([m['active_connections'] for m in pg_metrics]),
                'avg_cache_hit_ratio': statistics.mean([m['cache_hit_ratio'] for m in pg_metrics]),
                'db_size_gb': pg_metrics[-1]['db_size'] / (1024**3)
            }
        
        # 计算Redis统计信息
        if redis_metrics:
            hit_rates = []
            for m in redis_metrics:
                total = m['keyspace_hits'] + m['keyspace_misses']
                if total > 0:
                    hit_rate = (m['keyspace_hits'] / total) * 100
                    hit_rates.append(hit_rate)
            
            self.metrics['database']['redis'] = {
                'avg_connected_clients': statistics.mean([m['connected_clients'] for m in redis_metrics]),
                'avg_memory_usage_mb': statistics.mean([m['used_memory'] for m in redis_metrics]) / (1024**2),
                'avg_hit_rate': statistics.mean(hit_rates) if hit_rates else 0
            }
        
        print("✓ 数据库指标收集完成")
    
    def generate_baseline_report(self):
        """生成性能基线报告"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'performance_baseline_{timestamp}.json'
        
        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'collection_duration': '60 minutes',
            'metrics': self.metrics,
            'thresholds': {
                'system': {
                    'cpu_warning': self.metrics['system']['cpu']['mean'] + 2 * self.metrics['system']['cpu']['stdev'],
                    'cpu_critical': self.metrics['system']['cpu']['mean'] + 3 * self.metrics['system']['cpu']['stdev'],
                    'memory_warning': min(85, self.metrics['system']['memory']['mean'] + 10),
                    'memory_critical': min(95, self.metrics['system']['memory']['mean'] + 20)
                },
                'application': {
                    'response_time_warning': self.metrics['application']['response_time']['p95'] * 1.5,
                    'response_time_critical': self.metrics['application']['response_time']['p95'] * 2,
                    'error_rate_warning': max(5, self.metrics['application']['error_rate']['mean'] * 2),
                    'error_rate_critical': max(10, self.metrics['application']['error_rate']['mean'] * 3)
                }
            }
        }
        
        # 保存基线数据
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=2, ensure_ascii=False)
        
        # 生成可读报告
        readable_report = f'performance_baseline_report_{timestamp}.txt'
        with open(readable_report, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("IT基础设施性能基线报告\n")
            f.write("="*60 + "\n\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"数据收集周期: 60分钟\n\n")
            
            # 系统指标
            f.write("系统性能指标:\n")
            f.write("-"*30 + "\n")
            f.write(f"CPU使用率 - 平均: {self.metrics['system']['cpu']['mean']:.2f}%, ")
            f.write(f"最大: {self.metrics['system']['cpu']['max']:.2f}%, ")
            f.write(f"标准差: {self.metrics['system']['cpu']['stdev']:.2f}%\n")
            f.write(f"内存使用率 - 平均: {self.metrics['system']['memory']['mean']:.2f}%, ")
            f.write(f"最大: {self.metrics['system']['memory']['max']:.2f}%\n\n")
            
            # 应用指标
            f.write("应用性能指标:\n")
            f.write("-"*30 + "\n")
            f.write(f"响应时间 - 平均: {self.metrics['application']['response_time']['mean']:.2f}ms, ")
            f.write(f"P95: {self.metrics['application']['response_time']['p95']:.2f}ms, ")
            f.write(f"P99: {self.metrics['application']['response_time']['p99']:.2f}ms\n")
            f.write(f"错误率 - 平均: {self.metrics['application']['error_rate']['mean']:.4f}%\n")
            f.write(f"吞吐量 - 平均: {self.metrics['application']['throughput']['mean']:.2f} req/s\n\n")
            
            # 数据库指标
            if 'postgresql' in self.metrics['database']:
                f.write("PostgreSQL指标:\n")
                f.write("-"*30 + "\n")
                f.write(f"平均连接数: {self.metrics['database']['postgresql']['avg_connections']:.0f}\n")
                f.write(f"缓存命中率: {self.metrics['database']['postgresql']['avg_cache_hit_ratio']:.2f}%\n")
                f.write(f"数据库大小: {self.metrics['database']['postgresql']['db_size_gb']:.2f} GB\n\n")
            
            if 'redis' in self.metrics['database']:
                f.write("Redis指标:\n")
                f.write("-"*30 + "\n")
                f.write(f"平均连接数: {self.metrics['database']['redis']['avg_connected_clients']:.0f}\n")
                f.write(f"内存使用: {self.metrics['database']['redis']['avg_memory_usage_mb']:.2f} MB\n")
                f.write(f"缓存命中率: {self.metrics['database']['redis']['avg_hit_rate']:.2f}%\n\n")
            
            # 告警阈值
            f.write("建议告警阈值:\n")
            f.write("-"*30 + "\n")
            f.write(f"CPU使用率告警: {baseline_data['thresholds']['system']['cpu_warning']:.1f}%\n")
            f.write(f"CPU使用率严重: {baseline_data['thresholds']['system']['cpu_critical']:.1f}%\n")
            f.write(f"内存使用率告警: {baseline_data['thresholds']['system']['memory_warning']:.1f}%\n")
            f.write(f"响应时间告警: {baseline_data['thresholds']['application']['response_time_warning']:.0f}ms\n")
            f.write(f"错误率告警: {baseline_data['thresholds']['application']['error_rate_warning']:.2f}%\n")
        
        print(f"✓ 性能基线报告已生成:")
        print(f"  - JSON数据: {report_file}")
        print(f"  - 可读报告: {readable_report}")
        
        return baseline_data

    def run_baseline_collection(self):
        """执行完整的基线收集"""
        
        print("开始IT基础设施性能基线建立...")
        print("预计总耗时: 3小时 (每类指标1小时)")
        
        # 并行收集不同类型的指标可能会互相影响，所以串行执行
        self.collect_system_metrics(60)
        self.collect_application_metrics(60)
        self.collect_database_metrics(60)
        
        baseline_data = self.generate_baseline_report()
        
        print("✓ 性能基线建立完成！")
        return baseline_data

if __name__ == "__main__":
    baseline = PerformanceBaseline()
    baseline.run_baseline_collection()
```

## 3. 问题处理管理

### 3.1 故障响应流程

#### 故障分级与响应
```yaml
故障分级标准:
  P0级故障 (紧急):
    定义: 核心业务系统完全不可用
    影响: 超过50%用户无法正常工作
    响应时间: 15分钟内
    解决时间: 4小时内
    通知对象: 
      - 技术总监
      - 运维主管
      - 值班工程师
      - 业务部门负责人
    
  P1级故障 (高):
    定义: 核心功能受到严重影响
    影响: 20-50%用户工作受影响
    响应时间: 30分钟内
    解决时间: 8小时内
    通知对象:
      - 运维主管
      - 值班工程师
      - 相关业务负责人
    
  P2级故障 (中):
    定义: 部分功能异常或性能下降
    影响: 少于20%用户工作受影响
    响应时间: 2小时内
    解决时间: 24小时内
    通知对象:
      - 值班工程师
      - 相关技术人员
    
  P3级故障 (低):
    定义: 轻微问题或功能缺陷
    影响: 不影响正常业务
    响应时间: 4小时内
    解决时间: 72小时内
    通知对象:
      - 相关技术人员

故障处理流程:
  1. 故障发现:
     - 监控系统自动发现
     - 用户报告
     - 巡检发现
     
  2. 故障确认:
     - 初步诊断
     - 影响范围评估
     - 故障分级
     
  3. 应急响应:
     - 通知相关人员
     - 启动应急预案
     - 临时解决方案
     
  4. 根因分析:
     - 详细调查
     - 确定根本原因
     - 制定永久解决方案
     
  5. 问题修复:
     - 实施修复方案
     - 测试验证
     - 恢复正常服务
     
  6. 总结改进:
     - 故障报告编写
     - 流程改进建议
     - 预防措施制定
```

#### 自动化故障处理脚本
```python
#!/usr/bin/env python3
# 自动化故障处理系统

import json
import time
import requests
import subprocess
import logging
from datetime import datetime
from enum import Enum

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/incident-response.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    P0 = "P0-紧急"
    P1 = "P1-高"
    P2 = "P2-中" 
    P3 = "P3-低"

class IncidentStatus(Enum):
    NEW = "新建"
    ACKNOWLEDGED = "已确认"
    IN_PROGRESS = "处理中"
    RESOLVED = "已解决"
    CLOSED = "已关闭"

class AutoIncidentResponse:
    def __init__(self):
        self.slack_webhook = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
        self.email_api = "https://api.company.local/send-email"
        self.api_token = "your_api_token"
        
    def create_incident(self, alert_data):
        """创建故障工单"""
        
        incident = {
            'id': f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'title': alert_data.get('title', '未知故障'),
            'description': alert_data.get('description', ''),
            'severity': self.determine_severity(alert_data),
            'status': IncidentStatus.NEW,
            'created_at': datetime.now().isoformat(),
            'assigned_to': self.get_on_call_engineer(),
            'affected_services': alert_data.get('services', []),
            'metrics': alert_data.get('metrics', {})
        }
        
        logger.info(f"创建故障工单: {incident['id']} - {incident['title']}")
        
        # 保存到数据库/文件
        self.save_incident(incident)
        
        # 发送通知
        self.notify_incident_created(incident)
        
        # 执行自动化响应
        self.execute_auto_response(incident)
        
        return incident
    
    def determine_severity(self, alert_data):
        """根据告警数据确定故障级别"""
        
        alert_type = alert_data.get('type', '')
        metrics = alert_data.get('metrics', {})
        
        # P0级故障条件
        if (alert_type == 'service_down' and 
            'web-server' in alert_data.get('services', [])):
            return IncidentSeverity.P0
        
        if (alert_type == 'database_down' or
            metrics.get('error_rate', 0) > 50):
            return IncidentSeverity.P0
        
        # P1级故障条件  
        if (metrics.get('response_time', 0) > 10000 or
            metrics.get('error_rate', 0) > 20):
            return IncidentSeverity.P1
        
        if alert_type == 'high_cpu' and metrics.get('cpu_usage', 0) > 95:
            return IncidentSeverity.P1
        
        # P2级故障条件
        if (metrics.get('response_time', 0) > 5000 or
            metrics.get('error_rate', 0) > 5):
            return IncidentSeverity.P2
        
        # 默认P3级
        return IncidentSeverity.P3
    
    def get_on_call_engineer(self):
        """获取当前值班工程师"""
        
        # 这里可以集成值班轮替系统
        # 简化实现，返回固定值班表
        hour = datetime.now().hour
        
        if 9 <= hour < 18:  # 工作时间
            return "day-shift@company.local"
        else:  # 非工作时间
            return "night-shift@company.local"
    
    def execute_auto_response(self, incident):
        """执行自动化响应措施"""
        
        logger.info(f"执行自动化响应: {incident['id']}")
        
        if incident['severity'] == IncidentSeverity.P0:
            self.handle_p0_incident(incident)
        elif incident['severity'] == IncidentSeverity.P1:
            self.handle_p1_incident(incident)
        elif incident['severity'] == IncidentSeverity.P2:
            self.handle_p2_incident(incident)
        else:
            self.handle_p3_incident(incident)
    
    def handle_p0_incident(self, incident):
        """处理P0级故障"""
        
        logger.critical(f"处理P0级故障: {incident['title']}")
        
        # 1. 立即通知关键人员
        self.send_critical_notification(incident)
        
        # 2. 启动应急响应
        if 'web-server' in incident['affected_services']:
            self.restart_web_services()
            
        if 'database' in incident['affected_services']:
            self.check_database_status()
            
        # 3. 启用备用系统
        if 'web-server' in incident['affected_services']:
            self.activate_backup_servers()
        
        # 4. 创建作战室
        self.create_war_room(incident)
    
    def handle_p1_incident(self, incident):
        """处理P1级故障"""
        
        logger.error(f"处理P1级故障: {incident['title']}")
        
        # 1. 通知相关人员
        self.send_high_priority_notification(incident)
        
        # 2. 执行基础恢复操作
        if 'high_cpu' in incident['title'].lower():
            self.investigate_high_cpu()
            
        if 'slow_response' in incident['title'].lower():
            self.optimize_performance()
    
    def handle_p2_incident(self, incident):
        """处理P2级故障"""
        
        logger.warning(f"处理P2级故障: {incident['title']}")
        
        # 收集详细信息用于后续分析
        self.collect_diagnostic_data(incident)
        
        # 通知值班工程师
        self.send_standard_notification(incident)
    
    def handle_p3_incident(self, incident):
        """处理P3级故障"""
        
        logger.info(f"处理P3级故障: {incident['title']}")
        
        # 仅记录，工作时间处理
        self.log_for_business_hours(incident)
    
    def restart_web_services(self):
        """重启Web服务"""
        
        try:
            logger.info("尝试重启Web服务...")
            
            # 重启Nginx
            subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], 
                         check=True, timeout=30)
            
            # 重启应用服务
            subprocess.run(['sudo', 'systemctl', 'restart', 'webapp'], 
                         check=True, timeout=60)
            
            # 验证服务状态
            time.sleep(10)
            response = requests.get('https://app.company.local/health', timeout=10)
            
            if response.status_code == 200:
                logger.info("✓ Web服务重启成功")
                return True
            else:
                logger.error(f"✗ Web服务重启后健康检查失败: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Web服务重启失败: {str(e)}")
            return False
    
    def check_database_status(self):
        """检查数据库状态"""
        
        try:
            import psycopg2
            
            # 检查主数据库
            conn = psycopg2.connect(
                host='192.168.10.21',
                database='companydb',
                user='postgres',
                password='postgres_password',
                connect_timeout=10
            )
            
            cursor = conn.cursor()
            cursor.execute('SELECT 1;')
            result = cursor.fetchone()
            conn.close()
            
            if result:
                logger.info("✓ 主数据库连接正常")
                return True
            else:
                logger.error("✗ 主数据库查询异常")
                return False
                
        except Exception as e:
            logger.error(f"数据库连接失败: {str(e)}")
            
            # 尝试切换到从数据库
            self.failover_to_slave_db()
            return False
    
    def activate_backup_servers(self):
        """激活备用服务器"""
        
        try:
            # 通过负载均衡器API激活备用服务器
            response = requests.post(
                'https://lb.company.local/api/activate-backup',
                headers={'Authorization': f'Bearer {self.api_token}'},
                json={'backup_servers': ['192.168.10.50', '192.168.10.51']},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("✓ 备用服务器已激活")
                return True
            else:
                logger.error(f"激活备用服务器失败: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"激活备用服务器异常: {str(e)}")
            return False
    
    def send_critical_notification(self, incident):
        """发送紧急通知"""
        
        message = f"""
🚨 P0级故障告警 🚨

故障ID: {incident['id']}
故障标题: {incident['title']}
影响服务: {', '.join(incident['affected_services'])}
创建时间: {incident['created_at']}
值班工程师: {incident['assigned_to']}

请立即处理！
        """
        
        # 发送Slack通知
        self.send_slack_notification(message, urgent=True)
        
        # 发送邮件通知
        recipients = [
            'cto@company.local',
            'ops-manager@company.local',
            incident['assigned_to']
        ]
        self.send_email_notification(recipients, f"P0级故障: {incident['title']}", message)
        
        # 发送短信通知 (如果配置)
        self.send_sms_notification(incident)
    
    def send_slack_notification(self, message, urgent=False):
        """发送Slack通知"""
        
        color = "danger" if urgent else "warning"
        
        payload = {
            "text": "故障告警",
            "attachments": [{
                "color": color,
                "text": message,
                "fields": [{
                    "title": "处理要求",
                    "value": "请立即响应" if urgent else "请及时处理",
                    "short": True
                }]
            }]
        }
        
        try:
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("✓ Slack通知发送成功")
            else:
                logger.error(f"Slack通知发送失败: {response.text}")
        except Exception as e:
            logger.error(f"Slack通知发送异常: {str(e)}")
    
    def collect_diagnostic_data(self, incident):
        """收集诊断数据"""
        
        logger.info(f"收集故障诊断数据: {incident['id']}")
        
        diagnostic_data = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {},
            'application_logs': {},
            'performance_metrics': {}
        }
        
        try:
            # 收集系统信息
            diagnostic_data['system_info'] = {
                'uptime': subprocess.getoutput('uptime'),
                'memory': subprocess.getoutput('free -h'),
                'disk': subprocess.getoutput('df -h'),
                'processes': subprocess.getoutput('ps aux --sort=-%cpu | head -10')
            }
            
            # 收集应用日志
            diagnostic_data['application_logs'] = {
                'nginx_error': subprocess.getoutput('tail -50 /var/log/nginx/error.log'),
                'application': subprocess.getoutput('tail -50 /var/log/webapp/app.log'),
                'system': subprocess.getoutput('tail -50 /var/log/syslog')
            }
            
            # 保存诊断数据
            filename = f"/var/log/diagnostics/incident_{incident['id']}.json"
            with open(filename, 'w') as f:
                json.dump(diagnostic_data, f, indent=2)
            
            logger.info(f"✓ 诊断数据已保存: {filename}")
            
        except Exception as e:
            logger.error(f"收集诊断数据失败: {str(e)}")
    
    def save_incident(self, incident):
        """保存故障工单"""
        
        # 简化实现，保存到JSON文件
        # 实际应用中应该保存到数据库
        filename = f"/var/log/incidents/{incident['id']}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(incident, f, indent=2, default=str)
            logger.info(f"故障工单已保存: {filename}")
        except Exception as e:
            logger.error(f"保存故障工单失败: {str(e)}")

# 使用示例
def handle_alert(alert_data):
    """处理告警数据"""
    
    response_system = AutoIncidentResponse()
    incident = response_system.create_incident(alert_data)
    
    return incident

# 示例告警数据
if __name__ == "__main__":
    sample_alert = {
        'type': 'service_down',
        'title': 'Web服务器宕机',
        'description': '主Web服务器无响应，用户无法访问应用',
        'services': ['web-server'],
        'metrics': {
            'error_rate': 100,
            'response_time': 0
        }
    }
    
    incident = handle_alert(sample_alert)
    print(f"故障处理完成: {incident['id']}")
```

---
*文档版本：v1.0*  
*创建日期：2025年8月*  
*负责人：运维支持团队*