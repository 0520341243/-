# health_check.py - 健康检查脚本
#!/usr/bin/env python3
import requests
import sys
import json

def check_health():
    """检查应用健康状态"""
    try:
        # 检查API健康状态
        response = requests.get('http://localhost:5000/api/health', timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ API服务正常: {data.get('status', 'unknown')}")
        else:
            print(f"✗ API服务异常: HTTP {response.status_code}")
            return False
            
        # 检查数据库连接
        response = requests.get('http://localhost:5000/api/system/stats', timeout=10)
        
        if response.status_code == 200:
            print("✓ 数据库连接正常")
        else:
            print("✗ 数据库连接异常")
            return False
            
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"✗ 健康检查失败: {e}")
        return False

if __name__ == '__main__':
    if check_health():
        print("所有服务运行正常")
        sys.exit(0)
    else:
        print("服务存在问题")
        sys.exit(1)

# 添加到app.py中的健康检查端点
@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查端点"""
    try:
        # 检查数据库连接
        db.session.execute('SELECT 1')
        
        # 检查调度器状态
        scheduler_running = scheduler.running if 'scheduler' in globals() else False
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'scheduler': 'running' if scheduler_running else 'stopped',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
