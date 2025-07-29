# gunicorn.conf.py - Gunicorn配置
import os
import multiprocessing

# 服务器配置
bind = f"0.0.0.0:{os.getenv('PORT', 5000)}"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 30
keepalive = 2

# 日志配置
accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# 安全配置
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# 预加载应用
preload_app = True

# 进程管理
daemon = False
pidfile = "gunicorn.pid"
user = None
group = None

# 重启配置
max_requests = 1000
max_requests_jitter = 100
preload_app = True
