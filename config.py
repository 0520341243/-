# config.py - 配置文件
import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    """基础配置"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)
    
    # 数据库配置
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    
    # 文件上传配置
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    
    # 加密配置
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
    
    # Redis配置（可选，用于缓存和任务队列）
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # 日志配置
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'app.log'
    
    # 系统限制
    DEFAULT_MAX_GROUPS = 10
    DEFAULT_MAX_RUNNING_GROUPS = 3
    DEFAULT_MAX_DAILY_REMINDERS = 200
    
    # 钉钉API配置
    DINGTALK_TIMEOUT = 10  # 秒
    DINGTALK_RETRY_TIMES = 3
    
    # 调度器配置
    SCHEDULER_TIMEZONE = 'Asia/Shanghai'
    SCHEDULER_JOBSTORES = {
        'default': {'type': 'memory'}
    }
    
    @staticmethod
    def init_app(app):
        """初始化应用配置"""
        # 确保上传目录存在
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # 创建日志目录
        log_dir = os.path.dirname(app.config['LOG_FILE'])
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.getcwd(), 'dingtalk_reminder_dev.db')
    
    # 开发环境宽松的限制
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)

class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    
    # 测试环境使用固定的密钥
    SECRET_KEY = 'test-secret-key'
    JWT_SECRET_KEY = 'test-jwt-secret'

class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    
    # 生产环境数据库
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost/dingtalk_reminder'
    
    # 生产环境必须设置的环境变量
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # 检查必要的环境变量
        required_vars = [
            'SECRET_KEY',
            'JWT_SECRET_KEY',
            'DATABASE_URL',
            'ENCRYPTION_KEY'
        ]
        
        missing_vars = [var for var in required_vars if not os.environ.get(var)]
        if missing_vars:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        # 生产环境日志配置
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            if not os.path.exists('logs'):
                os.mkdir('logs')
            
            file_handler = RotatingFileHandler(
                'logs/dingtalk_reminder.log',
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('DingTalk Reminder System startup')

class CloudflareConfig(Config):
    """Cloudflare Workers部署配置"""
    DEBUG = False
    
    # Cloudflare Workers环境变量
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Cloudflare Workers特殊配置
    PREFERRED_URL_SCHEME = 'https'
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Cloudflare Workers特殊处理
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# 配置字典
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'cloudflare': CloudflareConfig,
    'default': DevelopmentConfig
}

# 环境变量示例文件内容
ENV_EXAMPLE = """
# 基础配置
SECRET_KEY=your-super-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
ENCRYPTION_KEY=your-encryption-key-here

# 数据库配置
DATABASE_URL=sqlite:///dingtalk_reminder.db
# 或者使用PostgreSQL: postgresql://username:password@localhost/dingtalk_reminder

# Redis配置（可选）
REDIS_URL=redis://localhost:6379/0

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=logs/app.log

# Flask环境
FLASK_ENV=development
FLASK_APP=app.py

# 部署相关
PORT=5000
HOST=0.0.0.0
"""
