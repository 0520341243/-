# app.py - 主应用程序
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import logging
from datetime import datetime, timedelta
import json
import pandas as pd
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit
from functools import wraps
import hashlib
from cryptography.fernet import Fernet
import base64

# 应用配置
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///dingtalk_reminder.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB文件上传限制
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()

# 初始化应用
app = Flask(__name__)
app.config.from_object(Config)

# 初始化扩展
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# 加密工具
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # admin, user
    max_groups = db.Column(db.Integer, default=10)
    max_running_groups = db.Column(db.Integer, default=3)
    max_daily_reminders = db.Column(db.Integer, default=200)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    groups = db.relationship('Group', backref='owner', lazy=True, cascade='all, delete-orphan')

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    webhook_url_encrypted = db.Column(db.Text, nullable=False)  # 加密存储
    status = db.Column(db.String(20), default='draft')  # running, paused, stopped, draft
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 星期工作表映射
    monday_sheet = db.Column(db.String(50), default='子表1')
    tuesday_sheet = db.Column(db.String(50), default='子表1')
    wednesday_sheet = db.Column(db.String(50), default='子表1')
    thursday_sheet = db.Column(db.String(50), default='子表1')
    friday_sheet = db.Column(db.String(50), default='子表2')
    saturday_sheet = db.Column(db.String(50), default='子表5')
    sunday_sheet = db.Column(db.String(50), default='子表5')
    
    # 统计信息
    reminders_today = db.Column(db.Integer, default=0)
    total_reminders_sent = db.Column(db.Integer, default=0)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    
    schedules = db.relationship('ReminderSchedule', backref='group', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('ActivityLog', backref='group', lazy=True, cascade='all, delete-orphan')

class ReminderSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    schedule_date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, sent, failed
    is_temp = db.Column(db.Boolean, default=False)  # 是否为临时计划
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(10))  # regular, temp
    start_mode = db.Column(db.String(20))  # immediate, scheduled
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 工具函数
def encrypt_webhook(webhook_url):
    """加密Webhook地址"""
    return cipher_suite.encrypt(webhook_url.encode()).decode()

def decrypt_webhook(encrypted_webhook):
    """解密Webhook地址"""
    try:
        return cipher_suite.decrypt(encrypted_webhook.encode()).decode()
    except:
        return None

def log_activity(user_id, action, description=None, group_id=None):
    """记录用户活动"""
    try:
        log = ActivityLog(
            user_id=user_id,
            group_id=group_id,
            action=action,
            description=description,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

def check_user_quota(user_id, quota_type):
    """检查用户配额"""
    user = User.query.get(user_id)
    if not user:
        return False
    
    if quota_type == 'groups':
        current_count = Group.query.filter_by(owner_id=user_id).count()
        return current_count < user.max_groups
    
    elif quota_type == 'running_groups':
        current_count = Group.query.filter_by(owner_id=user_id, status='running').count()
        return current_count < user.max_running_groups
    
    elif quota_type == 'daily_reminders':
        today = datetime.utcnow().date()
        current_count = db.session.query(db.func.sum(Group.reminders_today)).filter(
            Group.owner_id == user_id
        ).scalar() or 0
        return current_count < user.max_daily_reminders
    
    return False

def allowed_file(filename):
    """检查文件类型"""
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_excel_file(file_path, group, is_temp=False, start_mode='scheduled'):
    """处理Excel文件并生成提醒计划"""
    try:
        # 读取Excel文件
        excel_data = pd.read_excel(file_path, sheet_name=None)
        
        # 获取当前日期和星期
        today = datetime.now().date()
        weekday = today.weekday()  # 0=Monday, 6=Sunday
        
        # 获取今天对应的工作表名称
        sheet_mapping = {
            0: group.monday_sheet,
            1: group.tuesday_sheet,
            2: group.wednesday_sheet,
            3: group.thursday_sheet,
            4: group.friday_sheet,
            5: group.saturday_sheet,
            6: group.sunday_sheet
        }
        
        target_sheet = sheet_mapping.get(weekday, '子表1')
        
        if target_sheet not in excel_data:
            logger.warning(f"Sheet '{target_sheet}' not found in Excel file")
            return False, f"工作表 '{target_sheet}' 未找到"
        
        # 获取工作表数据
        df = excel_data[target_sheet]
        
        # 查找时间和消息列
        time_col = None
        message_col = None
        
        for col in df.columns:
            col_lower = str(col).lower()
            if '时间' in col_lower or 'time' in col_lower:
                time_col = col
            elif '消息' in col_lower or '内容' in col_lower or 'message' in col_lower:
                message_col = col
        
        if not time_col or not message_col:
            return False, "未找到时间列或消息列"
        
        # 清除旧的提醒计划（如果不是临时文件）
        if not is_temp:
            ReminderSchedule.query.filter_by(
                group_id=group.id,
                schedule_date=today,
                is_temp=False
            ).delete()
        
        # 解析并创建提醒计划
        schedules_created = 0
        current_time = datetime.now().time()
        
        for index, row in df.iterrows():
            try:
                time_str = str(row[time_col]).strip()
                message = str(row[message_col]).strip()
                
                if pd.isna(row[time_col]) or pd.isna(row[message_col]):
                    continue
                
                # 解析时间
                if ':' in time_str:
                    time_parts = time_str.split(':')
                    if len(time_parts) >= 2:
                        hour = int(time_parts[0])
                        minute = int(time_parts[1])
                        second = int(time_parts[2]) if len(time_parts) > 2 else 0
                        
                        schedule_time = datetime.time(hour, minute, second)
                        
                        # 智能时间过滤：如果是立即启动且时间已过，标记为已发送
                        status = 'pending'
                        if start_mode == 'immediate' and schedule_time <= current_time:
                            status = 'sent'
                        
                        schedule = ReminderSchedule(
                            group_id=group.id,
                            schedule_date=today,
                            time=schedule_time,
                            message=message,
                            status=status,
                            is_temp=is_temp
                        )
                        
                        db.session.add(schedule)
                        schedules_created += 1
                        
            except Exception as e:
                logger.error(f"Error processing row {index}: {e}")
                continue
        
        db.session.commit()
        
        # 记录文件处理
        uploaded_file = UploadedFile.query.filter_by(file_path=file_path).first()
        if uploaded_file:
            uploaded_file.processed_at = datetime.utcnow()
            db.session.commit()
        
        return True, f"成功创建 {schedules_created} 个提醒计划"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {e}")
        return False, str(e)

def send_dingtalk_message(webhook_url, message):
    """发送钉钉消息"""
    try:
        payload = {
            "msgtype": "text",
            "text": {
                "content": message
            }
        }
        
        response = requests.post(
            webhook_url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('errcode') == 0:
                return True, "发送成功"
            else:
                return False, result.get('errmsg', '发送失败')
        else:
            return False, f"HTTP错误: {response.status_code}"
            
    except Exception as e:
        logger.error(f"Error sending DingTalk message: {e}")
        return False, str(e)

# 权限装饰器
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated_function

def group_owner_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # 管理员可以访问所有群组
        if user and user.role == 'admin':
            return f(*args, **kwargs)
        
        # 普通用户只能访问自己的群组
        group_id = kwargs.get('group_id') or request.json.get('group_id')
        if group_id:
            group = Group.query.get(group_id)
            if not group or group.owner_id != current_user_id:
                return jsonify({'error': '无权限访问此群组'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# API路由
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """用户注册"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'error': '缺少必要参数'}), 400
    
    # 检查用户是否已存在
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': '用户名已存在'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': '邮箱已存在'}), 400
    
    # 创建新用户
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        role=data.get('role', 'user')
    )
    
    db.session.add(user)
    db.session.commit()
    
    log_activity(user.id, 'register', f"用户注册: {user.username}")
    
    return jsonify({
        'message': '注册成功',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """用户登录"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': '缺少用户名或密码'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': '用户名或密码错误'}), 401
    
    if not user.is_active:
        return jsonify({'error': '账户已被禁用'}), 401
    
    access_token = create_access_token(identity=user.id)
    
    log_activity(user.id, 'login', "用户登录")
    
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'max_groups': user.max_groups,
            'max_running_groups': user.max_running_groups,
            'max_daily_reminders': user.max_daily_reminders
        }
    })

@app.route('/api/groups', methods=['GET'])
@jwt_required()
def get_groups():
    """获取用户群组列表"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.role == 'admin':
        groups = Group.query.all()
    else:
        groups = Group.query.filter_by(owner_id=current_user_id).all()
    
    result = []
    for group in groups:
        result.append({
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'status': group.status,
            'owner_id': group.owner_id,
            'reminders_today': group.reminders_today,
            'total_reminders_sent': group.total_reminders_sent,
            'last_active': group.last_active.isoformat() if group.last_active else None,
            'created_at': group.created_at.isoformat(),
            'week_mapping': {
                'monday': group.monday_sheet,
                'tuesday': group.tuesday_sheet,
                'wednesday': group.wednesday_sheet,
                'thursday': group.thursday_sheet,
                'friday': group.friday_sheet,
                'saturday': group.saturday_sheet,
                'sunday': group.sunday_sheet
            }
        })
    
    return jsonify({'groups': result})

@app.route('/api/groups', methods=['POST'])
@jwt_required()
def create_group():
    """创建新群组"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('webhook_url'):
        return jsonify({'error': '缺少必要参数'}), 400
    
    # 检查配额
    if not check_user_quota(current_user_id, 'groups'):
        return jsonify({'error': '群组数量已达上限'}), 400
    
    # 加密Webhook地址
    encrypted_webhook = encrypt_webhook(data['webhook_url'])
    
    group = Group(
        name=data['name'],
        description=data.get('description', ''),
        webhook_url_encrypted=encrypted_webhook,
        status=data.get('status', 'draft'),
        owner_id=current_user_id,
        monday_sheet=data.get('monday_sheet', '子表1'),
        tuesday_sheet=data.get('tuesday_sheet', '子表1'),
        wednesday_sheet=data.get('wednesday_sheet', '子表1'),
        thursday_sheet=data.get('thursday_sheet', '子表1'),
        friday_sheet=data.get('friday_sheet', '子表2'),
        saturday_sheet=data.get('saturday_sheet', '子表5'),
        sunday_sheet=data.get('sunday_sheet', '子表5')
    )
    
    db.session.add(group)
    db.session.commit()
    
    log_activity(current_user_id, 'create_group', f"创建群组: {group.name}", group.id)
    
    return jsonify({
        'message': '群组创建成功',
        'group': {
            'id': group.id,
            'name': group.name,
            'status': group.status
        }
    }), 201

# 更多API路由将在下一个文件中继续...

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # 创建默认管理员用户
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                max_groups=100,
                max_running_groups=50,
                max_daily_reminders=1000
            )
            db.session.add(admin)
            db.session.commit()
            print("默认管理员用户已创建: admin/admin123")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
