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

# api_routes.py - API路由扩展文件
# 继续添加到 app.py 文件中

@app.route('/api/groups/<int:group_id>', methods=['GET'])
@jwt_required()
@group_owner_required
def get_group(group_id):
    """获取群组详情"""
    group = Group.query.get_or_404(group_id)
    
    # 获取今日提醒计划
    today = datetime.utcnow().date()
    schedules = ReminderSchedule.query.filter_by(
        group_id=group_id,
        schedule_date=today
    ).order_by(ReminderSchedule.time).all()
    
    schedule_list = []
    for schedule in schedules:
        schedule_list.append({
            'id': schedule.id,
            'time': schedule.time.strftime('%H:%M:%S'),
            'message': schedule.message,
            'status': schedule.status,
            'is_temp': schedule.is_temp,
            'sent_at': schedule.sent_at.isoformat() if schedule.sent_at else None
        })
    
    return jsonify({
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'status': group.status,
        'webhook_url': '***已加密***',  # 不返回真实Webhook地址
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
        },
        'schedules': schedule_list
    })

@app.route('/api/groups/<int:group_id>', methods=['PUT'])
@jwt_required()
@group_owner_required
def update_group(group_id):
    """更新群组信息"""
    current_user_id = get_jwt_identity()
    group = Group.query.get_or_404(group_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': '缺少更新数据'}), 400
    
    # 更新基本信息
    if 'name' in data:
        group.name = data['name']
    if 'description' in data:
        group.description = data['description']
    if 'webhook_url' in data:
        group.webhook_url_encrypted = encrypt_webhook(data['webhook_url'])
    
    # 更新星期映射
    week_fields = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    for field in week_fields:
        if f'{field}_sheet' in data:
            setattr(group, f'{field}_sheet', data[f'{field}_sheet'])
    
    group.updated_at = datetime.utcnow()
    db.session.commit()
    
    log_activity(current_user_id, 'update_group', f"更新群组: {group.name}", group.id)
    
    return jsonify({'message': '群组更新成功'})

@app.route('/api/groups/<int:group_id>/status', methods=['PUT'])
@jwt_required()
@group_owner_required
def update_group_status(group_id):
    """更新群组状态"""
    current_user_id = get_jwt_identity()
    group = Group.query.get_or_404(group_id)
    data = request.get_json()
    
    if not data or 'status' not in data:
        return jsonify({'error': '缺少状态参数'}), 400
    
    new_status = data['status']
    if new_status not in ['running', 'paused', 'stopped', 'draft']:
        return jsonify({'error': '无效的状态值'}), 400
    
    # 检查运行群组配额
    if new_status == 'running' and not check_user_quota(current_user_id, 'running_groups'):
        return jsonify({'error': '运行群组数量已达上限'}), 400
    
    old_status = group.status
    group.status = new_status
    group.last_active = datetime.utcnow()
    group.updated_at = datetime.utcnow()
    
    db.session.commit()
    
    log_activity(current_user_id, 'change_status', 
                f"群组状态从 {old_status} 更改为 {new_status}", group.id)
    
    return jsonify({'message': f'群组状态已更新为 {new_status}'})

@app.route('/api/groups/<int:group_id>/test', methods=['POST'])
@jwt_required()
@group_owner_required
def test_webhook(group_id):
    """测试Webhook发送"""
    group = Group.query.get_or_404(group_id)
    
    webhook_url = decrypt_webhook(group.webhook_url_encrypted)
    if not webhook_url:
        return jsonify({'error': 'Webhook地址解密失败'}), 500
    
    test_message = f"测试消息 - 来自群组 {group.name}\n发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    success, message = send_dingtalk_message(webhook_url, test_message)
    
    if success:
        group.last_active = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': '测试消息发送成功'})
    else:
        return jsonify({'error': f'测试消息发送失败: {message}'}), 500

@app.route('/api/groups/<int:group_id>/upload', methods=['POST'])
@jwt_required()
@group_owner_required
def upload_file(group_id):
    """上传Excel文件"""
    current_user_id = get_jwt_identity()
    group = Group.query.get_or_404(group_id)
    
    if 'file' not in request.files:
        return jsonify({'error': '没有文件被上传'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': '不支持的文件类型，只支持.xlsx和.xls文件'}), 400
    
    file_type = request.form.get('file_type', 'regular')  # regular, temp
    start_mode = request.form.get('start_mode', 'scheduled')  # immediate, scheduled
    
    # 生成安全的文件名
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = f"{group_id}_{timestamp}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    try:
        # 保存文件
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # 记录文件信息
        uploaded_file = UploadedFile(
            group_id=group_id,
            filename=safe_filename,
            original_filename=filename,
            file_path=file_path,
            file_size=file_size,
            file_type=file_type,
            start_mode=start_mode
        )
        
        db.session.add(uploaded_file)
        db.session.commit()
        
        # 处理Excel文件
        is_temp = (file_type == 'temp')
        success, message = process_excel_file(file_path, group, is_temp, start_mode)
        
        if success:
            log_activity(current_user_id, 'upload_file', 
                        f"上传文件: {filename} ({'临时' if is_temp else '常规'})", group.id)
            
            # 如果是定时启动的临时文件，添加到调度器
            if is_temp and start_mode == 'scheduled':
                add_scheduled_temp_file(group_id, file_path)
            
            return jsonify({
                'message': f'文件上传成功。{message}',
                'file_id': uploaded_file.id
            })
        else:
            # 删除上传失败的文件
            try:
                os.remove(file_path)
            except:
                pass
            db.session.delete(uploaded_file)
            db.session.commit()
            
            return jsonify({'error': f'文件处理失败: {message}'}), 400
            
    except Exception as e:
        # 清理失败的文件
        try:
            os.remove(file_path)
        except:
            pass
        
        logger.error(f"File upload error: {e}")
        return jsonify({'error': f'文件上传失败: {str(e)}'}), 500

@app.route('/api/groups/<int:group_id>/reload', methods=['POST'])
@jwt_required()
@group_owner_required
def reload_schedule(group_id):
    """重新加载提醒计划"""
    current_user_id = get_jwt_identity()
    group = Group.query.get_or_404(group_id)
    
    # 获取最新的常规文件
    latest_file = UploadedFile.query.filter_by(
        group_id=group_id,
        file_type='regular',
        is_active=True
    ).order_by(UploadedFile.uploaded_at.desc()).first()
    
    if not latest_file:
        return jsonify({'error': '没有找到可用的Excel文件'}), 400
    
    # 重新处理文件（应用智能时间过滤）
    success, message = process_excel_file(latest_file.file_path, group, False, 'immediate')
    
    if success:
        group.last_active = datetime.utcnow()
        db.session.commit()
        
        log_activity(current_user_id, 'reload_schedule', 
                    f"重新加载计划: {message}", group.id)
        
        return jsonify({'message': f'计划重新加载成功。{message}'})
    else:
        return jsonify({'error': f'计划重新加载失败: {message}'}), 500

@app.route('/api/groups/<int:group_id>/temp-files', methods=['GET'])
@jwt_required()
@group_owner_required
def get_temp_files(group_id):
    """获取临时文件状态"""
    temp_files = UploadedFile.query.filter_by(
        group_id=group_id,
        file_type='temp',
        is_active=True
    ).order_by(UploadedFile.uploaded_at.desc()).all()
    
    result = []
    for file in temp_files:
        result.append({
            'id': file.id,
            'filename': file.original_filename,
            'start_mode': file.start_mode,
            'uploaded_at': file.uploaded_at.isoformat(),
            'processed_at': file.processed_at.isoformat() if file.processed_at else None,
            'file_size': file.file_size
        })
    
    return jsonify({'temp_files': result})

@app.route('/api/groups/<int:group_id>/temp-files', methods=['DELETE'])
@jwt_required()
@group_owner_required
def clear_temp_files(group_id):
    """清理临时文件"""
    current_user_id = get_jwt_identity()
    
    temp_files = UploadedFile.query.filter_by(
        group_id=group_id,
        file_type='temp',
        is_active=True
    ).all()
    
    cleared_count = 0
    for file in temp_files:
        try:
            # 删除物理文件
            if os.path.exists(file.file_path):
                os.remove(file.file_path)
            
            # 标记为不活跃
            file.is_active = False
            cleared_count += 1
            
        except Exception as e:
            logger.error(f"Error clearing temp file {file.id}: {e}")
    
    # 删除临时提醒计划
    today = datetime.utcnow().date()
    ReminderSchedule.query.filter_by(
        group_id=group_id,
        schedule_date=today,
        is_temp=True
    ).delete()
    
    db.session.commit()
    
    log_activity(current_user_id, 'clear_temp_files', 
                f"清理 {cleared_count} 个临时文件", group_id)
    
    return jsonify({'message': f'已清理 {cleared_count} 个临时文件'})

@app.route('/api/groups/batch-status', methods=['PUT'])
@jwt_required()
def batch_update_status():
    """批量更新群组状态"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    data = request.get_json()
    
    if not data or 'group_ids' not in data or 'status' not in data:
        return jsonify({'error': '缺少必要参数'}), 400
    
    group_ids = data['group_ids']
    new_status = data['status']
    
    if new_status not in ['running', 'paused', 'stopped']:
        return jsonify({'error': '无效的状态值'}), 400
    
    # 获取用户的群组（管理员可以操作所有群组）
    if user.role == 'admin':
        groups = Group.query.filter(Group.id.in_(group_ids)).all()
    else:
        groups = Group.query.filter(
            Group.id.in_(group_ids),
            Group.owner_id == current_user_id
        ).all()
    
    # 检查运行群组配额
    if new_status == 'running':
        current_running = Group.query.filter_by(
            owner_id=current_user_id,
            status='running'
        ).count()
        
        will_be_running = len([g for g in groups if g.status != 'running'])
        
        if current_running + will_be_running > user.max_running_groups:
            return jsonify({'error': f'运行群组数量将超出限制 ({user.max_running_groups})'}), 400
    
    updated_count = 0
    for group in groups:
        group.status = new_status
        group.last_active = datetime.utcnow()
        group.updated_at = datetime.utcnow()
        updated_count += 1
    
    db.session.commit()
    
    log_activity(current_user_id, 'batch_update_status', 
                f"批量更新 {updated_count} 个群组状态为 {new_status}")
    
    return jsonify({'message': f'已更新 {updated_count} 个群组状态'})

@app.route('/api/system/stats', methods=['GET'])
@jwt_required()
def get_system_stats():
    """获取系统统计信息"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.role == 'admin':
        # 管理员看到所有统计
        total_groups = Group.query.count()
        running_groups = Group.query.filter_by(status='running').count()
        total_users = User.query.count()
        today_reminders = db.session.query(db.func.sum(Group.reminders_today)).scalar() or 0
    else:
        # 普通用户只看自己的统计
        total_groups = Group.query.filter_by(owner_id=current_user_id).count()
        running_groups = Group.query.filter_by(
            owner_id=current_user_id,
            status='running'
        ).count()
        total_users = 1
        today_reminders = db.session.query(db.func.sum(Group.reminders_today)).filter(
            Group.owner_id == current_user_id
        ).scalar() or 0
    
    # 计算内存使用（估算）
    memory_usage = 128 + running_groups * 20  # MB
    
    return jsonify({
        'total_groups': total_groups,
        'running_groups': running_groups,
        'paused_groups': Group.query.filter_by(status='paused').count(),
        'stopped_groups': Group.query.filter_by(status='stopped').count(),
        'total_users': total_users,
        'today_reminders': today_reminders,
        'memory_usage': memory_usage,
        'system_status': 'normal'
    })

@app.route('/api/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    """获取用户列表（管理员专用）"""
    users = User.query.all()
    
    result = []
    for user in users:
        user_groups = Group.query.filter_by(owner_id=user.id).count()
        running_groups = Group.query.filter_by(
            owner_id=user.id,
            status='running'
        ).count()
        
        result.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat(),
            'max_groups': user.max_groups,
            'max_running_groups': user.max_running_groups,
            'max_daily_reminders': user.max_daily_reminders,
            'current_groups': user_groups,
            'current_running_groups': running_groups
        })
    
    return jsonify({'users': result})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    """更新用户信息（管理员专用）"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'error': '缺少更新数据'}), 400
    
    # 更新用户信息
    if 'role' in data:
        user.role = data['role']
    if 'is_active' in data:
        user.is_active = data['is_active']
    if 'max_groups' in data:
        user.max_groups = int(data['max_groups'])
    if 'max_running_groups' in data:
        user.max_running_groups = int(data['max_running_groups'])
    if 'max_daily_reminders' in data:
        user.max_daily_reminders = int(data['max_daily_reminders'])
    
    db.session.commit()
    
    current_user_id = get_jwt_identity()
    log_activity(current_user_id, 'update_user', 
                f"更新用户 {user.username} 的信息")
    
    return jsonify({'message': '用户信息更新成功'})

@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_activity_logs():
    """获取活动日志"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    if user.role == 'admin':
        # 管理员可以看到所有日志
        logs_query = ActivityLog.query
    else:
        # 普通用户只能看到自己的日志
        logs_query = ActivityLog.query.filter_by(user_id=current_user_id)
    
    logs = logs_query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    result = []
    for log in logs.items:
        result.append({
            'id': log.id,
            'user_id': log.user_id,
            'group_id': log.group_id,
            'action': log.action,
            'description': log.description,
            'ip_address': log.ip_address,
            'created_at': log.created_at.isoformat()
        })
    
    return jsonify({
        'logs': result,
        'total': logs.total,
        'pages': logs.pages,
        'current_page': page
    })

# 定时任务相关
scheduler = BackgroundScheduler()

def send_reminder_job():
    """发送提醒消息的定时任务"""
    with app.app_context():
        try:
            current_time = datetime.now().time()
            today = datetime.now().date()
            
            # 获取需要发送的提醒
            schedules = ReminderSchedule.query.join(Group).filter(
                ReminderSchedule.schedule_date == today,
                ReminderSchedule.time <= current_time,
                ReminderSchedule.status == 'pending',
                Group.status == 'running'
            ).all()
            
            for schedule in schedules:
                try:
                    group = schedule.group
                    webhook_url = decrypt_webhook(group.webhook_url_encrypted)
                    
                    if webhook_url:
                        success, message = send_dingtalk_message(webhook_url, schedule.message)
                        
                        if success:
                            schedule.status = 'sent'
                            schedule.sent_at = datetime.utcnow()
                            group.reminders_today += 1
                            group.total_reminders_sent += 1
                            group.last_active = datetime.utcnow()
                        else:
                            schedule.status = 'failed'
                            schedule.error_message = message
                            logger.error(f"Failed to send reminder {schedule.id}: {message}")
                    else:
                        schedule.status = 'failed'
                        schedule.error_message = 'Webhook解密失败'
                        logger.error(f"Failed to decrypt webhook for group {group.id}")
                        
                except Exception as e:
                    schedule.status = 'failed'
                    schedule.error_message = str(e)
                    logger.error(f"Error sending reminder {schedule.id}: {e}")
            
            db.session.commit()
            logger.info(f"Processed {len(schedules)} reminders")
            
        except Exception as e:
            logger.error(f"Error in send_reminder_job: {e}")

def daily_reset_job():
    """每日重置任务"""
    with app.app_context():
        try:
            # 重置今日提醒计数
            Group.query.update({'reminders_today': 0})
            
            # 清理过期的提醒计划
            yesterday = datetime.now().date() - timedelta(days=1)
            ReminderSchedule.query.filter(
                ReminderSchedule.schedule_date < yesterday
            ).delete()
            
            # 处理定时启动的临时文件
            process_scheduled_temp_files()
            
            db.session.commit()
            logger.info("Daily reset completed")
            
        except Exception as e:
            logger.error(f"Error in daily_reset_job: {e}")

def process_scheduled_temp_files():
    """处理定时启动的临时文件"""
    try:
        # 获取所有待处理的定时临时文件
        temp_files = UploadedFile.query.filter_by(
            file_type='temp',
            start_mode='scheduled',
            is_active=True,
            processed_at=None
        ).all()
        
        for temp_file in temp_files:
            try:
                group = Group.query.get(temp_file.group_id)
                if group and os.path.exists(temp_file.file_path):
                    success, message = process_excel_file(
                        temp_file.file_path, 
                        group, 
                        is_temp=True, 
                        start_mode='scheduled'
                    )
                    
                    if success:
                        temp_file.processed_at = datetime.utcnow()
                        logger.info(f"Processed scheduled temp file: {temp_file.filename}")
                        
                        # 备份并删除文件
                        backup_and_delete_temp_file(temp_file)
                    else:
                        logger.error(f"Failed to process temp file {temp_file.id}: {message}")
                        
            except Exception as e:
                logger.error(f"Error processing temp file {temp_file.id}: {e}")
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error in process_scheduled_temp_files: {e}")

def backup_and_delete_temp_file(temp_file):
    """备份并删除临时文件"""
    try:
        # 这里可以添加文件备份逻辑
        # 例如移动到备份目录或上传到云存储
        
        # 删除物理文件
        if os.path.exists(temp_file.file_path):
            os.remove(temp_file.file_path)
        
        # 标记为不活跃
        temp_file.is_active = False
        
    except Exception as e:
        logger.error(f"Error backing up temp file {temp_file.id}: {e}")

def add_scheduled_temp_file(group_id, file_path):
    """添加定时临时文件到处理队列"""
    # 这里可以添加特殊的调度逻辑
    # 目前依赖每日重置任务来处理
    pass

# 启动调度器
if not scheduler.running:
    # 每分钟检查提醒
    scheduler.add_job(
        func=send_reminder_job,
        trigger=CronTrigger(second=0),
        id='send_reminders',
        name='Send reminders every minute',
        replace_existing=True
    )
    
    # 每日02:00重置
    scheduler.add_job(
        func=daily_reset_job,
        trigger=CronTrigger(hour=2, minute=0),
        id='daily_reset',
        name='Daily reset at 02:00',
        replace_existing=True
    )
    
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '资源未找到'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': '服务器内部错误'}), 500

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({'error': '文件大小超过限制 (16MB)'}), 413

# 静态文件服务（开发环境）
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)
