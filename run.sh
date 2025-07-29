# run.sh - 启动脚本
#!/bin/bash

# 等待数据库启动
echo "Waiting for database..."
while ! nc -z db 5432; do
  sleep 1
done
echo "Database is ready!"

# 初始化数据库
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database initialized')
"

# 启动应用
if [ "$FLASK_ENV" = "production" ]; then
    echo "Starting production server..."
    gunicorn --bind 0.0.0.0:5000 --workers 4 --threads 2 --timeout 30 --keep-alive 2 --max-requests 1000 --max-requests-jitter 50 app:app
else
    echo "Starting development server..."
    python app.py
fi
