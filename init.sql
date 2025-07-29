# init.sql - 数据库初始化脚本
-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS dingtalk_reminder;

-- 设置字符集
ALTER DATABASE dingtalk_reminder CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 创建用户（如果需要）
-- CREATE USER 'dingtalk_user'@'%' IDENTIFIED BY 'password';
-- GRANT ALL PRIVILEGES ON dingtalk_reminder.* TO 'dingtalk_user'@'%';
-- FLUSH PRIVILEGES;
