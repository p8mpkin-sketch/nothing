const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 9999;

// 静态文件服务
app.use(express.static(path.join(__dirname, 'public')));

// 主页
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>备份文件泄露测试站点</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .section h2 { color: #666; margin-top: 0; }
        .file-list { list-style: none; padding: 0; }
        .file-list li { padding: 8px; margin: 5px 0; background: #f5f5f5; border-radius: 3px; }
        .file-list a { color: #0066cc; text-decoration: none; }
        .file-list a:hover { text-decoration: underline; }
        .status { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin-left: 10px; }
        .status.real { background: #ff4444; color: white; }
        .status.fake { background: #44ff44; color: #333; }
    </style>
</head>
<body>
    <h1>🔍 备份文件泄露测试站点</h1>
    <p>这个测试站点包含真实的备份文件泄露和误报场景，用于测试 Nothing 插件的检测能力。</p>

    <div class="section">
        <h2>✅ 真实泄露（应该被检测到）</h2>
        <ul class="file-list">
            <li><a href="/backup.zip">/backup.zip</a> <span class="status real">真实 ZIP</span></li>
            <li><a href="/www.tar.gz">/www.tar.gz</a> <span class="status real">真实 TAR.GZ</span></li>
            <li><a href="/database.sql">/database.sql</a> <span class="status real">真实 SQL</span></li>
            <li><a href="/.env">/.env</a> <span class="status real">真实配置</span></li>
            <li><a href="/config.php">/config.php</a> <span class="status real">真实 PHP</span></li>
            <li><a href="/.svn/entries">/.svn/entries</a> <span class="status real">真实 SVN</span></li>
            <li><a href="/admin/admin.zip">/admin/admin.zip</a> <span class="status real">真实 ZIP</span></li>
            <li><a href="/api/backup.tar">/api/backup.tar</a> <span class="status real">真实 TAR</span></li>
        </ul>
    </div>

    <div class="section">
        <h2>❌ 误报场景（应该被过滤）</h2>
        <ul class="file-list">
            <li><a href="/fake-404.zip">/fake-404.zip</a> <span class="status fake">404 错误页</span></li>
            <li><a href="/fake-error.tar.gz">/fake-error.tar.gz</a> <span class="status fake">Spring Boot 错误</span></li>
            <li><a href="/fake-denied.sql">/fake-denied.sql</a> <span class="status fake">Access Denied</span></li>
            <li><a href="/fake-html.env">/fake-html.env</a> <span class="status fake">HTML 错误页</span></li>
        </ul>
    </div>

    <div class="section">
        <h2>📊 测试说明</h2>
        <ol>
            <li>启动服务器：<code>node server.js</code></li>
            <li>访问：<code>http://localhost:3000</code></li>
            <li>打开 Nothing 插件，启用"备份文件扫描"</li>
            <li>查看"备份文件" Tab，应该只显示真实泄露，不显示误报</li>
        </ol>
    </div>
</body>
</html>
    `);
});

// ========== 真实泄露场景 ==========

// 1. 真实 ZIP 文件
app.get('/backup.zip', (req, res) => {
    const zipBuffer = Buffer.from([
        0x50, 0x4B, 0x03, 0x04, // ZIP 文件头 "PK\x03\x04"
        0x14, 0x00, 0x00, 0x00, 0x08, 0x00,
        // ... 后续是 ZIP 文件内容
    ]);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="backup.zip"');
    res.send(zipBuffer);
});

// 2. 真实 TAR.GZ 文件
app.get('/www.tar.gz', (req, res) => {
    const gzipBuffer = Buffer.from([
        0x1f, 0x8b, // GZIP 文件头
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ... 后续是 GZIP 内容
    ]);
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="www.tar.gz"');
    res.send(gzipBuffer);
});

// 3. 真实 SQL 备份
app.get('/database.sql', (req, res) => {
    const sql = `-- MySQL dump 10.13
--
-- Database: production_db
--

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email) VALUES
('admin', 'e10adc3949ba59abbe56e057f20f883e', 'admin@example.com'),
('user1', '5f4dcc3b5aa765d61d8327deb882cf99', 'user1@example.com');

CREATE TABLE orders (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT,
  total DECIMAL(10,2),
  status VARCHAR(20),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Dump completed on 2026-03-03
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(sql);
});

// 4. 真实 .env 文件
app.get('/.env', (req, res) => {
    const env = `# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=P@ssw0rd123!

# API Keys
API_KEY=sk-1234567890abcdef
SECRET_KEY=abcdef1234567890
JWT_SECRET=my-super-secret-jwt-key

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=redis_secret_pass

# Email
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=noreply@example.com
MAIL_PASSWORD=email_password_123
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(env);
});

// 5. 真实 PHP 配置文件
app.get('/config.php', (req, res) => {
    const php = `<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'MySecretPassword123!');
define('DB_NAME', 'production_db');

// API Configuration
define('API_KEY', 'sk-1234567890abcdef');
define('API_SECRET', 'secret_key_here');

// Session Configuration
define('SESSION_LIFETIME', 3600);
define('SESSION_SECURE', true);

// Database Connection
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Admin Credentials
$admin_username = 'admin';
$admin_password = 'admin123456';

?>
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(php);
});

// 6. 真实 SVN entries
app.get('/.svn/entries', (req, res) => {
    const svn = `12

dir
0
svn://svn.example.com/project/trunk
svn://svn.example.com/project



2026-03-03T10:30:00.000000Z
1234
admin


svn:special svn:externals svn:needs-lock

index.php
file




2026-03-03T10:25:00.000000Z
abc123def456
1233
admin
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(svn);
});

// 7. 子目录备份文件
app.get('/admin/admin.zip', (req, res) => {
    const zipBuffer = Buffer.from([
        0x50, 0x4B, 0x03, 0x04,
        0x14, 0x00, 0x00, 0x00, 0x08, 0x00,
    ]);
    res.setHeader('Content-Type', 'application/zip');
    res.send(zipBuffer);
});

app.get('/api/backup.tar', (req, res) => {
    const tarContent = 'ustar  ' + 'x'.repeat(500); // TAR 文件包含 ustar 标识
    res.setHeader('Content-Type', 'application/x-tar');
    res.send(tarContent);
});

// ========== 误报场景 ==========

// 1. 404 错误页（返回 200 但内容是 404）
app.get('/fake-404.zip', (req, res) => {
    res.status(200).send(`
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested file /fake-404.zip was not found on this server.</p>
</body>
</html>
    `);
});

// 2. Spring Boot 错误页
app.get('/fake-error.tar.gz', (req, res) => {
    res.status(200).send(`
Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.

Tue Mar 03 19:04:35 CST 2026
There was an unexpected error (type=Not Found, status=404).
No static resource fake-error.tar.gz.
    `);
});

// 3. Access Denied 页面
app.get('/fake-denied.sql', (req, res) => {
    res.status(200).send(`
<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Access Denied</h1>
<p>You don't have permission to access /fake-denied.sql on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>
    `);
});

// 4. HTML 错误页（伪装成 .env）
app.get('/fake-html.env', (req, res) => {
    res.status(200).send(`
<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<h1>Error occurred</h1>
<p>An unexpected error has occurred while processing your request.</p>
<p>Error code: 404</p>
</body>
</html>
    `);
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  🔍 备份文件泄露测试服务器已启动                           ║
╚════════════════════════════════════════════════════════════╝

📍 访问地址: http://localhost:${PORT}

✅ 真实泄露文件（应该被检测到）:
   - /backup.zip          (真实 ZIP 文件)
   - /www.tar.gz          (真实 TAR.GZ 文件)
   - /database.sql        (真实 SQL 备份)
   - /.env                (真实环境变量配置)
   - /config.php          (真实 PHP 配置)
   - /.svn/entries        (真实 SVN 泄露)
   - /admin/admin.zip     (子目录备份)
   - /api/backup.tar      (子目录备份)

❌ 误报场景（应该被过滤）:
   - /fake-404.zip        (404 错误页)
   - /fake-error.tar.gz   (Spring Boot 错误)
   - /fake-denied.sql     (Access Denied)
   - /fake-html.env       (HTML 错误页)

🧪 测试步骤:
   1. 打开浏览器访问 http://localhost:${PORT}
   2. 打开 Nothing 插件
   3. 启用"备份文件扫描"
   4. 查看"备份文件" Tab
   5. 应该只显示 8 个真实泄露，0 个误报

按 Ctrl+C 停止服务器
    `);
});
