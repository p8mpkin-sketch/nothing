# 备份文件泄露测试服务器

这是一个用于测试 Nothing 插件备份文件扫描功能的测试服务器。

## 快速开始

### 1. 安装依赖
```bash
cd backscan
npm install
```

### 2. 启动服务器
```bash
npm start
```

### 3. 访问测试站点
打开浏览器访问：http://localhost:3000

### 4. 测试插件
1. 在浏览器中安装 Nothing 插件
2. 打开插件设置，启用"备份文件扫描"
3. 访问 http://localhost:3000
4. 打开插件，切换到"备份文件" Tab
5. 查看检测结果

## 测试场景

### ✅ 真实泄露（应该被检测到）

| 文件路径 | 类型 | 说明 |
|---------|------|------|
| `/backup.zip` | 备份文件 | 真实 ZIP 文件（包含 PK 文件头） |
| `/www.tar.gz` | 备份文件 | 真实 TAR.GZ 文件（包含 GZIP 文件头） |
| `/database.sql` | 备份文件 | 真实 SQL 备份（包含 CREATE TABLE） |
| `/.env` | 敏感文件 | 真实环境变量配置（包含数据库密码、API Key） |
| `/config.php` | 敏感文件 | 真实 PHP 配置（包含数据库凭据） |
| `/.svn/entries` | 版本控制泄露 | 真实 SVN entries 文件 |
| `/admin/admin.zip` | 备份文件 | 子目录下的备份文件 |
| `/api/backup.tar` | 备份文件 | 子目录下的 TAR 文件 |

**预期结果：8 个真实泄露被检测到**

### ❌ 误报场景（应该被过滤）

| 文件路径 | 类型 | 说明 |
|---------|------|------|
| `/fake-404.zip` | 误报 | 返回 200 但内容是 404 错误页 |
| `/fake-error.tar.gz` | 误报 | Spring Boot Whitelabel Error Page |
| `/fake-denied.sql` | 误报 | Access Denied 错误页 |
| `/fake-html.env` | 误报 | HTML 错误页伪装成 .env |

**预期结果：0 个误报被检测到**

## 验证标准

### 成功标准
- ✅ 检测到 8 个真实泄露
- ✅ 0 个误报
- ✅ 准确率 100%

### 失败标准
- ❌ 漏检真实泄露
- ❌ 误报错误页面
- ❌ 准确率 < 90%

## 技术细节

### 真实泄露特征
1. **ZIP 文件**：包含 `PK\x03\x04` 文件头
2. **GZIP 文件**：包含 `0x1f 0x8b` 文件头
3. **SQL 文件**：包含 `CREATE TABLE`, `INSERT INTO` 等 SQL 语句
4. **.env 文件**：包含 `KEY=value` 格式的环境变量
5. **PHP 配置**：包含 `<?php` 和数据库配置
6. **SVN entries**：包含 `svn:` 和版本信息

### 误报特征
1. **404 错误页**：包含 "404", "Not Found"
2. **Spring Boot 错误**：包含 "Whitelabel Error Page"
3. **Access Denied**：包含 "Access Denied", "Forbidden"
4. **HTML 错误页**：包含 HTML 标签 + 错误关键词

## 故障排查

### 问题：插件没有扫描
- 确认已启用"备份文件扫描"开关
- 确认已启用"主动扫描"开关（备份扫描依赖此开关）
- 刷新页面重新触发扫描

### 问题：检测到误报
- 检查插件版本是否最新
- 查看浏览器控制台是否有错误
- 如果配置了 AI，检查 AI Key 是否有效

### 问题：漏检真实泄露
- 检查网络请求是否成功（F12 -> Network）
- 查看插件日志（F12 -> Console）
- 确认文件内容是否符合验证规则

## 扩展测试

你可以添加更多测试场景：

```javascript
// 添加新的真实泄露
app.get('/test.rar', (req, res) => {
    const rarBuffer = Buffer.from([0x52, 0x61, 0x72, 0x21]); // "Rar!"
    res.setHeader('Content-Type', 'application/x-rar');
    res.send(rarBuffer);
});

// 添加新的误报场景
app.get('/fake-nginx.zip', (req, res) => {
    res.send('<html><body><h1>404 Not Found</h1><p>nginx/1.18.0</p></body></html>');
});
```

## 许可证

MIT
