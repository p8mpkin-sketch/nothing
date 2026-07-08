# 🧪 备份文件扫描测试指南

## 测试服务器已启动

✅ 服务器地址：**http://localhost:9999**

## 测试步骤

### 1. 准备工作
- [x] 测试服务器已启动（端口 9999）
- [ ] 安装 Nothing 插件到浏览器
- [ ] 配置 AI Key（可选，用于 AI 降噪）

### 2. 启用备份文件扫描
1. 打开 Nothing 插件
2. 切换到"设置" Tab
3. 启用以下开关：
   - ✅ **主动扫描**（必须）
   - ✅ **备份文件扫描**（必须）
4. 如果配置了 AI，AI 会自动进行二次降噪

### 3. 访问测试站点
在浏览器中打开：**http://localhost:9999**

### 4. 查看检测结果
1. 打开 Nothing 插件
2. 切换到"备份文件" Tab
3. 等待扫描完成（约 10-30 秒）

## 预期结果

### ✅ 应该检测到（8 个真实泄露）

| 序号 | 文件路径 | 类型 | 验证方法 |
|-----|---------|------|---------|
| 1 | `/backup.zip` | 备份文件 | 包含 ZIP 文件头 `PK\x03\x04` |
| 2 | `/www.tar.gz` | 备份文件 | 包含 GZIP 文件头 `0x1f 0x8b` |
| 3 | `/database.sql` | 备份文件 | 包含 SQL 语句 `CREATE TABLE` |
| 4 | `/.env` | 敏感文件 | 包含环境变量 `DB_PASSWORD=xxx` |
| 5 | `/config.php` | 敏感文件 | 包含 PHP 代码和数据库凭据 |
| 6 | `/.svn/entries` | 版本控制 | 包含 SVN 格式 `svn:` |
| 7 | `/admin/admin.zip` | 备份文件 | 子目录下的 ZIP 文件 |
| 8 | `/api/backup.tar` | 备份文件 | 子目录下的 TAR 文件 |

### ❌ 应该被过滤（0 个误报）

| 序号 | 文件路径 | 误报类型 | 过滤原因 |
|-----|---------|---------|---------|
| 1 | `/fake-404.zip` | 404 错误页 | 包含 "404 Not Found" |
| 2 | `/fake-error.tar.gz` | Spring Boot 错误 | 包含 "Whitelabel Error Page" |
| 3 | `/fake-denied.sql` | Access Denied | 包含 "Access Denied" |
| 4 | `/fake-html.env` | HTML 错误页 | HTML 标签 + "Error" |

## 验证标准

### ✅ 测试通过
- 检测到 **8 个**真实泄露
- **0 个**误报
- 准确率 **100%**

### ❌ 测试失败
- 漏检任何真实泄露
- 误报任何错误页面
- 准确率 < 90%

## 手动验证

你可以手动访问这些 URL 来验证：

### 真实泄露示例
```bash
# 1. ZIP 文件（应该下载）
curl http://localhost:9999/backup.zip --output test.zip
file test.zip  # 应该显示：Zip archive data

# 2. SQL 备份（应该看到 SQL 语句）
curl http://localhost:9999/database.sql
# 应该包含：CREATE TABLE users

# 3. .env 文件（应该看到环境变量）
curl http://localhost:9999/.env
# 应该包含：DB_PASSWORD=P@ssw0rd123!

# 4. SVN 泄露（应该看到 SVN 格式）
curl http://localhost:9999/.svn/entries
# 应该包含：svn://svn.example.com
```

### 误报示例
```bash
# 1. 假 ZIP（应该是 404 错误页）
curl http://localhost:9999/fake-404.zip
# 应该包含：404 Not Found

# 2. 假 TAR.GZ（应该是 Spring Boot 错误）
curl http://localhost:9999/fake-error.tar.gz
# 应该包含：Whitelabel Error Page

# 3. 假 SQL（应该是 Access Denied）
curl http://localhost:9999/fake-denied.sql
# 应该包含：Access Denied
```

## 故障排查

### 问题 1：没有检测到任何文件
**可能原因：**
- 未启用"主动扫描"或"备份文件扫描"
- 扫描还在进行中（等待 30 秒）

**解决方法：**
1. 检查设置页面的开关状态
2. 刷新页面重新触发扫描
3. 查看浏览器控制台是否有错误

### 问题 2：检测到误报
**可能原因：**
- 本地验证逻辑未生效
- AI 降噪未启用或失败

**解决方法：**
1. 检查插件版本是否最新
2. 配置 AI Key 启用 AI 降噪
3. 查看控制台日志确认过滤逻辑

### 问题 3：漏检真实泄露
**可能原因：**
- 网络请求失败
- 验证逻辑过于严格

**解决方法：**
1. 打开 F12 -> Network，查看请求状态
2. 查看控制台日志确认扫描过程
3. 手动访问 URL 确认内容正确

## 性能测试

### 扫描时间
- **预期**：10-30 秒
- **实际**：_____秒

### 请求数量
- **预期**：约 100 个请求（根据字典大小）
- **实际**：_____个请求

### 准确率
- **真实泄露检出率**：___/8 = ___%
- **误报率**：___/4 = ___%
- **总体准确率**：___%

## 停止服务器

测试完成后，停止服务器：
```bash
# 按 Ctrl+C 或者
pkill -f "node server.js"
```

## 扩展测试

你可以添加更多测试场景到 `server.js`：

```javascript
// 添加 RAR 文件测试
app.get('/test.rar', (req, res) => {
    const rarBuffer = Buffer.from([0x52, 0x61, 0x72, 0x21]); // "Rar!"
    res.setHeader('Content-Type', 'application/x-rar');
    res.send(rarBuffer);
});

// 添加 7z 文件测试
app.get('/test.7z', (req, res) => {
    const sevenZipBuffer = Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
    res.setHeader('Content-Type', 'application/x-7z-compressed');
    res.send(sevenZipBuffer);
});
```

## 测试报告模板

```
测试日期：2026-03-03
测试人员：_______
插件版本：_______

检测结果：
- 真实泄露：___/8
- 误报：___/4
- 准确率：___%

问题记录：
1. _______
2. _______

改进建议：
1. _______
2. _______
```
