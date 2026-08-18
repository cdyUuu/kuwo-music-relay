# 酷我音乐中转解密服务器

[English](README.md) | 中文

单文件 PHP 中转服务器，实时解密酷我音乐加密音频文件（`.mflac`、`.mgg`、`.mmp3`）并流式传输给播放器。专为落雪音乐等第三方播放器设计。

## 功能特性

- **实时流式解密** — 无需等待整个文件下载完成，边下载边解密边播放
- **多格式支持** — `.mflac`（FLAC）、`.mgg`（OGG Vorbis）、`.mmp3`（MP3）
- **HTTP Range 支持** — 拖动进度条时直接转发 Range 请求到 CDN，只下载需要的字节范围
- **磁盘缓存** — 解密后的文件自动缓存，重复访问直接从磁盘读取；断连时保留部分缓存支持断点续传
- **并发请求处理** — 文件锁防止同一首歌被重复下载
- **FLAC 元数据提取** — 自动发送 `X-Duration`、`X-Sample-Rate`、`X-Channels`、`X-Bits-Per-Sample` 等头部信息
- **CORS 跨域支持** — 浏览器播放器可直接跨域访问
- **SSRF 防护** — 阻止请求指向内网/保留 IP 地址段
- **第三方播放器兼容** — 兼容落雪音乐（LX Music）等支持 URL 播放的播放器
- **单文件部署** — 只需上传 `decrypt.php` 到任意 PHP 服务器

## 环境要求

- PHP 7.4+（64 位）
- cURL 扩展

## 快速开始

### 方式一：Docker 部署（推荐）

```bash
# 使用 docker-compose
docker compose up -d

# 或手动构建
docker build -t kuwo-relay .
docker run -d -p 8080:8080 --name kuwo-relay kuwo-relay
```

然后在浏览器打开 `http://localhost:8080/`。

### 方式二：PHP 内置服务器

```bash
php -S 0.0.0.0:8080 decrypt.php
```

### 方式三：上传到 Web 服务器

1. 将 `decrypt.php` 上传到支持 PHP 的 Web 服务器（Apache/Nginx + PHP-FPM）
2. 确保 Web 服务器有系统临时目录（`/tmp/mflac_relay/`）的写入权限
3. 通过浏览器访问即可看到帮助页面

## 使用方法

### 基本 URL 格式

```
http://你的服务器地址/decrypt.php?url=<加密文件URL>&ekey=<加密密钥>
```

### 配合落雪音乐使用

在落雪音乐中配置自定义音乐源，将本服务器作为播放 URL 前缀。落雪音乐的插件会自动构造包含 `url` 和 `ekey` 参数的完整链接。

### 下载模式

在 URL 后添加 `&download=1` 可强制下载而非在线播放：

```
http://你的服务器地址/decrypt.php?url=<url>&ekey=<key>&download=1
```

## 配置说明

所有配置项以 PHP 常量定义在 `decrypt.php` 文件顶部：

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `RELAY_CACHE_DIR` | `/tmp/mflac_relay` | 解密后文件的缓存目录 |
| `RELAY_LOG_FILE` | `./access.log` | 日志文件路径（相对于脚本） |
| `RELAY_ENABLE_LOG` | `true` | 是否启用日志 |
| `RELAY_CACHE_TIME` | `3600` | 缓存有效期（秒，默认 1 小时） |
| `RELAY_DOWNLOAD_TIMEOUT` | `300` | 下载超时时间（秒） |
| `RELAY_CONNECT_TIMEOUT` | `15` | 连接超时时间（秒） |
| `RELAY_MAX_CACHE_SIZE` | `536870912` | 最大缓存总大小（字节，默认 512MB） |
| `RELAY_MAX_CACHE_FILES` | `50` | 最大缓存文件数量 |
| `RELAY_MAX_LOG_SIZE` | `10485760` | 日志文件最大大小，超过后轮转（10MB） |
| `RELAY_MEMORY_LIMIT` | `256M` | PHP 内存限制 |
| `RELAY_VERSION` | `1.0.0` | 服务器版本号 |

## 工作原理

```
播放器  <──解密音频──>  decrypt.php  <──加密数据──>  酷我 CDN
                            |
                      解密 + 写入
                      磁盘缓存
```

1. **播放器发送 HEAD** → 服务器返回 `Content-Type`、`Content-Length`、`Accept-Ranges: bytes`
2. **播放器发送 GET** → 服务器开始从 CDN 下载，实时解密，边播放边写入磁盘缓存
3. **播放器拖动进度条（Range 请求）** → 服务器转发字节范围到 CDN，只解密请求的部分，返回 `206 Partial Content`
4. **重复播放同一首歌** → 服务器直接从磁盘缓存读取，瞬时响应

### 解密算法

使用 QMC2 加密方案：

1. **ekey 解密**：`ekey` 经过 Base64 编码并用 TC-TEA（腾讯 TEA）加密。解密后提取原始密钥。
2. **密钥派生**：原始密钥经过 QMC 密钥派生处理（EncV2 格式检测、哈希计算）。
3. **音频解密**：根据密钥长度选择算法：
   - 密钥 <= 300 字节 → **Map XOR 加密**（基于位置的密钥映射）
   - 密钥 > 300 字节 → **RC4 流加密**（基于分段的跳过逻辑）

### 关于 MGG 音频质量显示

QQ 音乐的 `.mgg` 文件采用 4 声道 OGG Vorbis 编码，标称码率 640kbps（相当于 320kbps 立体声复制到 4 声道）。这是 QQ 音乐 CDN 的原始编码 —— 解密是正确的，但部分播放器可能因 OGG 头中的 640kbps 码率而显示为"高品质"或"母带"。这是预期行为，不修改音频数据无法改变。

## 支持的格式

| 扩展名 | 解密后格式 | Content-Type |
|--------|-----------|--------------|
| `.mflac` / `.mflac0` | FLAC | `audio/flac` |
| `.mgg` / `.mggl` | OGG Vorbis | `audio/ogg` |
| `.mmp3` | MP3 | `audio/mpeg` |

## 日志

日志以单行 JSON 格式写入 `access.log`（可配置）。每条记录包含：

- 时间戳、日志级别、客户端 IP、HTTP 方法
- 请求 URI、ekey 前缀（前 16 字符）、Range 头、User-Agent
- 下载/解密字节数、完成百分比、耗时

日志轮转：当日志文件超过 `RELAY_MAX_LOG_SIZE` 时，当前文件重命名为 `.old` 并开始新文件。

## 安全性

- **URL 协议校验** — 仅允许 `http`/`https`
- **SSRF 防护** — 阻止请求指向内网/保留 IP 地址段（RFC 1918、loopback、link-local）
- **ekey 长度校验** — 拒绝格式异常的密钥
- **无文件路径遍历风险** — 缓存键使用 SHA-256 哈希
- **缓存文件** 存储在系统临时目录中

## 项目结构

```
.
├── decrypt.php         # 主服务器文件（单文件，约 2100 行）
├── Dockerfile          # Docker 镜像定义
├── docker-compose.yml  # Docker Compose 配置
├── README.md           # 英文文档
├── README_CN.md        # 中文文档（本文件）
├── LICENSE             # PolyForm Noncommercial
└── .gitignore          # Git 忽略规则
```

## 参与贡献

欢迎提交 Pull Request！

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/新功能`）
3. 提交更改（`git commit -m '添加新功能'`）
4. 推送到分支（`git push origin feature/新功能`）
5. 发起 Pull Request

### 贡献指南

- 保持单文件架构 — 所有服务器逻辑应保留在 `decrypt.php` 中
- 提交前请使用实际的 `.mflac` 和 `.mgg` 文件测试
- 如果新增配置项，请同步更新 README 文档
- 遵循现有代码风格（PSR-12 兼容）

## 算法来源

解密算法基于 [nonebot-plugin-kuwo](https://github.com/006lp/nonebot-plugin-kuwo) 的 Rust 实现。

## 免责声明

本项目仅供**个人学习与技术交流**使用。

- 本项目不存储、不托管、不分发任何受版权保护的音乐文件。
- 使用本工具前，请确保你已获得版权所有者的授权或许可。
- 本项目作者及贡献者不对使用本工具所产生的任何法律后果承担责任。
- 使用本项目即表示你同意自行承担一切法律责任。
- 如果你是版权方，认为本项目侵犯了你的权益，请联系仓库所有者，我们将及时处理。
- 严禁将本工具用于商业用途、传播解密后的内容或以此牟利。

## 适配的 LX Music 插件

本服务专为配合 LX Music 自定义音源插件使用：
[lx-music-xinghai-source](https://github.com/cdyUuu/lx-music-xinghai-source)

该插件会自动将酷我加密音频（`.mflac` / `.mgg`）路由到本中转服务器进行实时解密。
**兼容性以该插件为准。**

## 许可证

PolyForm Noncommercial License 1.0.0 — 详见 [LICENSE](LICENSE)。

本项目使用 [PolyForm Noncommercial License](https://polyformproject.org/licenses/noncommercial/1.0.0)，
**禁止商业用途**。商业用途包括出售软件、用于付费服务、传播解密内容牟利、
或集成到商业产品中。个人学习、技术交流和非商业教育用途允许使用。
