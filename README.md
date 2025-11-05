# ViaeGo

基于Go语言实现的HTTP和SOCKS5代理服务器，支持服务器和客户端两种模式。

## 功能特性

- 支持HTTP代理协议
- 支持SOCKS5代理协议
- 可选的用户名密码认证
- 服务器模式：直接提供代理服务
- 客户端模式：本地代理转发到远程服务器
- 详细的日志记录
- 通过YAML配置文件管理

## 快速开始

### 安装依赖

```bash
go get gopkg.in/yaml.v3
```

### 编译

```bash
go build -o viaego
```

### 配置文件

复制并编辑 `config.yaml` 文件：

```bash
cp config.yaml my-config.yaml
```

### 运行

使用默认配置文件（config.yaml）：

```bash
./viaego
```

使用自定义配置文件：

```bash
./viaego -c my-config.yaml
```

## 使用场景

### 场景1：直接代理服务器（无认证）

适用于内网环境，不需要认证的代理服务器。

**config.yaml 配置：**

```yaml
mode: server

server:
  host: 0.0.0.0
  httpPort: 8080
  socksPort: 1080
  username: ""
  password: ""

log:
  level: info
  filePath: ""
```

**启动服务器：**

```bash
./viaego
```

**客户端使用：**

```bash
# HTTP代理
curl -x http://server-ip:8080 https://example.com

# SOCKS5代理
curl -x socks5://server-ip:1080 https://example.com
```

### 场景2：带认证的代理服务器

适用于需要安全认证的环境。

**config.yaml 配置：**

```yaml
mode: server

server:
  host: 0.0.0.0
  httpPort: 8080
  socksPort: 1080
  username: admin
  password: password123

log:
  level: info
  filePath: ""
```

**客户端使用：**

```bash
# HTTP代理（带认证）
curl -x http://admin:password123@server-ip:8080 https://example.com

# SOCKS5代理（带认证）
curl -x socks5://admin:password123@server-ip:1080 https://example.com
```

### 场景3：客户端模式（本地代理转发）

适用于需要在本地启动代理，将流量转发到远程代理服务器的场景。

**config.yaml 配置：**

```yaml
mode: client

client:
  localHost: 127.0.0.1
  localPort: 1080
  proxyType: socks5
  remoteHost: remote-proxy.example.com
  remotePort: 1080
  username: admin
  password: password123

log:
  level: info
  filePath: ""
```

**启动客户端：**

```bash
./viaego
```

**使用本地代理：**

```bash
# 使用本地SOCKS5代理（会自动转发到远程服务器）
curl -x socks5://127.0.0.1:1080 https://example.com
```

## 配置说明

### 模式选择

- `mode: server` - 服务器模式，直接提供代理服务
- `mode: client` - 客户端模式，本地代理转发到远程服务器

### 服务器配置

- `host` - 监听地址（0.0.0.0表示监听所有网卡）
- `httpPort` - HTTP代理端口（设置为0则不启动HTTP代理）
- `socksPort` - SOCKS5代理端口（设置为0则不启动SOCKS5代理）
- `username` - 用户名（留空则不需要认证）
- `password` - 密码（留空则不需要认证）

### 客户端配置

- `localHost` - 本地监听地址
- `localPort` - 本地监听端口
- `proxyType` - 代理类型（http 或 socks5）
- `remoteHost` - 远程代理服务器地址
- `remotePort` - 远程代理服务器端口
- `username` - 远程服务器用户名（留空则不需要认证）
- `password` - 远程服务器密码（留空则不需要认证）

### 日志配置

- `level` - 日志级别（debug, info, warn, error）
- `filePath` - 日志文件路径（留空则只输出到控制台）

## 项目结构

```
ViaeGo/
├── main.go           # 主程序入口
├── config/           # 配置模块
│   └── config.go
├── logger/           # 日志模块
│   └── logger.go
├── auth/             # 认证模块
│   └── auth.go
├── server/           # 服务器模块
│   ├── http.go       # HTTP代理服务器
│   └── socks5.go     # SOCKS5代理服务器
├── client/           # 客户端模块
│   └── client.go     # 本地代理客户端
├── config.yaml       # 配置文件示例
└── README.md         # 项目说明
```

## 协议支持

### HTTP代理

- 支持HTTP和HTTPS（CONNECT方法）
- 支持Basic认证（Proxy-Authorization）

### SOCKS5代理

- 支持TCP连接（CONNECT命令）
- 支持IPv4、IPv6和域名地址类型
- 支持用户名密码认证（RFC 1929）

## 注意事项

1. 在生产环境中，建议启用认证以提高安全性
2. 建议使用HTTPS或加密隧道保护代理流量
3. 日志文件可能包含敏感信息，注意保护
4. 客户端模式适合于需要在本地启动代理并转发到远程服务器的场景

## 许可证

MIT License
