package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	Mode   string       `yaml:"mode"`   // server 或 client
	Server ServerConfig `yaml:"server"` // 服务器配置
	Client ClientConfig `yaml:"client"` // 客户端配置
	Log    LogConfig    `yaml:"log"`    // 日志配置
}

// ServerConfig 服务器模式配置
type ServerConfig struct {
	Host     string   `yaml:"host"`     // 监听地址
	HTTPPort int      `yaml:"httpPort"` // HTTP代理端口
	SocksPort int     `yaml:"socksPort"` // SOCKS5代理端口
	Username string   `yaml:"username"` // 用户名（可选）
	Password string   `yaml:"password"` // 密码（可选）
}

// ClientConfig 客户端模式配置
type ClientConfig struct {
	LocalHost  string `yaml:"localHost"`  // 本地监听地址
	LocalPort  int    `yaml:"localPort"`  // 本地监听端口
	ProxyType  string `yaml:"proxyType"`  // 代理类型：http 或 socks5
	RemoteHost string `yaml:"remoteHost"` // 远程代理服务器地址
	RemotePort int    `yaml:"remotePort"` // 远程代理服务器端口
	Username   string `yaml:"username"`   // 远程服务器用户名（可选）
	Password   string `yaml:"password"`   // 远程服务器密码（可选）
}

// LogConfig 日志配置
type LogConfig struct {
	Level    string `yaml:"level"`    // 日志级别：debug, info, warn, error
	FilePath string `yaml:"filePath"` // 日志文件路径（可选，为空则输出到控制台）
}

// Load 从文件加载配置
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	if cfg.Mode == "" {
		cfg.Mode = "server"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	return &cfg, nil
}

// NeedAuth 检查是否需要认证
func (s *ServerConfig) NeedAuth() bool {
	return s.Username != "" && s.Password != ""
}

// NeedAuth 检查客户端是否需要向远程服务器认证
func (c *ClientConfig) NeedAuth() bool {
	return c.Username != "" && c.Password != ""
}
