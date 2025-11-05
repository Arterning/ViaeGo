package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Arterning/ViaeGo/auth"
	"github.com/Arterning/ViaeGo/client"
	"github.com/Arterning/ViaeGo/config"
	"github.com/Arterning/ViaeGo/logger"
	"github.com/Arterning/ViaeGo/server"
)

func main() {
	// 解析命令行参数
	configFile := flag.String("c", "config.yaml", "配置文件路径")
	flag.Parse()

	// 加载配置文件
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志系统
	if err := logger.Init(cfg.Log.Level, cfg.Log.FilePath); err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}

	logger.Infof("ViaeGo 代理服务器启动，模式: %s", cfg.Mode)

	// 根据模式启动相应的服务
	switch cfg.Mode {
	case "server":
		runServer(cfg)
	case "client":
		runClient(cfg)
	default:
		logger.Errorf("不支持的模式: %s", cfg.Mode)
		os.Exit(1)
	}
}

// runServer 运行服务器模式
func runServer(cfg *config.Config) {
	// 创建认证器
	var authenticator auth.Authenticator
	if cfg.Server.NeedAuth() {
		logger.Info("启用认证")
		authenticator = auth.NewSimpleAuthenticator(cfg.Server.Username, cfg.Server.Password)
	} else {
		logger.Info("无需认证")
		authenticator = auth.NewNoAuth()
	}

	// 启动HTTP代理和SOCKS5代理
	errChan := make(chan error, 2)

	// 启动HTTP代理
	if cfg.Server.HTTPPort > 0 {
		go func() {
			httpProxy := server.NewHTTPProxy(cfg.Server.Host, cfg.Server.HTTPPort, authenticator)
			if err := httpProxy.Start(); err != nil {
				errChan <- fmt.Errorf("HTTP代理启动失败: %w", err)
			}
		}()
	}

	// 启动SOCKS5代理
	if cfg.Server.SocksPort > 0 {
		go func() {
			socks5Proxy := server.NewSOCKS5Proxy(cfg.Server.Host, cfg.Server.SocksPort, authenticator)
			if err := socks5Proxy.Start(); err != nil {
				errChan <- fmt.Errorf("SOCKS5代理启动失败: %w", err)
			}
		}()
	}

	// 等待错误
	err := <-errChan
	logger.Errorf("服务器错误: %v", err)
	os.Exit(1)
}

// runClient 运行客户端模式
func runClient(cfg *config.Config) {
	logger.Infof("客户端模式：本地 %s:%d -> 远程 %s 代理 %s:%d",
		cfg.Client.LocalHost, cfg.Client.LocalPort,
		cfg.Client.ProxyType, cfg.Client.RemoteHost, cfg.Client.RemotePort)

	var err error

	// 根据代理类型创建客户端
	if cfg.Client.ProxyType == "socks5" {
		// SOCKS5本地代理
		proxy := client.NewSOCKS5LocalProxy(
			cfg.Client.LocalHost,
			cfg.Client.LocalPort,
			cfg.Client.RemoteHost,
			cfg.Client.RemotePort,
			cfg.Client.Username,
			cfg.Client.Password,
		)
		err = proxy.Start()
	} else if cfg.Client.ProxyType == "http" {
		// HTTP本地代理
		proxy := client.NewLocalProxy(
			cfg.Client.LocalHost,
			cfg.Client.LocalPort,
			"http",
			cfg.Client.RemoteHost,
			cfg.Client.RemotePort,
			cfg.Client.Username,
			cfg.Client.Password,
		)
		err = proxy.Start()
	} else {
		logger.Errorf("不支持的代理类型: %s", cfg.Client.ProxyType)
		os.Exit(1)
	}

	if err != nil {
		logger.Errorf("客户端启动失败: %v", err)
		os.Exit(1)
	}
}
