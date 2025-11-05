package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Arterning/ViaeGo/auth"
	"github.com/Arterning/ViaeGo/logger"
)

// HTTPProxy HTTP代理服务器
type HTTPProxy struct {
	host string
	port int
	auth auth.Authenticator
}

// NewHTTPProxy 创建HTTP代理服务器
func NewHTTPProxy(host string, port int, authenticator auth.Authenticator) *HTTPProxy {
	return &HTTPProxy{
		host: host,
		port: port,
		auth: authenticator,
	}
}

// Start 启动HTTP代理服务器
func (h *HTTPProxy) Start() error {
	addr := fmt.Sprintf("%s:%d", h.host, h.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Infof("HTTP代理服务器启动在 %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("接受连接失败: %v", err)
			continue
		}

		go h.handleConnection(conn)
	}
}

// handleConnection 处理客户端连接
func (h *HTTPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	logger.Debugf("收到来自 %s 的HTTP连接", clientAddr)

	reader := bufio.NewReader(clientConn)

	// 读取HTTP请求
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Errorf("读取HTTP请求失败: %v", err)
		return
	}

	// 验证认证
	if h.auth != nil {
		if authHeader := req.Header.Get("Proxy-Authorization"); authHeader != "" {
			username, password, ok := auth.ParseBasicAuth(authHeader)
			if !ok || !h.auth.Authenticate(username, password) {
				logger.Warnf("来自 %s 的认证失败", clientAddr)
				h.sendAuthRequired(clientConn)
				return
			}
		} else {
			// 检查是否需要认证
			if _, ok := h.auth.(*auth.NoAuth); !ok {
				logger.Warnf("来自 %s 缺少认证信息", clientAddr)
				h.sendAuthRequired(clientConn)
				return
			}
		}
	}

	logger.Infof("HTTP请求: %s %s (来自 %s)", req.Method, req.URL.String(), clientAddr)

	// 处理CONNECT方法（用于HTTPS）
	if req.Method == http.MethodConnect {
		h.handleConnect(clientConn, req)
	} else {
		// 处理普通HTTP请求
		h.handleHTTP(clientConn, req)
	}
}

// handleConnect 处理CONNECT请求（HTTPS隧道）
func (h *HTTPProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	// 连接到目标服务器
	targetConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		logger.Errorf("连接到目标服务器 %s 失败: %v", req.Host, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 发送连接成功响应
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	logger.Debugf("建立HTTPS隧道: %s", req.Host)

	// 双向转发数据
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// handleHTTP 处理普通HTTP请求
func (h *HTTPProxy) handleHTTP(clientConn net.Conn, req *http.Request) {
	// 确保请求有完整的URL
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// 移除Proxy-Authorization头
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	// 确保Host包含端口号
	targetAddr := ensurePort(req.URL.Host, req.URL.Scheme)

	// 连接到目标服务器
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		logger.Errorf("连接到目标服务器 %s 失败: %v", targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 发送请求到目标服务器
	if err := req.Write(targetConn); err != nil {
		logger.Errorf("发送请求到目标服务器失败: %v", err)
		return
	}

	// 将响应转发回客户端
	io.Copy(clientConn, targetConn)
}

// ensurePort 确保地址包含端口号
func ensurePort(host, scheme string) string {
	// 如果已经包含端口号，直接返回
	if strings.Contains(host, ":") {
		return host
	}

	// 根据协议添加默认端口
	if scheme == "https" {
		return net.JoinHostPort(host, "443")
	}
	return net.JoinHostPort(host, "80")
}

// sendAuthRequired 发送需要认证的响应
func (h *HTTPProxy) sendAuthRequired(conn net.Conn) {
	response := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	conn.Write([]byte(response))
}
