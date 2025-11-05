package client

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Arterning/ViaeGo/logger"
)

// LocalProxy 本地代理客户端，将流量转发到远程代理服务器
type LocalProxy struct {
	localHost  string
	localPort  int
	proxyType  string // "http" 或 "socks5"
	remoteHost string
	remotePort int
	username   string
	password   string
}

// NewLocalProxy 创建本地代理客户端
func NewLocalProxy(localHost string, localPort int, proxyType string, remoteHost string, remotePort int, username, password string) *LocalProxy {
	return &LocalProxy{
		localHost:  localHost,
		localPort:  localPort,
		proxyType:  proxyType,
		remoteHost: remoteHost,
		remotePort: remotePort,
		username:   username,
		password:   password,
	}
}

// Start 启动本地代理
func (l *LocalProxy) Start() error {
	addr := fmt.Sprintf("%s:%d", l.localHost, l.localPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Infof("本地代理启动在 %s，转发到远程 %s 代理 %s:%d",
		addr, l.proxyType, l.remoteHost, l.remotePort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("接受连接失败: %v", err)
			continue
		}

		go l.handleConnection(conn)
	}
}

// handleConnection 处理本地连接
func (l *LocalProxy) handleConnection(localConn net.Conn) {
	defer localConn.Close()

	clientAddr := localConn.RemoteAddr().String()
	logger.Debugf("收到来自 %s 的本地连接", clientAddr)

	// 连接到远程代理服务器
	remoteAddr := net.JoinHostPort(l.remoteHost, strconv.Itoa(l.remotePort))
	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		logger.Errorf("连接到远程代理服务器失败: %v", err)
		return
	}
	defer remoteConn.Close()

	logger.Debugf("已连接到远程代理服务器 %s", remoteAddr)

	// 根据代理类型进行握手
	if l.proxyType == "http" {
		// HTTP代理不需要特殊握手，直接转发
		l.forwardHTTP(localConn, remoteConn)
	} else if l.proxyType == "socks5" {
		// SOCKS5需要握手和认证
		if err := l.socks5Handshake(remoteConn); err != nil {
			logger.Errorf("SOCKS5握手失败: %v", err)
			return
		}
		// 转发流量
		l.forwardSOCKS5(localConn, remoteConn)
	}
}

// forwardHTTP 转发HTTP代理流量
func (l *LocalProxy) forwardHTTP(localConn, remoteConn net.Conn) {
	// 读取本地请求并添加认证头（如果需要）
	buf := make([]byte, 4096)
	n, err := localConn.Read(buf)
	if err != nil {
		logger.Errorf("读取本地请求失败: %v", err)
		return
	}

	// 如果需要认证，添加Proxy-Authorization头
	if l.username != "" && l.password != "" {
		// 简单处理：在第一行后添加认证头
		request := string(buf[:n])
		auth := base64.StdEncoding.EncodeToString([]byte(l.username + ":" + l.password))
		authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)

		// 查找第一个\r\n的位置，在其后插入认证头
		idx := 0
		for i := 0; i < len(request)-1; i++ {
			if request[i] == '\r' && request[i+1] == '\n' {
				idx = i + 2
				break
			}
		}

		if idx > 0 {
			newRequest := request[:idx] + authHeader + request[idx:]
			buf = []byte(newRequest)
			n = len(buf)
		}
	}

	// 发送请求到远程代理
	if _, err := remoteConn.Write(buf[:n]); err != nil {
		logger.Errorf("发送请求到远程代理失败: %v", err)
		return
	}

	// 双向转发
	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
}

// forwardSOCKS5 转发SOCKS5代理流量
func (l *LocalProxy) forwardSOCKS5(localConn, remoteConn net.Conn) {
	// 直接双向转发（已经完成握手）
	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
}

// socks5Handshake 执行SOCKS5握手和认证
func (l *LocalProxy) socks5Handshake(conn net.Conn) error {
	// 1. 发送认证方法协商
	var authMethod byte = 0x00 // 无需认证
	if l.username != "" && l.password != "" {
		authMethod = 0x02 // 用户名密码认证
	}

	// 发送：VER, NMETHODS, METHODS
	_, err := conn.Write([]byte{0x05, 0x01, authMethod})
	if err != nil {
		return fmt.Errorf("发送认证方法失败: %w", err)
	}

	// 2. 读取服务器选择的认证方法
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取服务器响应失败: %w", err)
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("不支持的SOCKS版本: %d", buf[0])
	}

	selectedMethod := buf[1]

	// 3. 如果需要用户名密码认证
	if selectedMethod == 0x02 {
		if err := l.socks5Auth(conn); err != nil {
			return err
		}
	} else if selectedMethod == 0xFF {
		return fmt.Errorf("服务器不接受认证方法")
	}

	logger.Debug("SOCKS5握手和认证完成")
	return nil
}

// socks5Auth 执行SOCKS5用户名密码认证
func (l *LocalProxy) socks5Auth(conn net.Conn) error {
	// 构建认证请求
	usernameLen := len(l.username)
	passwordLen := len(l.password)
	authReq := make([]byte, 3+usernameLen+passwordLen)

	authReq[0] = 0x01 // 认证子协议版本
	authReq[1] = byte(usernameLen)
	copy(authReq[2:], l.username)
	authReq[2+usernameLen] = byte(passwordLen)
	copy(authReq[3+usernameLen:], l.password)

	// 发送认证请求
	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("发送认证请求失败: %w", err)
	}

	// 读取认证响应
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取认证响应失败: %w", err)
	}

	if buf[1] != 0x00 {
		return fmt.Errorf("认证失败")
	}

	return nil
}

// SOCKS5LocalProxy SOCKS5本地代理，接受SOCKS5请求并转发到远程SOCKS5服务器
type SOCKS5LocalProxy struct {
	*LocalProxy
}

// NewSOCKS5LocalProxy 创建SOCKS5本地代理
func NewSOCKS5LocalProxy(localHost string, localPort int, remoteHost string, remotePort int, username, password string) *SOCKS5LocalProxy {
	return &SOCKS5LocalProxy{
		LocalProxy: NewLocalProxy(localHost, localPort, "socks5", remoteHost, remotePort, username, password),
	}
}

// Start 启动SOCKS5本地代理
func (s *SOCKS5LocalProxy) Start() error {
	addr := fmt.Sprintf("%s:%d", s.localHost, s.localPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Infof("SOCKS5本地代理启动在 %s，转发到远程SOCKS5服务器 %s:%d",
		addr, s.remoteHost, s.remotePort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("接受连接失败: %v", err)
			continue
		}

		go s.handleSOCKS5Connection(conn)
	}
}

// handleSOCKS5Connection 处理SOCKS5本地连接
func (s *SOCKS5LocalProxy) handleSOCKS5Connection(localConn net.Conn) {
	defer localConn.Close()

	clientAddr := localConn.RemoteAddr().String()
	logger.Debugf("收到来自 %s 的SOCKS5连接", clientAddr)

	// 1. 处理本地SOCKS5握手
	buf := make([]byte, 257)
	n, err := io.ReadAtLeast(localConn, buf, 2)
	if err != nil {
		logger.Errorf("读取SOCKS5握手失败: %v", err)
		return
	}

	if buf[0] != 0x05 {
		logger.Errorf("不支持的SOCKS版本: %d", buf[0])
		return
	}

	// 回复：无需认证
	if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
		logger.Errorf("发送SOCKS5握手响应失败: %v", err)
		return
	}

	// 2. 读取客户端请求
	n, err = io.ReadAtLeast(localConn, buf, 4)
	if err != nil {
		logger.Errorf("读取SOCKS5请求失败: %v", err)
		return
	}

	// 解析目标地址
	atyp := buf[3]
	var targetAddr []byte
	var host string
	var port uint16

	switch atyp {
	case 0x01: // IPv4
		if n < 10 {
			n2, err := io.ReadAtLeast(localConn, buf[n:], 10-n)
			if err != nil {
				return
			}
			n += n2
		}
		targetAddr = buf[:10]
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])

	case 0x03: // 域名
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			n2, err := io.ReadAtLeast(localConn, buf[n:], 5+domainLen+2-n)
			if err != nil {
				return
			}
			n += n2
		}
		targetAddr = buf[:5+domainLen+2]
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])

	case 0x04: // IPv6
		if n < 22 {
			n2, err := io.ReadAtLeast(localConn, buf[n:], 22-n)
			if err != nil {
				return
			}
			n += n2
		}
		targetAddr = buf[:22]
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])

	default:
		logger.Errorf("不支持的地址类型: %d", atyp)
		localConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	logger.Debugf("SOCKS5请求目标: %s:%d", host, port)

	// 3. 连接到远程SOCKS5服务器
	remoteAddr := net.JoinHostPort(s.remoteHost, strconv.Itoa(s.remotePort))
	remoteConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		logger.Errorf("连接到远程SOCKS5服务器失败: %v", err)
		localConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// 4. 与远程SOCKS5服务器握手
	if err := s.socks5Handshake(remoteConn); err != nil {
		logger.Errorf("与远程SOCKS5服务器握手失败: %v", err)
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 5. 发送目标地址到远程服务器
	if _, err := remoteConn.Write(targetAddr); err != nil {
		logger.Errorf("发送目标地址到远程服务器失败: %v", err)
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 6. 读取远程服务器响应
	respBuf := make([]byte, 10)
	if _, err := io.ReadAtLeast(remoteConn, respBuf, 10); err != nil {
		logger.Errorf("读取远程服务器响应失败: %v", err)
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 7. 转发响应给本地客户端
	if _, err := localConn.Write(respBuf[:10]); err != nil {
		logger.Errorf("转发响应失败: %v", err)
		return
	}

	// 8. 如果连接成功，开始双向转发
	if respBuf[1] == 0x00 {
		logger.Debugf("隧道建立成功: %s:%d", host, port)
		go io.Copy(remoteConn, localConn)
		io.Copy(localConn, remoteConn)
	}
}
