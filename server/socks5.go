package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Arterning/ViaeGo/auth"
	"github.com/Arterning/ViaeGo/logger"
)

const (
	socks5Version = 0x05

	// 认证方法
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// 命令类型
	cmdConnect = 0x01
	cmdBind    = 0x02
	cmdUDP     = 0x03

	// 地址类型
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// 响应状态
	repSuccess              = 0x00
	repServerFailure        = 0x01
	repConnectionNotAllowed = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repTTLExpired          = 0x06
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

// SOCKS5Proxy SOCKS5代理服务器
type SOCKS5Proxy struct {
	host string
	port int
	auth auth.Authenticator
}

// NewSOCKS5Proxy 创建SOCKS5代理服务器
func NewSOCKS5Proxy(host string, port int, authenticator auth.Authenticator) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		host: host,
		port: port,
		auth: authenticator,
	}
}

// Start 启动SOCKS5代理服务器
func (s *SOCKS5Proxy) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Infof("SOCKS5代理服务器启动在 %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("接受连接失败: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// handleConnection 处理客户端连接
func (s *SOCKS5Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	logger.Debugf("收到来自 %s 的SOCKS5连接", clientAddr)

	// 1. 协商认证方法
	if err := s.negotiate(clientConn); err != nil {
		logger.Errorf("协商认证方法失败: %v", err)
		return
	}

	// 2. 处理客户端请求
	target, err := s.handleRequest(clientConn)
	if err != nil {
		logger.Errorf("处理请求失败: %v", err)
		return
	}

	logger.Infof("SOCKS5请求: %s (来自 %s)", target, clientAddr)

	// 3. 连接到目标服务器
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logger.Errorf("连接到目标服务器 %s 失败: %v", target, err)
		s.sendReply(clientConn, repHostUnreachable)
		return
	}
	defer targetConn.Close()

	// 4. 发送成功响应
	s.sendReply(clientConn, repSuccess)

	// 5. 双向转发数据
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// negotiate 协商认证方法
func (s *SOCKS5Proxy) negotiate(conn net.Conn) error {
	buf := make([]byte, 257)

	// 读取客户端支持的认证方法
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("读取认证方法失败: %w", err)
	}

	// 检查版本
	if buf[0] != socks5Version {
		return fmt.Errorf("不支持的SOCKS版本: %d", buf[0])
	}

	nMethods := int(buf[1])
	if n < 2+nMethods {
		return fmt.Errorf("认证方法数据不完整")
	}

	// 确定使用的认证方法
	var selectedMethod byte
	_, needAuth := s.auth.(*auth.NoAuth)
	needAuth = !needAuth

	if needAuth {
		// 需要认证，查找是否支持用户名密码认证
		hasPasswordAuth := false
		for i := 0; i < nMethods; i++ {
			if buf[2+i] == authPassword {
				hasPasswordAuth = true
				break
			}
		}
		if hasPasswordAuth {
			selectedMethod = authPassword
		} else {
			selectedMethod = authNoAccept
		}
	} else {
		// 不需要认证
		selectedMethod = authNone
	}

	// 发送选择的认证方法
	_, err = conn.Write([]byte{socks5Version, selectedMethod})
	if err != nil {
		return fmt.Errorf("发送认证方法失败: %w", err)
	}

	if selectedMethod == authNoAccept {
		return fmt.Errorf("没有可接受的认证方法")
	}

	// 如果需要用户名密码认证，进行认证
	if selectedMethod == authPassword {
		if err := s.authenticate(conn); err != nil {
			return err
		}
	}

	return nil
}

// authenticate 用户名密码认证
func (s *SOCKS5Proxy) authenticate(conn net.Conn) error {
	buf := make([]byte, 513)

	// 读取认证请求
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return fmt.Errorf("读取认证请求失败: %w", err)
	}

	// 检查版本（认证子协议版本为0x01）
	if buf[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01}) // 认证失败
		return fmt.Errorf("不支持的认证版本: %d", buf[0])
	}

	// 读取用户名
	usernameLen := int(buf[1])
	if n < 2+usernameLen {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("用户名数据不完整")
	}
	username := string(buf[2 : 2+usernameLen])

	// 读取密码长度
	if n < 3+usernameLen {
		n2, err := io.ReadAtLeast(conn, buf[n:], 3+usernameLen-n)
		if err != nil {
			conn.Write([]byte{0x01, 0x01})
			return fmt.Errorf("读取密码长度失败: %w", err)
		}
		n += n2
	}

	passwordLen := int(buf[2+usernameLen])
	if n < 3+usernameLen+passwordLen {
		n2, err := io.ReadAtLeast(conn, buf[n:], 3+usernameLen+passwordLen-n)
		if err != nil {
			conn.Write([]byte{0x01, 0x01})
			return fmt.Errorf("读取密码失败: %w", err)
		}
		n += n2
	}
	password := string(buf[3+usernameLen : 3+usernameLen+passwordLen])

	// 验证用户名和密码
	if !s.auth.Authenticate(username, password) {
		conn.Write([]byte{0x01, 0x01}) // 认证失败
		return fmt.Errorf("用户名或密码错误")
	}

	// 认证成功
	_, err = conn.Write([]byte{0x01, 0x00})
	return err
}

// handleRequest 处理客户端请求
func (s *SOCKS5Proxy) handleRequest(conn net.Conn) (string, error) {
	buf := make([]byte, 262)

	// 读取请求头
	n, err := io.ReadAtLeast(conn, buf, 4)
	if err != nil {
		return "", fmt.Errorf("读取请求失败: %w", err)
	}

	// 检查版本
	if buf[0] != socks5Version {
		return "", fmt.Errorf("不支持的SOCKS版本: %d", buf[0])
	}

	// 检查命令
	cmd := buf[1]
	if cmd != cmdConnect {
		s.sendReply(conn, repCommandNotSupported)
		return "", fmt.Errorf("不支持的命令: %d", cmd)
	}

	// 解析目标地址
	atyp := buf[3]
	var host string
	var port uint16

	switch atyp {
	case atypIPv4:
		// IPv4地址
		if n < 10 {
			n2, err := io.ReadAtLeast(conn, buf[n:], 10-n)
			if err != nil {
				s.sendReply(conn, repServerFailure)
				return "", err
			}
			n += n2
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])

	case atypDomain:
		// 域名
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			n2, err := io.ReadAtLeast(conn, buf[n:], 5+domainLen+2-n)
			if err != nil {
				s.sendReply(conn, repServerFailure)
				return "", err
			}
			n += n2
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])

	case atypIPv6:
		// IPv6地址
		if n < 22 {
			n2, err := io.ReadAtLeast(conn, buf[n:], 22-n)
			if err != nil {
				s.sendReply(conn, repServerFailure)
				return "", err
			}
			n += n2
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])

	default:
		s.sendReply(conn, repAddrTypeNotSupported)
		return "", fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// sendReply 发送响应
func (s *SOCKS5Proxy) sendReply(conn net.Conn, rep byte) {
	// 简单的响应：VER REP RSV ATYP ADDR PORT
	// 使用0.0.0.0:0作为绑定地址
	reply := []byte{
		socks5Version,
		rep,
		0x00, // RSV
		atypIPv4,
		0, 0, 0, 0, // 0.0.0.0
		0, 0, // port 0
	}
	conn.Write(reply)
}
