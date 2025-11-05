package auth

import (
	"encoding/base64"
	"strings"
)

// Authenticator 认证器接口
type Authenticator interface {
	Authenticate(username, password string) bool
}

// SimpleAuthenticator 简单认证器（单用户名密码）
type SimpleAuthenticator struct {
	username string
	password string
}

// NewSimpleAuthenticator 创建简单认证器
func NewSimpleAuthenticator(username, password string) *SimpleAuthenticator {
	return &SimpleAuthenticator{
		username: username,
		password: password,
	}
}

// Authenticate 验证用户名和密码
func (a *SimpleAuthenticator) Authenticate(username, password string) bool {
	return a.username == username && a.password == password
}

// NoAuth 无需认证
type NoAuth struct{}

// NewNoAuth 创建无认证实例
func NewNoAuth() *NoAuth {
	return &NoAuth{}
}

// Authenticate 始终返回true
func (a *NoAuth) Authenticate(username, password string) bool {
	return true
}

// ParseBasicAuth 解析HTTP Basic认证头
func ParseBasicAuth(authHeader string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	encoded := strings.TrimPrefix(authHeader, prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		return "", "", false
	}

	return pair[0], pair[1], true
}
