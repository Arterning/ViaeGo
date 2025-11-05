package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Level 日志级别
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var (
	debugLog *log.Logger
	infoLog  *log.Logger
	warnLog  *log.Logger
	errorLog *log.Logger
	level    Level = INFO
)

// Init 初始化日志系统
func Init(levelStr string, filePath string) error {
	var writer io.Writer = os.Stdout

	// 如果指定了日志文件路径，则写入文件
	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		writer = io.MultiWriter(os.Stdout, file) // 同时输出到控制台和文件
	}

	// 设置日志级别
	level = parseLevel(levelStr)

	// 初始化各级别日志
	debugLog = log.New(writer, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)
	infoLog = log.New(writer, "[INFO] ", log.Ldate|log.Ltime|log.Lshortfile)
	warnLog = log.New(writer, "[WARN] ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLog = log.New(writer, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)

	return nil
}

// parseLevel 解析日志级别字符串
func parseLevel(levelStr string) Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

// Debug 输出调试日志
func Debug(v ...interface{}) {
	if level <= DEBUG {
		debugLog.Output(2, formatLog(v...))
	}
}

// Debugf 格式化输出调试日志
func Debugf(format string, v ...interface{}) {
	if level <= DEBUG {
		debugLog.Output(2, formatLogf(format, v...))
	}
}

// Info 输出信息日志
func Info(v ...interface{}) {
	if level <= INFO {
		infoLog.Output(2, formatLog(v...))
	}
}

// Infof 格式化输出信息日志
func Infof(format string, v ...interface{}) {
	if level <= INFO {
		infoLog.Output(2, formatLogf(format, v...))
	}
}

// Warn 输出警告日志
func Warn(v ...interface{}) {
	if level <= WARN {
		warnLog.Output(2, formatLog(v...))
	}
}

// Warnf 格式化输出警告日志
func Warnf(format string, v ...interface{}) {
	if level <= WARN {
		warnLog.Output(2, formatLogf(format, v...))
	}
}

// Error 输出错误日志
func Error(v ...interface{}) {
	if level <= ERROR {
		errorLog.Output(2, formatLog(v...))
	}
}

// Errorf 格式化输出错误日志
func Errorf(format string, v ...interface{}) {
	if level <= ERROR {
		errorLog.Output(2, formatLogf(format, v...))
	}
}

func formatLog(v ...interface{}) string {
	return fmt.Sprint(v...)
}

func formatLogf(format string, v ...interface{}) string {
	return fmt.Sprintf(format, v...)
}
