package conf

import (
	"strings"

	"github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

func DefaultLogConfig() *log.Config {
	return &log.Config{
		AccessLogType: log.LogType_None,
		ErrorLogType:  log.LogType_Console,
		ErrorLogLevel: clog.Severity_Warning,
		// 配置里整段没有 log 时也走同一套默认,免得「有 log 段就不记 api、没有就记」这种不一致。
		AccessExcludeInboundTags: defaultAccessExcludeInboundTags,
	}
}

// defaultAccessExcludeInboundTags 未配置时默认排除的入站。
//
// api 是管理用的 dokodemo-door 入站,管理端每轮询一次统计就写一行 "[api -> api]",
// 而访问日志不受 loglevel 约束(那只 gate 错误日志),这些噪音会一直占磁盘。
// 默认排除它;真要看就把 accessExcludeInboundTags 显式配成 [] 或别的清单。
var defaultAccessExcludeInboundTags = []string{"api"}

type LogConfig struct {
	AccessLog   string `json:"access"`
	ErrorLog    string `json:"error"`
	LogLevel    string `json:"loglevel"`
	DNSLog      bool   `json:"dnsLog"`
	MaskAddress string `json:"maskAddress"`
	// AccessExcludeInboundTags 不记访问日志的入站 tag。
	//
	// **指针是必要的**:要区分「没配」和「显式配成空」。
	//   nil(字段缺失) → 用默认清单 ["api"]
	//   []            → 一个都不排除(把 api 的日志要回来)
	// 用 []string 的话两者都是 len==0,没法表达「我就是要全都记」。
	AccessExcludeInboundTags *[]string `json:"accessExcludeInboundTags"`
}

func (v *LogConfig) Build() *log.Config {
	if v == nil {
		return nil
	}
	config := &log.Config{
		ErrorLogType:  log.LogType_Console,
		AccessLogType: log.LogType_Console,
		EnableDnsLog:  v.DNSLog,
	}

	if v.AccessLog == "none" {
		config.AccessLogType = log.LogType_None
	} else if len(v.AccessLog) > 0 {
		config.AccessLogPath = v.AccessLog
		config.AccessLogType = log.LogType_File
	}
	if v.ErrorLog == "none" {
		config.ErrorLogType = log.LogType_None
	} else if len(v.ErrorLog) > 0 {
		config.ErrorLogPath = v.ErrorLog
		config.ErrorLogType = log.LogType_File
	}

	level := strings.ToLower(v.LogLevel)
	switch level {
	case "debug":
		config.ErrorLogLevel = clog.Severity_Debug
	case "info":
		config.ErrorLogLevel = clog.Severity_Info
	case "error":
		config.ErrorLogLevel = clog.Severity_Error
	case "none":
		config.ErrorLogType = log.LogType_None
		config.AccessLogType = log.LogType_None
	default:
		config.ErrorLogLevel = clog.Severity_Warning
	}
	config.MaskAddress = v.MaskAddress
	if v.AccessExcludeInboundTags == nil {
		config.AccessExcludeInboundTags = defaultAccessExcludeInboundTags
	} else {
		config.AccessExcludeInboundTags = *v.AccessExcludeInboundTags
	}
	return config
}
