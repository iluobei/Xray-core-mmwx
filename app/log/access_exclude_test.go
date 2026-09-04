package log_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/testing/mocks"
)

// 按入站 tag 过滤访问日志:默认把 api 那条 dokodemo-door 入站的噪音挡掉,
// 别的入站原样记录。api 每被轮询一次就写一行,而访问日志不受 loglevel 约束。
func TestAccessLogExcludesInboundTags(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	var logged []string
	mockHandler := mocks.NewLogHandler(mockCtl)
	mockHandler.EXPECT().Handle(gomock.Any()).AnyTimes().DoAndReturn(func(msg clog.Message) {
		logged = append(logged, msg.String())
	})
	log.RegisterHandlerCreator(log.LogType_Console, func(lt log.LogType, options log.HandlerCreatorOptions) (clog.Handler, error) {
		return mockHandler, nil
	})

	logger, err := log.New(context.Background(), &log.Config{
		ErrorLogType:             log.LogType_None,
		AccessLogType:            log.LogType_Console,
		AccessExcludeInboundTags: []string{"api"},
	})
	common.Must(err)
	common.Must(logger.Start())
	defer func() { common.Must(logger.Close()) }()

	logged = nil
	clog.Record(&clog.AccessMessage{From: "127.0.0.1", To: "api", Status: clog.AccessAccepted, Tag: "api"})
	if len(logged) != 0 {
		t.Errorf("api 入站的访问日志应被挡掉,却写了: %v", logged)
	}

	clog.Record(&clog.AccessMessage{From: "1.2.3.4", To: "example.com", Status: clog.AccessAccepted, Tag: "vless-in"})
	if len(logged) != 1 {
		t.Fatalf("普通入站的访问日志应照常记录,实际 %v", logged)
	}
	// Tag 不能进日志行 —— 加这个字段不允许改变既有格式
	if got := logged[0]; got != "from 1.2.3.4 accepted example.com" {
		t.Errorf("日志行格式被改动了: %q", got)
	}

	// 没有 tag 的消息(不经 dispatcher 的拒绝态等)照常记录
	logged = nil
	clog.Record(&clog.AccessMessage{From: "5.6.7.8", To: "x.com", Status: clog.AccessRejected})
	if len(logged) != 1 {
		t.Errorf("无 tag 的访问日志应照常记录,实际 %v", logged)
	}
}
