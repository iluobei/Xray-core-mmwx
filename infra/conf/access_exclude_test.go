package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

// 「不记 api 入站的访问日志」要默认生效,同时留一条把它要回来的路。
// 用指针区分「没配」和「显式配空」—— 用 []string 的话两者都是 len==0,表达不了后者。
func TestLogConfigAccessExcludeInboundTags(t *testing.T) {
	empty := []string{}
	custom := []string{"api", "metrics-in"}

	for _, tc := range []struct {
		name string
		in   *[]string
		want []string
	}{
		{"没配 → 默认排除 api", nil, []string{"api"}},
		{"显式配空 → 一个都不排除(把 api 日志要回来)", &empty, []string{}},
		{"自定义清单原样生效", &custom, []string{"api", "metrics-in"}},
	} {
		got := (&conf.LogConfig{AccessExcludeInboundTags: tc.in}).Build().AccessExcludeInboundTags
		if len(got) != len(tc.want) {
			t.Errorf("%s: 得到 %v,期望 %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: 得到 %v,期望 %v", tc.name, got, tc.want)
				break
			}
		}
	}

	// 配置里整段没有 log 时也该排除 —— 否则「有 log 段就不记、没有就记」不一致
	if tags := conf.DefaultLogConfig().AccessExcludeInboundTags; len(tags) != 1 || tags[0] != "api" {
		t.Errorf("DefaultLogConfig 的排除清单 = %v,期望 [api]", tags)
	}
}
