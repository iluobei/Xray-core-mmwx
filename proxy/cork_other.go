//go:build !linux

package proxy

import "io"

// 分段直通只在 Linux / Android 上启用,别的平台用不到 TCP_CORK。
func setCork(io.Writer, bool) {}
