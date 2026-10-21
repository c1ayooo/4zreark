// Package httpprobe 只保留报告层需要的报文标记常量。
//
// 来源：4zreco internal/httpprobe。4zreark 的报文存储格式与之一致
// （vulnerabilities.request / response 与扫描结果的 transcript），
// 报告渲染按这两个标记切分请求与响应。
package httpprobe

const (
	RequestMarker  = "=== REQUEST ==="
	ResponseMarker = "=== RESPONSE ==="
)
