package evidenceguard

import "testing"

func TestQuoteFoundInText(t *testing.T) {
	text := "HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash"
	if !QuoteFoundInText("root:x:0:0", text) {
		t.Fatal("应命中")
	}
	if QuoteFoundInText("root:x:0:1", text) {
		t.Fatal("不应命中")
	}
	if QuoteFoundInText("", text) {
		t.Fatal("空引文不应命中")
	}
	if !QuoteFoundInText("HTTP/1.1   200   OK", text) {
		t.Fatal("空白归一后应命中")
	}
}
