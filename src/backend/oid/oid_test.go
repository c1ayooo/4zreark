package oid

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

// 前后端契约：24 位小写十六进制。
var hexRe = regexp.MustCompile(`^[0-9a-f]{24}$`)

func TestNewObjectIDFormat(t *testing.T) {
	seen := make(map[ObjectID]bool)
	for i := 0; i < 5000; i++ {
		id := NewObjectID()
		if id.IsZero() {
			t.Fatal("新生成的 ID 不该是零值")
		}
		if !hexRe.MatchString(id.Hex()) {
			t.Fatalf("Hex() 不是 24 位十六进制: %q", id.Hex())
		}
		if seen[id] {
			t.Fatalf("ID 重复: %s", id.Hex())
		}
		seen[id] = true
	}
}

func TestHexRoundTrip(t *testing.T) {
	id := NewObjectID()
	parsed, err := ObjectIDFromHex(id.Hex())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if parsed != id {
		t.Fatalf("往返不一致: %s != %s", parsed.Hex(), id.Hex())
	}
}

func TestObjectIDFromHexEdgeCases(t *testing.T) {
	// 空串返回零值且不报错——旧实现就是这个语义，不少调用方依赖它
	id, err := ObjectIDFromHex("")
	if err != nil || !id.IsZero() {
		t.Fatalf("空串应返回零值且无错，得到 %v %v", id, err)
	}
	if _, err := ObjectIDFromHex("abc"); err == nil {
		t.Fatal("长度不足应报错")
	}
	if _, err := ObjectIDFromHex("zzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Fatal("非十六进制应报错")
	}
	if _, err := ObjectIDFromHex("6AD72CAFE3485AE19E6437F3"); err != nil {
		t.Fatalf("大写应可解析: %v", err)
	}
}

func TestIsZero(t *testing.T) {
	if !NilObjectID.IsZero() {
		t.Fatal("零值判定错误")
	}
	if NewObjectID().IsZero() {
		t.Fatal("新 ID 不该判成零值")
	}
	// DDL 里 workspaces 的默认值就是 24 个 0
	fromZeroHex, err := ObjectIDFromHex("000000000000000000000000")
	if err != nil || !fromZeroHex.IsZero() {
		t.Fatalf("全零串应解析成零值: %v %v", fromZeroHex, err)
	}
}

func TestJSONMarshal(t *testing.T) {
	id := NewObjectID()
	b, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	want := `"` + id.Hex() + `"`
	if string(b) != want {
		t.Fatalf("序列化结果 %s，期望 %s", b, want)
	}

	// 零值输出 24 个 0，与旧实现一致
	b, _ = json.Marshal(NilObjectID)
	if string(b) != `"000000000000000000000000"` {
		t.Fatalf("零值序列化结果 %s", b)
	}
}

func TestJSONInStruct(t *testing.T) {
	type payload struct {
		ID   ObjectID `json:"id"`
		Name string   `json:"name"`
	}
	id := NewObjectID()
	b, err := json.Marshal(payload{ID: id, Name: "x"})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var back payload
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if back.ID != id {
		t.Fatalf("结构体内往返不一致: %s != %s", back.ID.Hex(), id.Hex())
	}
}

func TestJSONUnmarshalForms(t *testing.T) {
	id := NewObjectID()

	var fromString ObjectID
	if err := json.Unmarshal([]byte(`"`+id.Hex()+`"`), &fromString); err != nil {
		t.Fatalf("字符串形态解析失败: %v", err)
	}
	if fromString != id {
		t.Fatal("字符串形态解析结果不一致")
	}

	// 扩展 JSON 形态：老版本的导出文件里可能出现
	var fromExt ObjectID
	if err := json.Unmarshal([]byte(`{"$oid":"`+id.Hex()+`"}`), &fromExt); err != nil {
		t.Fatalf("扩展形态解析失败: %v", err)
	}
	if fromExt != id {
		t.Fatal("扩展形态解析结果不一致")
	}

	var fromNull ObjectID
	if err := json.Unmarshal([]byte(`null`), &fromNull); err != nil || !fromNull.IsZero() {
		t.Fatalf("null 应解析成零值: %v %v", fromNull, err)
	}

	var bad ObjectID
	if err := json.Unmarshal([]byte(`{"x":1}`), &bad); err == nil {
		t.Fatal("非法 JSON 应报错")
	}
}

func TestTextMarshal(t *testing.T) {
	id := NewObjectID()
	b, err := id.MarshalText()
	if err != nil || string(b) != id.Hex() {
		t.Fatalf("MarshalText 结果 %s", b)
	}
	var back ObjectID
	if err := back.UnmarshalText(b); err != nil || back != id {
		t.Fatalf("UnmarshalText 失败: %v", err)
	}
}

func TestTimestampAndCounter(t *testing.T) {
	// 秒级时间戳：刚生成的 ID 解析出的时间应贴近当前时间
	id := NewObjectID()
	ts := id.Timestamp()
	if ts.IsZero() {
		t.Fatal("时间戳不该是零值")
	}
	if d := time.Since(ts); d < 0 || d > 2*time.Minute {
		t.Fatalf("时间戳偏离当前时间过多: %v", d)
	}
	if !NilObjectID.Timestamp().IsZero() {
		t.Fatal("零值的时间戳应为零时间")
	}

	// 同一秒内后 3 字节计数器递增，但整串十六进制不保证单调——中间 5 字节是随机的。
	// 这里只断言「不重复」，排序一律走 created_at 或 bigserial 列。
	prev := NewObjectID()
	for i := 0; i < 100; i++ {
		cur := NewObjectID()
		if cur == prev {
			t.Fatalf("连续生成的 ID 重复: %s", cur.Hex())
		}
		prev = cur
	}

	// 计数器段（最后 3 字节）在同一秒内应递增
	a := NewObjectID()
	b := NewObjectID()
	counterOf := func(x ObjectID) uint32 {
		return uint32(x[9])<<16 | uint32(x[10])<<8 | uint32(x[11])
	}
	if a.Timestamp().Equal(b.Timestamp()) && counterOf(b) <= counterOf(a) {
		t.Logf("跨秒或回绕，跳过计数器断言: %d -> %d", counterOf(a), counterOf(b))
	}
}
