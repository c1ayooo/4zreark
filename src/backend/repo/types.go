package repo

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/oid"
)

// 类型映射集中在这里，对应交接规格 §4：
//   oid.ObjectID → char(24)
//   time.Time 零值     → NULL
//   []string           → text[]
//   map[string]interface{} / 结构体     → jsonb

// idFromString 校验并解析 24 位十六进制 ID。
func idFromString(s string) (oid.ObjectID, error) {
	return oid.ObjectIDFromHex(s)
}

// ValidID 供 service 层校验路径参数，避免把 mongo 的 primitive 类型带进上层。
func ValidID(s string) bool {
	_, err := idFromString(s)
	return err == nil
}

// timeToPG 把零值时间转成 NULL，避免写库报错或落成 0001-01-01。
func timeToPG(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// timeFromPG 把可能为 NULL 的列还原成零值时间。
func timeFromPG(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// textArray 把空切片统一成 {}，不写 NULL。
func textArray(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// ParseID 把 24 位十六进制串解析成 ObjectID。服务层做模型映射时需要它，
// 由 repo 包出面，避免上层 import mongo 的 primitive。
func ParseID(s string) (oid.ObjectID, error) {
	return idFromString(s)
}

// jsonUnmarshal 解析 jsonb 列。
func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}

// timeOrNow 零值时间落成当前时间。
func timeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t.UTC()
}

// boolValue 处理 enabled / installed 这类布尔列。
func boolValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case bool:
		return x, nil
	case string:
		return x == "true" || x == "1", nil
	case float64:
		return x != 0, nil
	default:
		return nil, fmt.Errorf("无法转成 boolean: %T", v)
	}
}

// intValue 处理 intel_id 这类 bigint 列，空值落成 NULL。
func intValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case int:
		if x == 0 {
			return nil, nil
		}
		return int64(x), nil
	case int64:
		if x == 0 {
			return nil, nil
		}
		return x, nil
	case float64:
		return int64(x), nil
	default:
		return nil, fmt.Errorf("无法转成 bigint: %T", v)
	}
}

// jsonb 把结构体序列化成 jsonb 列的值，nil 落成 {}。
func jsonb(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || string(b) == "null" {
		return []byte("{}"), nil
	}
	return b, nil
}
