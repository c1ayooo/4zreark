package repo

import (
	"encoding/json"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 类型映射集中在这里，对应交接规格 §4：
//   primitive.ObjectID → char(24)
//   time.Time 零值     → NULL
//   []string           → text[]
//   bson.M / 结构体     → jsonb

// idFromString 校验并解析 24 位十六进制 ID。
func idFromString(s string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(s)
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
