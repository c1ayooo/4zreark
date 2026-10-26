// Package oid 提供 24 位十六进制形态的对象 ID。
//
// 这套 ID 是迁移前 Mongo 时代留下的契约：前后端、URL、库里 char(24) 列全部按
// 「24 位小写十六进制字符串」交换。数据层换成 PostgreSQL 之后 ID 本身没有变，
// 所以这里只需要一个 12 字节的值类型 + 十六进制编解码，不再依赖 Mongo 驱动。
//
// 与 mongo-driver 的 primitive.ObjectID 行为保持一致的几个点（改动会影响线上响应）：
//   - JSON 序列化成带引号的 24 位十六进制串，零值序列化成 24 个 '0'
//   - 反序列化同时接受 "hex" 与 {"$oid": "hex"} 两种写法
//   - ObjectIDFromHex("") 返回零值且不报错
//   - 生成时前 4 字节放秒级时间戳、后 3 字节放进程内计数器，中间 5 字节随机
package oid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// ObjectID 是 12 字节的 ID。
type ObjectID [12]byte

// NilObjectID 是零值 ID。
var NilObjectID ObjectID

const hexLength = 24

// 进程内自增计数器，同一秒内生成多个 ID 时保证有序且不重复。
var counter uint32

func init() {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		counter = binary.BigEndian.Uint32(b[:])
	} else {
		counter = uint32(time.Now().UnixNano())
	}
}

// NewObjectID 生成一个新的 ID：4 字节时间戳 + 5 字节随机 + 3 字节计数器。
// 布局与 Mongo 的 ObjectID 相同，所以「按时间取」只能靠前 4 字节（Timestamp()），
// 不要指望整串十六进制严格单调——中间 5 字节是随机的。
// 库内需要时间序的地方一律用 created_at 或 bigserial 列排序。
func NewObjectID() ObjectID {
	var id ObjectID
	binary.BigEndian.PutUint32(id[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(id[4:9]); err != nil {
		// 随机源不可用时退化成计数器填充，仍保证唯一性
		n := atomic.AddUint32(&counter, 1)
		binary.BigEndian.PutUint32(id[4:8], n)
	}
	n := atomic.AddUint32(&counter, 1)
	id[9] = byte(n >> 16)
	id[10] = byte(n >> 8)
	id[11] = byte(n)
	return id
}

// ObjectIDFromHex 从 24 位十六进制串解析 ID。空串返回零值且不报错。
func ObjectIDFromHex(s string) (ObjectID, error) {
	if len(s) == 0 {
		return NilObjectID, nil
	}
	if len(s) != hexLength {
		return NilObjectID, fmt.Errorf("invalid ObjectID %q: 长度必须是 %d", s, hexLength)
	}
	var id ObjectID
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return NilObjectID, fmt.Errorf("invalid ObjectID %q: %w", s, err)
	}
	return id, nil
}

// MustObjectIDFromHex 只在确定合法的场景（如常量）使用。
func MustObjectIDFromHex(s string) ObjectID {
	id, err := ObjectIDFromHex(s)
	if err != nil {
		panic(err)
	}
	return id
}

// Hex 返回 24 位小写十六进制串。
func (id ObjectID) Hex() string {
	buf := make([]byte, hexLength)
	hex.Encode(buf, id[:])
	return string(buf)
}

// String 与 Hex 等价，便于 fmt/log 直接打印。
func (id ObjectID) String() string { return id.Hex() }

// IsZero 判断是否为零值。
func (id ObjectID) IsZero() bool { return id == NilObjectID }

// Timestamp 返回 ID 内嵌的秒级时间戳（零值返回零时间）。
func (id ObjectID) Timestamp() time.Time {
	if id.IsZero() {
		return time.Time{}
	}
	return time.Unix(int64(binary.BigEndian.Uint32(id[0:4])), 0)
}

// ---------- JSON ----------

// MarshalJSON 输出带引号的十六进制串，与旧实现一致。
func (id ObjectID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.Hex())
}

// UnmarshalJSON 接受 "hex" 与 {"$oid": "hex"} 两种写法。
func (id *ObjectID) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*id = NilObjectID
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		parsed, err := ObjectIDFromHex(s)
		if err != nil {
			return err
		}
		*id = parsed
		return nil
	}
	var ext struct {
		OID string `json:"$oid"`
	}
	if err := json.Unmarshal(data, &ext); err != nil || ext.OID == "" {
		return errors.New("invalid ObjectID: 既不是字符串也不是 {\"$oid\": ...}")
	}
	parsed, err := ObjectIDFromHex(ext.OID)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// MarshalText 让 ID 能直接用于模板与文本协议。
func (id ObjectID) MarshalText() ([]byte, error) { return []byte(id.Hex()), nil }

// UnmarshalText 与 UnmarshalJSON 的字符串分支等价。
func (id *ObjectID) UnmarshalText(b []byte) error {
	parsed, err := ObjectIDFromHex(string(b))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
