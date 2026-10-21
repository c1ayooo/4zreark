package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 注册码：生成、一次性/多次消费、过期拒绝、事务回滚、批量删除。
func TestRegistrationCodes(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := service.NewRegistrationService()
	users := service.NewUserService()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	codes, err := svc.Generate(ctx, 2, "operator", 1, nil, "tester")
	if err != nil || len(codes) != 2 {
		t.Fatalf("生成注册码失败: %v %v", codes, err)
	}
	created := append([]string{}, codes...)
	t.Cleanup(func() {
		_, _ = svc.DeleteBatch(context.Background(), created)
		_, _ = r.Pool().Exec(context.Background(),
			`delete from users where username like $1`, "reg-"+suffix+"%")
	})

	u1, err := users.RegisterWithCode("reg-"+suffix+"-a", "Passw0rd!", "reg-"+suffix+"-a@example.test", codes[0])
	if err != nil {
		t.Fatalf("用注册码注册失败: %v", err)
	}
	if u1.Role != "operator" {
		t.Fatalf("注册码角色未生效: %s", u1.Role)
	}
	// 一次性注册码第二次应失败
	if _, err := users.RegisterWithCode("reg-"+suffix+"-b", "Passw0rd!", "reg-"+suffix+"-b@example.test", codes[0]); err == nil {
		t.Fatal("一次性注册码不应可重复使用")
	}

	// 多次注册码
	multi, err := svc.Generate(ctx, 1, "viewer", 2, nil, "tester")
	if err != nil {
		t.Fatalf("生成多次注册码失败: %v", err)
	}
	created = append(created, multi...)
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("reg-%s-m%d", suffix, i)
		if _, err := users.RegisterWithCode(name, "Passw0rd!", name+"@example.test", multi[0]); err != nil {
			t.Fatalf("第 %d 次注册失败: %v", i+1, err)
		}
	}
	if _, err := users.RegisterWithCode("reg-"+suffix+"-m9", "Passw0rd!", "reg-"+suffix+"-m9@example.test", multi[0]); err == nil {
		t.Fatal("超过 max_uses 后应失败")
	}

	// 过期注册码：直接用 repo 写入过去时间
	rr := r.RegistrationCodes()
	expired := "zc_expired_" + suffix
	past := time.Now().Add(-time.Hour)
	if err := rr.Create(ctx, expired, "user", 1, &past, "tester"); err != nil {
		t.Fatalf("写入过期注册码失败: %v", err)
	}
	created = append(created, expired)
	if _, err := users.RegisterWithCode("reg-"+suffix+"-x", "Passw0rd!", "reg-"+suffix+"-x@example.test", expired); err == nil {
		t.Fatal("过期注册码应被拒绝")
	}

	list, err := svc.List(ctx, 50)
	if err != nil || len(list) == 0 {
		t.Fatalf("列表失败: %v", err)
	}
	n, err := svc.DeleteBatch(ctx, []string{multi[0], expired})
	if err != nil || n != 2 {
		t.Fatalf("批量删除不符: n=%d err=%v", n, err)
	}
}
