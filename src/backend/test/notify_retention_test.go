package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 站内通知纳入保留策略：老通知被清、新通知保留、已读状态随 CASCADE 消失。
func TestNotificationRetention(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	notify := r.Notify()
	oldID, err := notify.AddNotification(ctx, "info", "retention-old", "old", "test", nil)
	if err != nil {
		t.Fatalf("写入老通知失败: %v", err)
	}
	freshID, err := notify.AddNotification(ctx, "info", "retention-fresh", "fresh", "test", nil)
	if err != nil {
		t.Fatalf("写入新通知失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM notifications WHERE id = ANY($1)`, []int64{oldID, freshID})
	})

	// 把老通知的 created_at 回拨到 31 天前，并把 fresh 标为已读以验证 CASCADE。
	if _, err := r.Pool().Exec(ctx,
		`UPDATE notifications SET created_at = now() - interval '31 days' WHERE id = $1`, oldID); err != nil {
		t.Fatal(err)
	}
	if err := notify.MarkRead(ctx, "retention-test-user", freshID); err != nil {
		t.Fatal(err)
	}

	if n, err := r.RetentionCount(ctx, "notifications", 30); err != nil {
		t.Fatalf("RetentionCount 失败: %v", err)
	} else if n < 1 {
		t.Fatalf("应至少统计到 1 条 30 天前通知, got %d", n)
	}

	purged, err := notify.PurgeNotifications(ctx, 30, 1000)
	if err != nil {
		t.Fatalf("PurgeNotifications 失败: %v", err)
	}
	if purged < 1 {
		t.Fatalf("应至少清除 1 条老通知, got %d", purged)
	}

	var exists bool
	if err := r.Pool().QueryRow(ctx,
		`SELECT exists (SELECT 1 FROM notifications WHERE id = $1)`, oldID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("老通知应已被删除")
	}
	if err := r.Pool().QueryRow(ctx,
		`SELECT exists (SELECT 1 FROM notifications WHERE id = $1)`, freshID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("新通知不应被删除")
	}
	var reads int64
	if err := r.Pool().QueryRow(ctx,
		`SELECT count(*) FROM notification_reads WHERE notification_id = $1`, freshID).Scan(&reads); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("新通知的已读状态应保留, got %d", reads)
	}
}

// days<=0 时 Purge 是 no-op：保留策略把 NotificationsDays 配 0 即关闭清理。
func TestNotificationPurgeZeroDaysNoop(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	id, err := r.Notify().AddNotification(ctx, "info", "retention-noop", "x", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM notifications WHERE id = $1`, id)
	})
	if _, err := r.Pool().Exec(ctx,
		`UPDATE notifications SET created_at = now() - interval '400 days' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	purged, err := r.Notify().PurgeNotifications(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if purged != 0 {
		t.Fatalf("days=0 应为 no-op, purged=%d", purged)
	}

	p := service.DefaultRetentionPolicy()
	if p.NotificationsDays != 30 {
		t.Fatalf("默认通知保留期 = %d, want 30", p.NotificationsDays)
	}
}
