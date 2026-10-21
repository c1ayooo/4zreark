package service

import "testing"

func TestBudgetDailyTargets(t *testing.T) {
	cases := []struct {
		budget map[string]any
		want   int
	}{
		{map[string]any{"daily_targets": float64(100)}, 100},
		{map[string]any{"max_targets_per_day": "50"}, 50},
		{map[string]any{"daily": int64(10)}, 10},
		{map[string]any{}, 0},
		{map[string]any{"daily_targets": "bad"}, 0},
	}
	for _, c := range cases {
		if got := budgetDailyTargets(c.budget); got != c.want {
			t.Fatalf("budgetDailyTargets(%v)=%d，期望 %d", c.budget, got, c.want)
		}
	}
}
