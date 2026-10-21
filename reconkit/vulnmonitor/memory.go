package vulnmonitor

import (
	"context"
	"sync"
)

// MemoryStore is a concurrency-safe in-memory Store for tests and small tools.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]Intel
	order []string
}

// NewMemoryStore creates an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: map[string]Intel{}}
}

// UpsertIntel inserts or replaces by UniqueKey.
func (s *MemoryStore) UpsertIntel(_ context.Context, intel Intel) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.items[intel.UniqueKey]
	s.items[intel.UniqueKey] = intel
	if !exists {
		s.order = append(s.order, intel.UniqueKey)
	}
	return !exists, nil
}

// Items returns a stable-order copy.
func (s *MemoryStore) Items() []Intel {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Intel, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, s.items[key])
	}
	return out
}

// Len returns the number of stored records.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}
