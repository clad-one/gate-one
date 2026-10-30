package proxy

import (
	"fmt"
	"sync"
	"testing"
)

// TestAuthCacheConcurrentAccounting hammers the identity cache from
// several goroutines. Under -race it guards the size counter (the
// phase 4.5 load test found it unsynchronised) and the expired-entry
// purge path.
func TestAuthCacheConcurrentAccounting(t *testing.T) {
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	const goroutines = 16
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				key := fmt.Sprintf("%d-%d", g, i)
				cacheAuth(key, &RequestContext{
					UserID:   "user",
					Username: "user",
				})
				if _, ok := cachedAuth(key); !ok {
					t.Errorf("cache miss for freshly stored key %q", key)
				}
				deleteAuth(key)
			}
		}(g)
	}
	wg.Wait()

	if got := authCacheSize.Load(); got != 0 {
		t.Fatalf("authCacheSize = %d after balanced stores/deletes", got)
	}
}
