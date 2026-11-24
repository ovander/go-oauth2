package middleware

import (
	"context"
	"testing"
	"time"
)

// An exempt address is never treated as blocked, even with a block stored or
// cached for it (one created before such blocks were refused); any other
// address is still checked.
func TestIPBlockChecker_ExemptAddressIsNeverBlocked(t *testing.T) {
	c := newBareChecker(&stubBlockedIPRepo{isBlockedResult: true})
	setCacheEntry(c, "127.0.0.1", cacheEntry{blocked: true, expiresAt: time.Now().Add(time.Minute)})
	c.SetExempt(func(ip string) bool { return ip == "127.0.0.1" })

	if blocked, err := c.IsBlocked(context.Background(), "127.0.0.1"); blocked || err != nil {
		t.Fatalf("exempt address: blocked=%v err=%v, want not blocked", blocked, err)
	}
	if blocked, err := c.IsBlocked(context.Background(), "198.51.100.9"); !blocked || err != nil {
		t.Fatalf("other address: blocked=%v err=%v, want blocked", blocked, err)
	}
}
