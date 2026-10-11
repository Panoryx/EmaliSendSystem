package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestMessageFilterValidation(t *testing.T) {
	for _, tc := range []struct {
		query string
		valid bool
	}{
		{"", true}, {"status=queued", true}, {"status=cancelled&created_from=1&created_to=1", true},
		{"id=0123456789abcdef0123456789abcdef", true},
		{"status=invalid", false}, {"id=bad", false}, {"id=%27%20OR%201=1--", false},
		{"created_from=-1", false}, {"created_to=abc", false}, {"created_from=2&created_to=1", false},
		{"created_to=0", false}, {"created_to=999999999999999999999", false},
	} {
		t.Run(tc.query, func(t *testing.T) {
			_, err := messageFilter(httptest.NewRequest("GET", "/api/v1/messages?"+tc.query, nil))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, got %v", tc.valid, err)
			}
		})
	}
}
