package domain

import "testing"

func TestStateMachine(t *testing.T) {
	states := []State{Queued, Sending, RetryWait, Submitted, Failed, Unknown, Cancelled}
	valid := map[[2]State]bool{{Queued, Sending}: true, {Queued, Cancelled}: true, {Queued, Failed}: true, {RetryWait, Sending}: true, {RetryWait, Cancelled}: true, {RetryWait, Failed}: true, {Sending, Submitted}: true, {Sending, RetryWait}: true, {Sending, Failed}: true, {Sending, Unknown}: true}
	for _, from := range states {
		for _, to := range states {
			if CanTransition(from, to) != valid[[2]State{from, to}] {
				t.Fatalf("invalid transition rule %s -> %s", from, to)
			}
		}
	}
}
func TestSelectionStrategy(t *testing.T) {
	a, ok := (LeastRecentlyUsed{}).Select([]Account{{ID: "b", LastUsed: 10}, {ID: "a", LastUsed: 10}, {ID: "c", LastUsed: 20}})
	if !ok || a.ID != "a" {
		t.Fatal("unstable selection")
	}
	if _, ok = (LeastRecentlyUsed{}).Select(nil); ok {
		t.Fatal("selected empty candidate")
	}
}
