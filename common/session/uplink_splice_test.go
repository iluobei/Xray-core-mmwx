package session

import (
	"testing"
	"time"
)

func TestUplinkSpliceWait(t *testing.T) {
	u := &UplinkSplice{}
	if !u.Wait(0, nil) {
		t.Fatal("nothing owed: Wait must return at once")
	}
	done := make(chan bool, 1)
	go func() { done <- u.Wait(10, nil) }()
	u.Wrote(4)
	select {
	case <-done:
		t.Fatal("Wait returned before all 10 bytes were written")
	case <-time.After(50 * time.Millisecond):
	}
	u.Wrote(6)
	if !<-done {
		t.Fatal("Wait = false after all bytes were written")
	}
	u.Spliced(5)
	if !u.Wait(15, nil) {
		t.Fatal("spliced bytes not counted")
	}

	go func() { done <- u.Wait(100, nil) }()
	time.Sleep(20 * time.Millisecond)
	u.Close()
	if <-done {
		t.Fatal("Wait = true after Close")
	}
	if tc, _, _ := u.Target(); tc != nil {
		t.Fatal("Target after Close")
	}

	v := &UplinkSplice{}
	cancel := make(chan struct{})
	go func() { done <- v.Wait(1, cancel) }()
	close(cancel)
	if <-done {
		t.Fatal("Wait = true after cancel")
	}
}
