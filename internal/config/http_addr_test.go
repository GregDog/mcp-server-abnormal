package config

import "testing"

func TestIsLoopbackHTTPAddr(t *testing.T) {
	if !IsLoopbackHTTPAddr("127.0.0.1:8090") {
		t.Fatal("expected loopback")
	}
	if IsLoopbackHTTPAddr("0.0.0.0:8090") {
		t.Fatal("expected non-loopback")
	}
	if IsLoopbackHTTPAddr(":8090") {
		t.Fatal("expected non-loopback for bare port")
	}
}
