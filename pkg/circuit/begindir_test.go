package circuit

import (
	"testing"
)

func TestTryCompleteHTTPBody(t *testing.T) {
	raw := []byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
	body, ok, err := tryCompleteHTTPBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected complete")
	}
	if string(body) != "hello" {
		t.Fatalf("body=%q", body)
	}
	if _, ok, err := tryCompleteHTTPBody([]byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhel")); err != nil || ok {
		t.Fatal("incomplete should be false without error")
	}
	_, ok, err = tryCompleteHTTPBody([]byte("HTTP/1.0 503 Unavailable\r\nContent-Length: 4\r\n\r\nfail"))
	if err == nil {
		t.Fatal("non-200 with full body must error")
	}
	if ok {
		t.Fatal("non-200 must not complete successfully")
	}
}

func TestParseHTTPResponseBody(t *testing.T) {
	raw := []byte("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nabcd")
	body, err := parseHTTPResponseBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "abcd" {
		t.Fatalf("%q", body)
	}
	_, err = parseHTTPResponseBody([]byte("HTTP/1.0 404 Not Found\r\n\r\n"))
	if err == nil {
		t.Fatal("404 must fail")
	}
}
