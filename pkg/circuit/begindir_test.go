package circuit

import (
	"testing"
)

func TestTryCompleteHTTPBody(t *testing.T) {
	raw := []byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
	body, ok := tryCompleteHTTPBody(raw)
	if !ok {
		t.Fatal("expected complete")
	}
	if string(body) != "hello" {
		t.Fatalf("body=%q", body)
	}
	if _, ok := tryCompleteHTTPBody([]byte("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhel")); ok {
		t.Fatal("incomplete should be false")
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
