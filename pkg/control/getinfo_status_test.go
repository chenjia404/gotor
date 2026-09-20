package control

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestLongName(t *testing.T) {
	fp := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	got := LongName(fp, "moria1")
	want := "$AABBCCDDEEFF00112233445566778899AABBCCDD~moria1"
	if got != want {
		t.Fatalf("%s", got)
	}
	if LongName("hs-rendezvous", "x") != "" {
		t.Fatal("non-hex hop must not become LongName")
	}
	if LongName("$"+strings.ToLower(fp), "") != "$"+fp {
		t.Fatal("hex case")
	}
}

func TestFormatCircuitStatusLine(t *testing.T) {
	created := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	got := FormatCircuitStatusLine(7, "BUILT", "$AABBCCDDEEFF00112233445566778899AABBCCDD~g", "NEED_CAPACITY", "GENERAL", created)
	if !strings.HasPrefix(got, "7 BUILT $AABBCCDDEEFF00112233445566778899AABBCCDD~g BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2024-01-01T12:00:00.000000") {
		t.Fatalf("%s", got)
	}
}

func TestGetInfoCircuitStatusPlusData(t *testing.T) {
	server, mock := setupTestServer(t)
	mock.circuitStatus = "1 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~a,$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~b BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2024-01-01T12:00:00.000000\n2 BUILT $CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC~c BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL PURPOSE=GENERAL TIME_CREATED=2024-01-01T12:00:01.000000"
	conn := connectToServer(t, server)
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	readResponse(t, reader)
	writer.WriteString("AUTHENTICATE\r\n")
	writer.Flush()
	readResponse(t, reader)
	writer.WriteString("GETINFO circuit-status\r\n")
	writer.Flush()
	header := readResponse(t, reader)
	if header != "250+circuit-status=" {
		t.Fatalf("header %s", header)
	}
	var body []string
	for {
		line := readResponse(t, reader)
		if line == "." {
			break
		}
		body = append(body, line)
	}
	if len(body) != 2 || !strings.HasPrefix(body[0], "1 BUILT ") || !strings.HasPrefix(body[1], "2 BUILT ") {
		t.Fatalf("%q", body)
	}
}

func TestGetInfoNSByID(t *testing.T) {
	server, mock := setupTestServer(t)
	fp := "AABBCCDDEEFF00112233445566778899AABBCCDD"
	mock.nsByID = map[string]string{
		fp: "r TestRelay AAAAAAAAAAAAAAAAAAAAAA 2038-01-01 00:00:00 192.0.2.1 9001 0\ns Fast Running Valid\nw Bandwidth=100",
	}
	conn := connectToServer(t, server)
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	readResponse(t, reader)
	writer.WriteString("AUTHENTICATE\r\n")
	writer.Flush()
	readResponse(t, reader)
	writer.WriteString("GETINFO ns/id/$" + fp + "\r\n")
	writer.Flush()
	header := readResponse(t, reader)
	if header != "250+ns/id/$"+fp+"=" {
		t.Fatalf("header %s", header)
	}
	var body []string
	for {
		line := readResponse(t, reader)
		if line == "." {
			break
		}
		body = append(body, line)
	}
	joined := strings.Join(body, "\n")
	if !strings.HasPrefix(joined, "r TestRelay ") || !strings.Contains(joined, "s Fast Running Valid") {
		t.Fatalf("%s", joined)
	}

	writer.WriteString("GETINFO ns/id/$FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n")
	writer.Flush()
	miss := readResponse(t, reader)
	if !strings.HasPrefix(miss, "551 ") {
		t.Fatalf("missing ns/id should be 551: %s", miss)
	}
}

func TestGetInfoDescByIDUnavailable(t *testing.T) {
	server, _ := setupTestServer(t)
	conn := connectToServer(t, server)
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	readResponse(t, reader)
	writer.WriteString("AUTHENTICATE\r\n")
	writer.Flush()
	readResponse(t, reader)
	writer.WriteString("GETINFO desc/id/$AABBCCDDEEFF00112233445566778899AABBCCDD\r\n")
	writer.Flush()
	got := readResponse(t, reader)
	if !strings.HasPrefix(got, "551 ") || !strings.Contains(got, "Descriptor is not available") {
		t.Fatalf("desc/id 无 server descriptor 应为 551: %s", got)
	}
}
