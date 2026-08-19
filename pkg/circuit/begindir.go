// Package circuit — RELAY_BEGIN_DIR 与经 ORPort 的目录 HTTP 拉取。
//
// 对照 tor-spec opening-streams：BEGIN_DIR 空载荷；成功回 CONNECTED 空载荷；
// 随后用 RELAY_DATA 传 HTTP/1.0 请求与响应。
package circuit

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// OpenDirStream 在本电路上打开目录流（RELAY_BEGIN_DIR）。
// 载荷必须为空；对端若非目录服务则回 RELAY_END REASON_NOTDIRECTORY。
func (c *Circuit) OpenDirStream(ctx context.Context, streamID uint16) error {
	if streamID == 0 {
		return fmt.Errorf("BEGIN_DIR stream ID must be non-zero")
	}
	beginCell, err := cell.NewRelayCell(streamID, cell.RelayBeginDir, nil)
	if err != nil {
		return fmt.Errorf("create BEGIN_DIR: %w", err)
	}
	if err := c.SendRelayCell(beginCell); err != nil {
		return fmt.Errorf("send BEGIN_DIR: %w", err)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		rc, err := c.ReceiveRelayCell(timeoutCtx)
		if err != nil {
			return fmt.Errorf("wait CONNECTED after BEGIN_DIR: %w", err)
		}
		if rc.StreamID != streamID {
			_ = c.deliverToStream(rc)
			continue
		}
		switch rc.Command {
		case cell.RelayConnected:
			return nil
		case cell.RelayEnd:
			reason := byte(0)
			if len(rc.Data) > 0 {
				reason = rc.Data[0]
			}
			return fmt.Errorf("BEGIN_DIR rejected: RELAY_END reason=%d", reason)
		default:
			continue
		}
	}
}

// HTTPGetViaBeginDir 经已打开的目录流发送 HTTP/1.0 GET 并读完整响应体。
// 调用前须已 OpenDirStream；结束后发送 RELAY_END。
func (c *Circuit) HTTPGetViaBeginDir(ctx context.Context, streamID uint16, host, path string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Tor\r\nAccept-Encoding: identity\r\n\r\n", path, host)
	if err := c.WriteToStream(streamID, []byte(req)); err != nil {
		_ = c.EndStream(streamID, 6) // DONE
		return nil, fmt.Errorf("write HTTP request: %w", err)
	}

	var raw bytes.Buffer
	for {
		select {
		case <-ctx.Done():
			_ = c.EndStream(streamID, 7) // TIMEOUT
			return nil, ctx.Err()
		default:
		}
		chunk, err := c.ReadFromStream(ctx, streamID)
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = c.EndStream(streamID, 1)
			return nil, err
		}
		raw.Write(chunk)
		// 若已有完整 HTTP 头且 Content-Length 满足则提前结束
		body, done, err := tryCompleteHTTPBody(raw.Bytes())
		if err != nil {
			_ = c.EndStream(streamID, 1)
			return nil, err
		}
		if done {
			_ = c.EndStream(streamID, 6)
			return body, nil
		}
		if raw.Len() > 8<<20 { // 8 MiB（共识可超过 2 MiB）
			_ = c.EndStream(streamID, 1)
			return nil, fmt.Errorf("directory response exceeds 8 MiB")
		}
	}
	_ = c.EndStream(streamID, 6)
	body, err := parseHTTPResponseBody(raw.Bytes())
	if err != nil {
		return nil, err
	}
	return body, nil
}

// FetchHTTPViaBeginDir 打开目录流、GET、关闭；封装完整一次拉取。
func (c *Circuit) FetchHTTPViaBeginDir(ctx context.Context, host, path string) ([]byte, error) {
	sid, err := c.AllocateStreamID()
	if err != nil {
		return nil, err
	}
	defer c.ReleaseStreamID(sid)

	if err := c.OpenDirStream(ctx, sid); err != nil {
		return nil, err
	}
	return c.HTTPGetViaBeginDir(ctx, sid, host, path)
}

// HTTPPostViaBeginDir 经目录流发送 HTTP/1.0 POST 并读响应体。
func (c *Circuit) HTTPPostViaBeginDir(ctx context.Context, streamID uint16, host, path string, body []byte) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := fmt.Sprintf("POST %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Tor\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nAccept-Encoding: identity\r\n\r\n",
		path, host, len(body))
	payload := append([]byte(req), body...)
	if err := c.WriteToStream(streamID, payload); err != nil {
		_ = c.EndStream(streamID, 6)
		return nil, fmt.Errorf("write HTTP POST: %w", err)
	}

	var raw bytes.Buffer
	for {
		select {
		case <-ctx.Done():
			_ = c.EndStream(streamID, 7)
			return nil, ctx.Err()
		default:
		}
		chunk, err := c.ReadFromStream(ctx, streamID)
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = c.EndStream(streamID, 1)
			return nil, err
		}
		raw.Write(chunk)
		bodyOut, done, err := tryCompleteHTTPBody(raw.Bytes())
		if err != nil {
			_ = c.EndStream(streamID, 1)
			return nil, err
		}
		if done {
			_ = c.EndStream(streamID, 6)
			return bodyOut, nil
		}
		if raw.Len() > 8<<20 {
			_ = c.EndStream(streamID, 1)
			return nil, fmt.Errorf("directory response exceeds 8 MiB")
		}
	}
	_ = c.EndStream(streamID, 6)
	return parseHTTPResponseBody(raw.Bytes())
}

// PostHTTPViaBeginDir 打开目录流、POST、关闭。
func (c *Circuit) PostHTTPViaBeginDir(ctx context.Context, host, path string, body []byte) ([]byte, error) {
	sid, err := c.AllocateStreamID()
	if err != nil {
		return nil, err
	}
	defer c.ReleaseStreamID(sid)
	if err := c.OpenDirStream(ctx, sid); err != nil {
		return nil, err
	}
	return c.HTTPPostViaBeginDir(ctx, sid, host, path, body)
}

func tryCompleteHTTPBody(raw []byte) ([]byte, bool, error) {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, false, nil
	}
	headers := string(raw[:headerEnd])
	statusLine := headers
	if i := strings.Index(headers, "\r\n"); i >= 0 {
		statusLine = headers[:i]
	}
	parts := strings.Fields(statusLine)
	statusOK := false
	for _, p := range parts {
		if p == "200" {
			statusOK = true
			break
		}
	}
	body := raw[headerEnd+4:]
	cl := httpContentLength(headers)
	if cl < 0 {
		return nil, false, nil // 无 Content-Length，等 END
	}
	if len(body) < cl {
		return nil, false, nil
	}
	if !statusOK {
		return nil, false, fmt.Errorf("directory HTTP status: %s", strings.TrimSpace(statusLine))
	}
	return body[:cl], true, nil
}

func parseHTTPResponseBody(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty directory HTTP response")
	}
	br := bufio.NewReader(bytes.NewReader(raw))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		// 宽松：若已有 \r\n\r\n 则取其后为 body
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			statusLine := string(raw[:bytes.IndexByte(raw, '\n')])
			if !strings.Contains(statusLine, "200") {
				return nil, fmt.Errorf("directory HTTP status: %s", strings.TrimSpace(statusLine))
			}
			return raw[i+4:], nil
		}
		return nil, fmt.Errorf("parse HTTP response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory HTTP status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func httpContentLength(headers string) int {
	for _, line := range strings.Split(headers, "\r\n") {
		if len(line) >= 15 && strings.EqualFold(line[:15], "Content-Length:") {
			n, err := strconv.Atoi(strings.TrimSpace(line[15:]))
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}
