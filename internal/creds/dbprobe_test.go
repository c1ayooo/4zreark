package creds

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// fakeRedis starts a one-connection RESP server that answers AUTH/PING/INFO
// according to mode: "open" (no auth), "noauth" (PING -> NOAUTH), "auth-ok",
// "auth-bad".
func fakeRedis(t *testing.T, mode string) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			cmd, err := readRESPCommand(br)
			if err != nil {
				return
			}
			if len(cmd) == 0 {
				return
			}
			switch strings.ToUpper(cmd[0]) {
			case "AUTH":
				if mode == "auth-ok" {
					_, _ = conn.Write([]byte("+OK\r\n"))
				} else {
					_, _ = conn.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
				}
			case "PING":
				if mode == "noauth" {
					_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
				} else {
					_, _ = conn.Write([]byte("+PONG\r\n"))
				}
			case "INFO":
				_, _ = conn.Write([]byte("$29\r\n# Server\r\nredis_version:7.0.0\r\n\r\n"))
			default:
				_, _ = conn.Write([]byte("+OK\r\n"))
			}
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func readRESPCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "*") {
		return nil, io.ErrUnexpectedEOF
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sizeLine = strings.TrimSpace(sizeLine)
		if !strings.HasPrefix(sizeLine, "$") {
			return nil, io.ErrUnexpectedEOF
		}
		size, err := strconv.Atoi(sizeLine[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		out = append(out, string(buf[:size]))
	}
	return out, nil
}

func TestVerifyRedisNOAUTHIsNotAuthed(t *testing.T) {
	host, port := fakeRedis(t, "noauth")
	res, err := VerifyDB(context.Background(), DBProbeInput{Type: "redis", Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive {
		t.Fatalf("alive=false, detail=%s", res.Detail)
	}
	if res.Authed {
		t.Fatalf("NOAUTH must not be reported as authed: %+v", res)
	}
	if !strings.Contains(res.Detail, "NOAUTH") {
		t.Fatalf("detail should expose NOAUTH: %s", res.Detail)
	}
}

func TestVerifyRedisOpenInstanceIsAuthedButNotCredential(t *testing.T) {
	host, port := fakeRedis(t, "open")
	res, err := VerifyDB(context.Background(), DBProbeInput{Type: "redis", Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || !res.Authed {
		t.Fatalf("open redis should be alive/usable: %+v", res)
	}
	if res.Version != "7.0.0" {
		t.Fatalf("version=%q", res.Version)
	}
	if !strings.Contains(res.Detail, "未授权") {
		t.Fatalf("open redis must be flagged as unauthorized: %s", res.Detail)
	}
}

func TestVerifyRedisAuthOK(t *testing.T) {
	host, port := fakeRedis(t, "auth-ok")
	res, err := VerifyDB(context.Background(), DBProbeInput{
		Type: "redis", Host: host, Port: port, Password: "s3cret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || !res.Authed || res.Version != "7.0.0" {
		t.Fatalf("auth-ok result: %+v", res)
	}
}

func TestVerifyRedisWrongPasswordIsNotAuthed(t *testing.T) {
	host, port := fakeRedis(t, "auth-bad")
	res, err := VerifyDB(context.Background(), DBProbeInput{
		Type: "redis", Host: host, Port: port, Password: "bad",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Alive || res.Authed {
		t.Fatalf("wrong password must not be authed: %+v", res)
	}
	if !strings.Contains(res.Detail, "AUTH 失败") {
		t.Fatalf("detail: %s", res.Detail)
	}
}
