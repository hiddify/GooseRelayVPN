package frame

import (
	"bytes"
	"testing"
)

func sid(b byte) [SessionIDLen]byte {
	var out [SessionIDLen]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestFrameRoundTrip_DataOnly(t *testing.T) {
	in := &Frame{
		SessionID: sid(0xAA),
		Seq:       42,
		Payload:   []byte("hello world"),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, n, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("n=%d want %d", n, len(raw))
	}
	if out.SessionID != in.SessionID {
		t.Fatalf("sid mismatch")
	}
	if out.Seq != in.Seq {
		t.Fatalf("seq=%d want %d", out.Seq, in.Seq)
	}
	if out.Flags != 0 {
		t.Fatalf("flags=%d want 0", out.Flags)
	}
	if out.Target != "" {
		t.Fatalf("target=%q want empty", out.Target)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: %q vs %q", out.Payload, in.Payload)
	}
}

func TestFrameRoundTrip_SYN(t *testing.T) {
	in := &Frame{
		SessionID: sid(0x01),
		Seq:       0,
		Flags:     FlagSYN,
		Target:    "example.com:443",
		Payload:   []byte("GET / HTTP/1.1\r\n"),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagSYN) {
		t.Fatal("SYN flag lost")
	}
	if out.Target != in.Target {
		t.Fatalf("target=%q want %q", out.Target, in.Target)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatal("payload mismatch")
	}
}

func TestFrameRoundTrip_FIN_NoPayload(t *testing.T) {
	in := &Frame{SessionID: sid(0x55), Seq: 99, Flags: FlagFIN}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagFIN) {
		t.Fatal("FIN flag lost")
	}
	if len(out.Payload) != 0 {
		t.Fatalf("payload should be empty, got %d bytes", len(out.Payload))
	}
}

func TestFrameRoundTrip_ACK(t *testing.T) {
	in := &Frame{SessionID: sid(0x77), Seq: 7, Flags: FlagACK}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, _, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.HasFlag(FlagACK) {
		t.Fatal("ACK flag lost")
	}
}

func TestUnmarshal_ShortHeader(t *testing.T) {
	if _, _, err := Unmarshal([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestUnmarshal_TargetTooLongRejectedAtMarshal(t *testing.T) {
	in := &Frame{SessionID: sid(1), Target: string(make([]byte, 256))}
	if _, err := in.Marshal(); err == nil {
		t.Fatal("expected error on oversized target")
	}
}
