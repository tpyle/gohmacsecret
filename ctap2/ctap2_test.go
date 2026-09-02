package ctap2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// scriptedTransport is a minimal, hand-controlled Transport for testing
// the CTAPHID framing layer (call/sendRequest/readResponse) in
// isolation, independent of fakeAuthenticator's higher-level CTAP2
// command handling.
type scriptedTransport struct {
	written [][]byte
	toRead  [][]byte
}

func (s *scriptedTransport) Write(p []byte) error {
	s.written = append(s.written, append([]byte(nil), p...))
	return nil
}

func (s *scriptedTransport) Read() ([]byte, error) {
	if len(s.toRead) == 0 {
		return nil, errors.New("scripted: no more packets queued")
	}
	p := s.toRead[0]
	s.toRead = s.toRead[1:]
	return p, nil
}

func initPacket(cid uint32, cmd byte, bcnt int, data []byte) []byte {
	p := make([]byte, packetSize)
	binary.BigEndian.PutUint32(p[0:4], cid)
	p[4] = cmd
	binary.BigEndian.PutUint16(p[5:7], uint16(bcnt)) //nolint:gosec // test helper; every bcnt this package's tests pass is a small fixed fixture length
	copy(p[7:], data)
	return p
}

func contPacket(cid uint32, seq byte, data []byte) []byte {
	p := make([]byte, packetSize)
	binary.BigEndian.PutUint32(p[0:4], cid)
	p[4] = seq
	copy(p[5:], data)
	return p
}

func TestSendRequestFragmentsAcrossPackets(t *testing.T) {
	tr := &scriptedTransport{toRead: [][]byte{initPacket(1, cmdCBOR, 0, nil)}}
	// 57 (first packet) + 59 (one continuation) + 10 leftover bytes needs
	// 3 packets total.
	data := make([]byte, 57+59+10)
	for i := range data {
		data[i] = byte(i)
	}
	if err := sendRequest(tr, 1, cmdCBOR, data); err != nil {
		t.Fatalf("sendRequest: %v", err)
	}
	if len(tr.written) != 3 {
		t.Fatalf("wrote %d packets, want 3", len(tr.written))
	}
	for _, p := range tr.written {
		if len(p) != packetSize {
			t.Fatalf("packet is %d bytes, want %d", len(p), packetSize)
		}
	}

	first := tr.written[0]
	if got := binary.BigEndian.Uint32(first[:4]); got != 1 {
		t.Errorf("first packet CID = %#x, want 1", got)
	}
	if first[4] != cmdCBOR {
		t.Errorf("first packet cmd = %#x, want %#x", first[4], cmdCBOR)
	}
	if got := binary.BigEndian.Uint16(first[5:7]); int(got) != len(data) {
		t.Errorf("first packet BCNT = %d, want %d", got, len(data))
	}
	// The first CONTINUATION packet must carry SEQ 0, not 1 - easy to get
	// off by one if the same counter is reused for "is this the init
	// packet" and "what SEQ number goes in a continuation packet".
	if got := tr.written[1][4]; got != 0 {
		t.Errorf("first continuation packet SEQ = %d, want 0", got)
	}
	if got := tr.written[2][4]; got != 1 {
		t.Errorf("second continuation packet SEQ = %d, want 1", got)
	}

	// Reassemble the body exactly as readResponse would, to confirm no
	// bytes were dropped or duplicated across the fragmentation.
	var reassembled []byte
	reassembled = append(reassembled, first[7:]...)
	reassembled = append(reassembled, tr.written[1][5:]...)
	reassembled = append(reassembled, tr.written[2][5:]...)
	reassembled = reassembled[:len(data)]
	for i, b := range data {
		if reassembled[i] != b {
			t.Fatalf("reassembled data differs at byte %d: got %#x, want %#x", i, reassembled[i], b)
		}
	}
}

func TestSendRequestSendsAtLeastOnePacketForEmptyData(t *testing.T) {
	tr := &scriptedTransport{}
	if err := sendRequest(tr, 1, cmdCBOR, nil); err != nil {
		t.Fatalf("sendRequest: %v", err)
	}
	if len(tr.written) != 1 {
		t.Fatalf("wrote %d packets for empty data, want 1", len(tr.written))
	}
}

func TestSendRequestRejectsOversizedData(t *testing.T) {
	tr := &scriptedTransport{}
	if err := sendRequest(tr, 1, cmdCBOR, make([]byte, 0x10000)); err == nil {
		t.Fatal("expected an error for a request exceeding the 16-bit length field, got nil")
	}
}

func TestReadResponseReassemblesFragmentedResponse(t *testing.T) {
	payload := make([]byte, 57+20)
	for i := range payload {
		payload[i] = byte(200 + i)
	}
	tr := &scriptedTransport{toRead: [][]byte{
		initPacket(1, cmdCBOR, len(payload), payload[:57]),
		contPacket(1, 0, payload[57:]),
	}}
	got, err := readResponse(tr, 1, cmdCBOR, nil)
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
	for i, b := range payload {
		if got[i] != b {
			t.Fatalf("byte %d = %#x, want %#x", i, got[i], b)
		}
	}
}

func TestReadResponseSkipsKeepAliveAndDedupsCallback(t *testing.T) {
	tr := &scriptedTransport{toRead: [][]byte{
		initPacket(1, cmdKeepAlive, 1, []byte{0x02}),
		initPacket(1, cmdKeepAlive, 1, []byte{0x02}), // same status - shouldn't fire the callback again
		initPacket(1, cmdKeepAlive, 1, []byte{0x03}), // different status - fires once more
		initPacket(1, cmdCBOR, 1, []byte{0x00}),
	}}
	var statuses []byte
	got, err := readResponse(tr, 1, cmdCBOR, func(status byte) { statuses = append(statuses, status) })
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(got) != 1 || got[0] != 0x00 {
		t.Fatalf("got %v, want [0x00]", got)
	}
	if want := []byte{0x02, 0x03}; !bytes.Equal(statuses, want) {
		t.Fatalf("keep-alive callback fired with %v, want %v", statuses, want)
	}
}

func TestReadResponseSurfacesError(t *testing.T) {
	tr := &scriptedTransport{toRead: [][]byte{initPacket(1, cmdError, 1, []byte{0x2E})}}
	_, err := readResponse(tr, 1, cmdCBOR, nil)
	var ctapErr *Error
	if !errors.As(err, &ctapErr) {
		t.Fatalf("readResponse error = %v (%T), want a *ctap2.Error", err, err)
	}
	if ctapErr.Code != 0x2E {
		t.Errorf("error code = %#x, want 0x2E", ctapErr.Code)
	}
}

func TestReadResponseRejectsWrongChannel(t *testing.T) {
	tr := &scriptedTransport{toRead: [][]byte{initPacket(99, cmdCBOR, 1, []byte{0x00})}}
	if _, err := readResponse(tr, 1, cmdCBOR, nil); err == nil {
		t.Fatal("expected an error for a response on the wrong channel, got nil")
	}
}

func TestReadResponseRejectsOutOfOrderContinuation(t *testing.T) {
	payload := make([]byte, 57+5)
	tr := &scriptedTransport{toRead: [][]byte{
		initPacket(1, cmdCBOR, len(payload), payload[:57]),
		contPacket(1, 5, payload[57:]), // should be seq 0, not 5
	}}
	if _, err := readResponse(tr, 1, cmdCBOR, nil); err == nil {
		t.Fatal("expected an error for an out-of-order continuation packet, got nil")
	}
}

func TestNewClientSuccess(t *testing.T) {
	fa := newFakeAuthenticator()
	c, err := NewClient(fa)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.cid != fa.cid {
		t.Errorf("client cid = %#x, want %#x", c.cid, fa.cid)
	}
}

func TestErrorMessage(t *testing.T) {
	named := &Error{Code: 0x2E}
	if got := named.Error(); got != "ctap2: authenticator returned no matching credential (0x2e)" {
		t.Errorf("Error() = %q for a named code", got)
	}
	unnamed := &Error{Code: 0x77}
	if got := unnamed.Error(); got != "ctap2: authenticator returned error 0x77" {
		t.Errorf("Error() = %q for an unnamed code", got)
	}
}

func TestNewClientRejectsNonceMismatch(t *testing.T) {
	tr := &scriptedTransport{toRead: [][]byte{
		initPacket(channelBroadcast, cmdInit, 17, append(make([]byte, 8), make([]byte, 9)...)), // all-zero nonce, never matches the random one NewClient sends
	}}
	if _, err := NewClient(tr); err == nil {
		t.Fatal("expected an error for a mismatched init nonce, got nil")
	}
}
