// Package ctap2 implements the CTAPHID USB framing layer (packet
// fragmentation/reassembly, channel allocation, keep-alive handling) and
// the small subset of the CTAP2 protocol gokeys needs to unlock a
// hardware-key slot via the hmac-secret extension: authenticatorGetInfo,
// authenticatorClientPIN (PIN/UV Auth Protocol Two only), and
// authenticatorMakeCredential/authenticatorGetAssertion with the
// hmac-secret extension.
//
// This package is transport-agnostic - it only requires something that
// can exchange fixed-size 64-byte USB HID reports (see Transport) - so
// its protocol logic is fully unit-testable against a fake, with no real
// hardware or platform-specific HID code involved. See internal/hid for
// the real, Linux-only, cgo-free HID transport, and internal/fido2hmac
// for the top-level facade that wires the two together.
//
// Every wire-format detail here (CBOR field numbers, the PIN/UV Auth
// Protocol Two key-derivation/encryption scheme, the hmac-secret
// extension's request/response shape, and the authenticatorData binary
// layout) was cross-checked against Yubico's own python-fido2 reference
// implementation rather than reconstructed from memory, since there is
// no way to validate a hand-rolled CTAP2 client against a
// spec-conformance test suite - only real hardware.
package ctap2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Transport exchanges fixed-size 64-byte USB HID reports with a FIDO
// authenticator - one Write/Read pair per report, with no framing of its
// own. internal/hid.Device satisfies this directly; tests use a fake.
type Transport interface {
	Write(report []byte) error
	Read() ([]byte, error)
}

const (
	packetSize       = 64         // USB HID report size CTAPHID always uses
	channelBroadcast = 0xFFFFFFFF // reserved CID used only for CTAPHID_INIT

	// CTAPHID command bytes, as sent on the wire: the high bit (0x80) is
	// always set to mark an initialization packet's command byte, so the
	// values below already include it (e.g. CTAPHID_INIT's 7-bit base
	// value is 0x06 - 0x80|0x06 = 0x86).
	cmdInit      = 0x86
	cmdCBOR      = 0x90
	cmdKeepAlive = 0xBB
	cmdError     = 0xBF

	// CTAP2 command bytes: the first byte of a CTAPHID_CBOR payload.
	ctapMakeCredential = 0x01
	ctapGetAssertion   = 0x02
	ctapGetInfo        = 0x04
	ctapClientPIN      = 0x06
)

// ctap2EncMode encodes requests as "CTAP2 Canonical CBOR" (shortest-form
// integers/lengths, sorted map keys, no indefinite-length items) - the
// wire form the CTAP2 spec defines and real authenticators expect.
var ctap2EncMode = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err) // unreachable: CTAP2EncOptions() always returns valid EncOptions
	}
	return mode
}()

// Error is a non-zero CTAP2 status code returned by the authenticator in
// place of a successful response.
type Error struct{ Code byte }

func (e *Error) Error() string {
	if name, ok := errorNames[e.Code]; ok {
		return fmt.Sprintf("ctap2: authenticator returned %s (0x%02x)", name, e.Code)
	}
	return fmt.Sprintf("ctap2: authenticator returned error 0x%02x", e.Code)
}

// errorNames covers the CTAP2 status codes gokeys' own error messages or
// callers are likely to actually see and want named rather than a bare
// hex code - not every code in the spec's table.
var errorNames = map[byte]string{
	0x01: "invalid command",
	0x02: "invalid parameter",
	0x2E: "no matching credential",
	0x2F: "user action timeout",
	0x30: "not allowed",
	0x31: "PIN invalid",
	0x32: "PIN blocked",
	0x33: "PIN auth invalid",
	0x34: "PIN auth blocked",
	0x35: "no PIN set",
	0x36: "PIN/UV auth token required",
	0x3B: "user presence required",
}

// Client is a CTAP2 connection to one authenticator over an allocated
// CTAPHID channel - see NewClient.
type Client struct {
	t   Transport
	cid uint32

	// OnKeepAlive, if set, is called once per distinct CTAPHID_KEEPALIVE
	// status byte the authenticator sends while a request (typically
	// MakeCredential or GetAssertion) is outstanding - status 0x02 means
	// "waiting for user presence," i.e. a touch. internal/fido2hmac uses
	// this to narrate that wait to the user exactly once per request,
	// not once per keep-alive frame (the authenticator sends one every
	// ~100ms while it waits).
	OnKeepAlive func(status byte)
}

// NewClient allocates a fresh CTAPHID channel over t (via CTAPHID_INIT)
// and returns a Client bound to it. Every real authenticator session
// needs exactly one of these; internal/fido2hmac creates one per
// discovered device.
func NewClient(t Transport) (*Client, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	resp, err := call(t, channelBroadcast, cmdInit, nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("ctap2: allocating a channel: %w", err)
	}
	if len(resp) < 17 {
		return nil, fmt.Errorf("ctap2: init response too short (%d bytes)", len(resp))
	}
	if !bytes.Equal(resp[:8], nonce) {
		return nil, fmt.Errorf("ctap2: init response echoed the wrong nonce")
	}
	return &Client{t: t, cid: binary.BigEndian.Uint32(resp[8:12])}, nil
}

// sendCBOR sends a CTAP2 command (cmd, e.g. ctapGetInfo) with an optional
// CBOR-encoded request body, and returns the raw bytes of a successful
// response's CBOR body (with the leading status byte already stripped
// and checked). Reports keep-alives to c.OnKeepAlive, if set.
func (c *Client) sendCBOR(cmd byte, req any) ([]byte, error) {
	payload := []byte{cmd}
	if req != nil {
		enc, err := ctap2EncMode.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("ctap2: encoding request: %w", err)
		}
		payload = append(payload, enc...)
	}
	resp, err := call(c.t, c.cid, cmdCBOR, payload, c.OnKeepAlive)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("ctap2: empty response")
	}
	if status := resp[0]; status != 0x00 {
		return nil, &Error{Code: status}
	}
	return resp[1:], nil
}

// call sends one CTAPHID request (cmd/data, fragmented into as many
// packets as needed) over channel cid and returns the reassembled
// response body, handling CTAPHID_KEEPALIVE and CTAPHID_ERROR frames
// along the way. This is the raw framing layer beneath sendCBOR; it's
// also used directly for CTAPHID_INIT, which isn't a CBOR command.
func call(t Transport, cid uint32, cmd byte, data []byte, onKeepAlive func(status byte)) ([]byte, error) {
	if err := sendRequest(t, cid, cmd, data); err != nil {
		return nil, err
	}
	return readResponse(t, cid, cmd, onKeepAlive)
}

func sendRequest(t Transport, cid uint32, cmd byte, data []byte) error {
	if len(data) > 0xFFFF {
		return fmt.Errorf("ctap2: request of %d bytes exceeds CTAPHID's 16-bit length field", len(data))
	}
	remaining := data
	first := true
	contSeq := byte(0) // the first CONTINUATION packet (not the init packet) is SEQ 0
	for len(remaining) > 0 || first {
		packet := make([]byte, packetSize)
		binary.BigEndian.PutUint32(packet[0:4], cid)
		var n int
		if first {
			packet[4] = cmd
			binary.BigEndian.PutUint16(packet[5:7], uint16(len(data))) //nolint:gosec // bounds-checked above; len(data) <= 0xFFFF always fits uint16
			n = 7
			first = false
		} else {
			packet[4] = contSeq & 0x7f
			n = 5
			contSeq++
		}
		bodyLen := min(len(remaining), packetSize-n)
		copy(packet[n:], remaining[:bodyLen])
		remaining = remaining[bodyLen:]
		if err := t.Write(packet); err != nil {
			return fmt.Errorf("ctap2: writing request: %w", err)
		}
	}
	return nil
}

func readResponse(t Transport, cid uint32, cmd byte, onKeepAlive func(status byte)) ([]byte, error) {
	var response []byte
	expectedLen := 0
	seq := byte(0)
	lastKeepAlive := -1

	for response == nil || len(response) < expectedLen {
		packet, err := t.Read()
		if err != nil {
			return nil, fmt.Errorf("ctap2: reading response: %w", err)
		}
		if len(packet) < 4 {
			return nil, fmt.Errorf("ctap2: short packet (%d bytes)", len(packet))
		}
		if gotCID := binary.BigEndian.Uint32(packet[:4]); gotCID != cid {
			return nil, fmt.Errorf("ctap2: response on channel %#x, expected %#x", gotCID, cid)
		}
		body := packet[4:]

		if response == nil {
			if len(body) < 3 {
				return nil, fmt.Errorf("ctap2: short initialization packet")
			}
			rCmd := body[0]
			rLen := int(binary.BigEndian.Uint16(body[1:3]))
			body = body[3:]
			switch rCmd {
			case cmd:
				expectedLen = rLen
				response = make([]byte, 0, rLen)
			case cmdKeepAlive:
				if len(body) < 1 {
					return nil, fmt.Errorf("ctap2: short keep-alive packet")
				}
				if onKeepAlive != nil && int(body[0]) != lastKeepAlive {
					lastKeepAlive = int(body[0])
					onKeepAlive(body[0])
				}
				continue
			case cmdError:
				if len(body) < 1 {
					return nil, fmt.Errorf("ctap2: short error packet")
				}
				return nil, &Error{Code: body[0]}
			default:
				return nil, fmt.Errorf("ctap2: unexpected response command %#x", rCmd)
			}
		} else {
			if len(body) < 1 {
				return nil, fmt.Errorf("ctap2: short continuation packet")
			}
			if rSeq := body[0]; rSeq != seq&0x7f {
				return nil, fmt.Errorf("ctap2: out-of-order continuation packet (got seq %d, expected %d)", rSeq, seq&0x7f)
			}
			body = body[1:]
			seq++
		}
		response = append(response, body...)
	}
	return response[:expectedLen], nil
}
