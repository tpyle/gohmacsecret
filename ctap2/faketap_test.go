package ctap2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// fakeAuthenticator plays the role of a real FIDO2 authenticator well
// enough to exercise Client's CTAPHID framing and CTAP2/PIN-protocol
// logic end to end, without any real hardware: it performs genuine
// CTAPHID packet reassembly/fragmentation and genuine PIN/UV Auth
// Protocol Two crypto (ECDH, HKDF, AES-256-CBC, HMAC-SHA256) using the
// same helpers pin.go implements for the client side, so a bug in
// either side's key agreement would make these tests fail via a mismatch,
// not silently pass.
type fakeAuthenticator struct {
	cid uint32 // allocated on the first CTAPHID_INIT; 0 means "not yet"
	key *ecdhKeyPair

	pinSet          bool   // if false, no PIN is configured at all
	pinOptionAbsent bool   // if true, omit the "clientPin" option entirely (no ClientPIN support)
	pin             string // the PIN a client must present to get a token
	pinToken        []byte // fixed 32-byte token returned once the right PIN is presented
	noHMACSecret    bool   // if true, GetInfo omits the hmac-secret extension
	pinProtocols    []int  // PINProtocols reported by GetInfo; defaults to [2]

	credentials  map[string][]byte // credentialID -> credRandom
	masterSecret []byte

	keepAlivesBeforeResponse int // how many keep-alive frames to emit before each CBOR response

	// incoming request reassembly state
	reqCmd byte
	reqLen int
	reqBuf []byte
	reqSeq byte

	outQueue [][]byte // framed response packets awaiting Read()
}

func newFakeAuthenticator() *fakeAuthenticator {
	kp, err := generateECDHKeyPair()
	if err != nil {
		panic(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		panic(err)
	}
	return &fakeAuthenticator{
		key:          kp,
		pinProtocols: []int{pinProtocol},
		credentials:  map[string][]byte{},
		masterSecret: master,
	}
}

func (f *fakeAuthenticator) withPIN(pin string) *fakeAuthenticator {
	f.pinSet = true
	f.pin = pin
	f.pinToken = bytes.Repeat([]byte{0x5A}, 32)
	return f
}

func (f *fakeAuthenticator) credRandom(credentialID []byte) ([]byte, bool) {
	cr, ok := f.credentials[string(credentialID)]
	return cr, ok
}

// Write implements Transport: it's given exactly one 64-byte HID report
// at a time, reassembles it into a full CTAPHID request, and - once the
// request is complete - dispatches it and queues the (possibly
// multi-packet) response for Read.
func (f *fakeAuthenticator) Write(report []byte) error {
	if len(report) != packetSize {
		return fmt.Errorf("fake: wrote a %d-byte report, want %d", len(report), packetSize)
	}
	cid := binary.BigEndian.Uint32(report[:4])
	body := report[4:]

	if f.reqBuf == nil {
		f.reqCmd = body[0]
		f.reqLen = int(binary.BigEndian.Uint16(body[1:3]))
		f.reqBuf = append([]byte{}, body[3:]...)
		f.reqSeq = 0
	} else {
		f.reqBuf = append(f.reqBuf, body[1:]...)
		f.reqSeq++
	}

	if len(f.reqBuf) < f.reqLen {
		return nil // more continuation packets still to come
	}
	payload := f.reqBuf[:f.reqLen]
	f.reqBuf = nil

	if f.reqCmd == cmdInit {
		f.handleInit(payload)
		return nil
	}
	if cid != f.cid {
		f.queueError(cid, f.reqCmd, 0x0B) // CTAP1_ERR_INVALID_CHANNEL
		return nil
	}

	for range f.keepAlivesBeforeResponse {
		f.queueKeepAlive(cid)
	}

	status, resp := f.handleCBOR(payload)
	f.queueResponse(cid, cmdCBOR, append([]byte{status}, resp...))
	return nil
}

func (f *fakeAuthenticator) handleInit(nonce []byte) {
	if f.cid == 0 {
		f.cid = 0xCAFEF00D
	}
	resp := make([]byte, 0, 17)
	resp = append(resp, nonce...)
	cidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cidBytes, f.cid)
	resp = append(resp, cidBytes...)
	resp = append(resp, 2, 1, 0, 0, 0x04) // u2fhid version 2, device v1.0.0, CAPABILITY_CBOR
	f.queueResponse(channelBroadcast, cmdInit, resp)
}

func (f *fakeAuthenticator) handleCBOR(payload []byte) (status byte, resp []byte) {
	if len(payload) == 0 {
		return 0x01, nil // INVALID_COMMAND
	}
	cmd, body := payload[0], payload[1:]
	switch cmd {
	case ctapGetInfo:
		return f.handleGetInfo()
	case ctapClientPIN:
		return f.handleClientPIN(body)
	case ctapMakeCredential:
		return f.handleMakeCredential(body)
	case ctapGetAssertion:
		return f.handleGetAssertion(body)
	default:
		return 0x01, nil
	}
}

func (f *fakeAuthenticator) handleGetInfo() (byte, []byte) {
	var extensions []string
	if !f.noHMACSecret {
		extensions = []string{"hmac-secret"}
	}
	var options map[string]bool
	if !f.pinOptionAbsent {
		options = map[string]bool{"clientPin": f.pinSet}
	}
	enc, err := cbor.Marshal(getInfoResponse{Extensions: extensions, Options: options, PINProtocols: f.pinProtocols})
	if err != nil {
		panic(err)
	}
	return 0x00, enc
}

func (f *fakeAuthenticator) handleClientPIN(body []byte) (byte, []byte) {
	var req clientPINRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		return 0x12, nil // INVALID_CBOR
	}
	switch req.SubCommand {
	case clientPINSubCmdGetKeyAgreement:
		pk := f.key.publicCOSEKey()
		enc, err := cbor.Marshal(clientPINResponse{KeyAgreement: &pk})
		if err != nil {
			panic(err)
		}
		return 0x00, enc
	case clientPINSubCmdGetPINToken:
		if req.KeyAgreement == nil {
			return 0x02, nil
		}
		shared, err := f.key.sharedSecret(*req.KeyAgreement)
		if err != nil {
			return 0x02, nil
		}
		hash, err := pinDecrypt(shared, req.PINHashEnc)
		if err != nil {
			return 0x31, nil // PIN_INVALID
		}
		want := sha256.Sum256([]byte(f.pin))
		if !bytes.Equal(hash, want[:16]) {
			return 0x31, nil // PIN_INVALID
		}
		tokenEnc, err := pinEncrypt(shared, f.pinToken)
		if err != nil {
			panic(err)
		}
		enc, err := cbor.Marshal(clientPINResponse{PINUvAuthToken: tokenEnc})
		if err != nil {
			panic(err)
		}
		return 0x00, enc
	default:
		return 0x3E, nil // INVALID_SUBCOMMAND
	}
}

func (f *fakeAuthenticator) verifyPINAuth(param []byte, protocol int, message []byte) bool {
	if !f.pinSet {
		return true // nothing to check on a PIN-less authenticator
	}
	return protocol == pinProtocol && hmacEqual(param, pinAuthenticate(f.pinToken, message))
}

func hmacEqual(a, b []byte) bool { return bytes.Equal(a, b) }

func (f *fakeAuthenticator) handleMakeCredential(body []byte) (byte, []byte) {
	var req makeCredentialRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		return 0x12, nil
	}
	if !f.verifyPINAuth(req.PINUvAuthParam, req.PINUvAuthProtocol, req.ClientDataHash) {
		return 0x33, nil // PIN_AUTH_INVALID
	}

	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		panic(err)
	}
	// f.masterSecret is exactly 32 bytes, so it's already the right shape
	// for pinAuthenticate's key argument (which only ever reads key[:32]).
	credRandom := pinAuthenticate(f.masterSecret, credID)
	f.credentials[string(credID)] = credRandom

	rpIDHash := sha256.Sum256([]byte(req.RP.ID))
	pubKey, err := cbor.Marshal(coseKey{Kty: coseKeyTypeEC2, Alg: -7, Crv: coseCurveP256, X: make([]byte, 32), Y: make([]byte, 32)})
	if err != nil {
		panic(err)
	}
	authData := make([]byte, 0, 128)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagAttestedCredData)
	authData = append(authData, 0, 0, 0, 1) // signCount
	authData = append(authData, make([]byte, 16)...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID))) //nolint:gosec // fake-authenticator credential IDs are always a small, fixed 16 bytes
	authData = append(authData, credIDLen...)
	authData = append(authData, credID...)
	authData = append(authData, pubKey...)

	enc, err := cbor.Marshal(makeCredentialResponse{AuthData: authData})
	if err != nil {
		panic(err)
	}
	return 0x00, enc
}

func (f *fakeAuthenticator) handleGetAssertion(body []byte) (byte, []byte) {
	var req getAssertionRequest
	if err := cbor.Unmarshal(body, &req); err != nil {
		return 0x12, nil
	}
	if len(req.AllowList) == 0 {
		return 0x02, nil
	}
	credRandom, ok := f.credRandom(req.AllowList[0].ID)
	if !ok {
		return 0x2E, nil // NO_CREDENTIALS
	}
	if !f.verifyPINAuth(req.PINUvAuthParam, req.PINUvAuthProtocol, req.ClientDataHash) {
		return 0x33, nil
	}

	rawExt, ok := req.Extensions["hmac-secret"]
	if !ok {
		return 0x02, nil
	}
	extBytes, err := cbor.Marshal(rawExt)
	if err != nil {
		panic(err)
	}
	var input hmacSecretInput
	if err := cbor.Unmarshal(extBytes, &input); err != nil {
		return 0x12, nil
	}
	shared, err := f.key.sharedSecret(input.KeyAgreement)
	if err != nil {
		return 0x02, nil
	}
	if !hmacEqual(input.SaltAuth, pinAuthenticate(shared, input.SaltEnc)) {
		return 0x3D, nil // INTEGRITY_FAILURE
	}
	salt, err := pinDecrypt(shared, input.SaltEnc)
	if err != nil {
		return 0x02, nil
	}

	secret := pinAuthenticate(credRandom, salt) // HMAC-SHA256(credRandom, salt), same as a real hmac-secret authenticator
	secretEnc, err := pinEncrypt(shared, secret)
	if err != nil {
		panic(err)
	}
	extOut, err := cbor.Marshal(map[string][]byte{"hmac-secret": secretEnc})
	if err != nil {
		panic(err)
	}

	rpIDHash := sha256.Sum256([]byte(req.RPID))
	authData := make([]byte, 0, 37+len(extOut))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagExtensionData)
	authData = append(authData, 0, 0, 0, 1)
	authData = append(authData, extOut...)

	enc, err := cbor.Marshal(getAssertionResponse{AuthData: authData})
	if err != nil {
		panic(err)
	}
	return 0x00, enc
}

// queueResponse frames payload as one or more CTAPHID response packets
// (an initialization packet followed by as many continuation packets as
// needed), mirroring exactly what a real device sends back - deliberately
// implemented independently from sendRequest/readResponse so these tests
// exercise two independent implementations of the same framing, not one
// codepath checking itself.
func (f *fakeAuthenticator) queueResponse(cid uint32, cmd byte, payload []byte) {
	cidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cidBytes, cid)

	remaining := payload
	first := true
	contSeq := byte(0) // the first CONTINUATION packet (not the init packet) is SEQ 0
	for len(remaining) > 0 || first {
		packet := make([]byte, packetSize)
		copy(packet[:4], cidBytes)
		var n int
		if first {
			packet[4] = cmd
			binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload))) //nolint:gosec // fake-authenticator responses in these tests are always well under 64KiB
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
		f.outQueue = append(f.outQueue, packet)
	}
}

func (f *fakeAuthenticator) queueKeepAlive(cid uint32) {
	f.queueResponse(cid, cmdKeepAlive, []byte{0x02}) // STATUS_UPNEEDED
}

func (f *fakeAuthenticator) queueError(cid uint32, _ byte, code byte) {
	f.queueResponse(cid, cmdError, []byte{code})
}

// Read implements Transport.
func (f *fakeAuthenticator) Read() ([]byte, error) {
	if len(f.outQueue) == 0 {
		return nil, fmt.Errorf("fake: nothing queued to read")
	}
	packet := f.outQueue[0]
	f.outQueue = f.outQueue[1:]
	return packet, nil
}
