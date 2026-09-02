# Examples

Two small, runnable programs demonstrating `gohmacsecret`, meant to be
run together: `enroll` creates a credential, `unlock` re-derives its
secret.

* [`enroll/`](enroll/main.go) - creates a new hmac-secret credential and
  prints its credential ID.

  ```sh
  go run ./examples/enroll
  ```

* [`unlock/`](unlock/main.go) - re-derives the secret for a credential ID
  printed by `enroll`.

  ```sh
  go run ./examples/unlock <credential-id-hex-from-enroll>
  ```

Both require a FIDO2 security key plugged in, and will prompt for its PIN
on stderr if one is set. See [Getting
Started](../wiki/Getting-Started.md) for the full API these examples use.
