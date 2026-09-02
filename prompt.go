package hmacsecret

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

// stdinReader is shared across calls (guarded by stdinReaderOnce) so
// that piped, non-terminal input isn't truncated by a fresh bufio.Reader
// over-reading and discarding bytes that belong to a later read from the
// same stdin - the same footgun gokeys' own internal/prompt package
// documents and works around for its own multi-prompt flows.
var (
	stdinReaderOnce sync.Once
	stdinReader     *bufio.Reader
)

// defaultPINPrompt writes prompt to stderr and reads a line from stdin
// with terminal echo disabled when stdin is a terminal, falling back to
// a plain line read otherwise (e.g. piped input in scripts/tests).
func defaultPINPrompt(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pass), nil
	}

	stdinReaderOnce.Do(func() {
		stdinReader = bufio.NewReader(os.Stdin)
	})
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}
