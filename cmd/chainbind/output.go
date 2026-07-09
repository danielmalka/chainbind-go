package main

import (
	"fmt"
	"io"
	"os"
)

// writeOutput writes data to path if non-empty, or to stdout otherwise. A
// stdout write gets a trailing newline appended if data does not already
// end in one, so piping to a terminal or another line-oriented tool behaves
// the way every other well-behaved CLI does; a file write does not, so the
// bytes on disk are exactly what the library produced.
func writeOutput(path string, stdout io.Writer, data []byte) error {
	if path == "" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
		return nil
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write output file %q: %w", path, err)
	}
	return nil
}
