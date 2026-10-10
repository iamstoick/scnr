package safety

import "io"

// CountingReader enforces a byte budget on a stream, typically the
// decompressed side of a gzip reader, so a bomb is stopped at the budget
// however small the compressed input. N is shared when several readers
// contribute to one budget (per-layer and per-image in the image engine).
// Err is returned once the budget is exceeded.
type CountingReader struct {
	R     io.Reader
	N     *int64
	Limit int64
	Err   error
}

func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	*c.N += int64(n)
	if *c.N > c.Limit {
		return n, c.Err
	}
	return n, err
}
