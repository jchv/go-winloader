package pe

import "io"

func readfully(r io.Reader, p []byte) error {
	n, err := r.Read(p)
	if n < 0 || n > len(p) {
		panic("invalid read length")
	}
	if err != nil && err != io.EOF {
		return err
	}
	for n < len(p) {
		m, err := r.Read(p[n:])
		if m < 0 || m > len(p[n:]) {
			panic("invalid read length")
		}
		n += m
		if n < len(p) && err != nil {
			return err
		}
		if n >= len(p) && err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}
