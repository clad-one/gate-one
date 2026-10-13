package proxy

import "net/http"

type headResponseWriter struct {
	http.ResponseWriter
}

func (w *headResponseWriter) Write(b []byte) (int, error) {
	// swallow body
	return len(b), nil
}
