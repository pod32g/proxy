package proxy

import (
	"net"
	"net/http"
)

// addProxyHeaders sets standard proxy headers on req. It appends the client IP
// to X-Forwarded-For and adds/updates the Via header with viaVal. Additional
// custom headers can then overwrite these if needed.
func addProxyHeaders(req *http.Request, clientAddr, viaVal string) {
	if req == nil {
		return
	}
	if host, _, err := net.SplitHostPort(clientAddr); err == nil {
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+host)
		} else {
			req.Header.Set("X-Forwarded-For", host)
		}
	}
	if viaVal != "" {
		if prior := req.Header.Get("Via"); prior != "" {
			req.Header.Set("Via", prior+", "+viaVal)
		} else {
			req.Header.Set("Via", viaVal)
		}
	}
}
