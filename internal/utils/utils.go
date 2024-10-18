package utils

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

func ExtractNameservers(msg *dns.Msg) []string {
	var nameservers []string
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}
	return nameservers
}

func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func ConvertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		result[name] = strings.Join(values, ", ")
	}
	return result
}

func GetTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
