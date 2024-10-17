// handlers/journey.go
package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sagoresarker/traceroute-go-portfolio/internal/models"
)

type JourneyHandler struct {
	dnsResolver   *dns.Client
	tracingClient *http.Client
}

func NewJourneyHandler() *JourneyHandler {
	return &JourneyHandler{
		dnsResolver: &dns.Client{
			Timeout: 5 * time.Second,
		},
		tracingClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
				DisableKeepAlives: true,
			},
		},
	}
}

func (h *JourneyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// Start overall timing
	start := time.Now()

	// Extract host from request
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Collect journey data
	journey, err := h.collectJourneyData(ctx, host, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error collecting journey data: %v", err), http.StatusInternalServerError)
		return
	}

	// Calculate overall time
	journey.TotalTime.OverallTimeMs = int(time.Since(start).Milliseconds())

	response := map[string]interface{}{
		"visitor_journey": journey,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (h *JourneyHandler) collectJourneyData(ctx context.Context, host string, originalReq *http.Request) (*models.VisitorJourney, error) {
	journey := &models.VisitorJourney{}

	// Collect DNS data
	dnsStart := time.Now()
	dnsData, err := h.performDNSLookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %v", err)
	}
	journey.DNSResolution = *dnsData
	journey.TotalTime.DNSLookupTimeMs = int(time.Since(dnsStart).Milliseconds())

	// Create a new request for tracing
	url := fmt.Sprintf("https://%s%s", host, originalReq.URL.Path)
	req, err := http.NewRequestWithContext(ctx, originalReq.Method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Copy original headers
	for k, v := range originalReq.Header {
		req.Header[k] = v
	}

	// Initialize timing variables
	var (
		connectStart   time.Time
		connectDone    time.Time
		tlsStart       time.Time
		tlsDone        time.Time
		gotConn        time.Time
		wroteRequest   time.Time
		gotFirstByte   time.Time
		serverIP       string
		tlsVersion     uint16
		tlsCipherSuite uint16
	)

	// Create trace
	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectDone = time.Now()
			if err == nil {
				host, _, _ := net.SplitHostPort(addr)
				serverIP = host
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			if err == nil {
				tlsVersion = state.Version
				tlsCipherSuite = state.CipherSuite
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			gotConn = time.Now()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			wroteRequest = time.Now()
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}

	// Add trace to request context
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Execute request
	resp, err := h.tracingClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Calculate TCP connection time
	tcpTime := connectDone.Sub(connectStart)
	journey.TCPConnection = models.TCPConnection{
		HandshakeTimeMs: int(tcpTime.Milliseconds()),
		ClientIP:        getClientIP(originalReq),
		ServerIP:        serverIP,
		Port:            443,
	}
	journey.TotalTime.TCPConnectionTimeMs = int(tcpTime.Milliseconds())

	// Calculate TLS handshake time
	tlsTime := tlsDone.Sub(tlsStart)
	journey.TLSHandshake = models.TLSHandshake{
		HandshakeTimeMs: int(tlsTime.Milliseconds()),
		TLSVersion:      getTLSVersionString(tlsVersion),
		CipherSuite:     tls.CipherSuiteName(tlsCipherSuite),
	}
	journey.TotalTime.TLSHandshakeTimeMs = int(tlsTime.Milliseconds())

	// HTTP Request timing
	requestTime := wroteRequest.Sub(gotConn)
	journey.HTTPRequest = models.HTTPRequest{
		RequestTimeMs: int(requestTime.Milliseconds()),
		Method:        req.Method,
		Path:          req.URL.Path,
		Headers:       convertHeaders(req.Header),
	}
	journey.TotalTime.HTTPRequestTimeMs = int(requestTime.Milliseconds())

	// Server processing time
	processingTime := gotFirstByte.Sub(wroteRequest)
	journey.ServerProcessing = models.ServerProcessing{
		ProcessingTimeMs: int(processingTime.Milliseconds()),
		BackendProcesses: []models.BackendProcess{
			{
				Name:   "Server Processing",
				TimeMs: int(processingTime.Milliseconds()),
			},
		},
	}
	journey.TotalTime.ServerProcessingTimeMs = int(processingTime.Milliseconds())

	// HTTP Response timing
	responseTime := time.Since(gotFirstByte)
	journey.HTTPResponse = models.HTTPResponse{
		ResponseTimeMs: int(responseTime.Milliseconds()),
		StatusCode:     resp.StatusCode,
		Headers:        convertHeaders(resp.Header),
	}
	journey.TotalTime.HTTPResponseTimeMs = int(responseTime.Milliseconds())

	return journey, nil
}

func (h *JourneyHandler) performDNSLookup(ctx context.Context, hostname string) (*models.DNSResolution, error) {
	dnsResolution := &models.DNSResolution{}
	startTime := time.Now()

	// Check local cache first
	localCacheStart := time.Now()
	_, err := net.DefaultResolver.LookupHost(ctx, hostname)
	localCacheTime := time.Since(localCacheStart)

	dnsResolution.Steps.LocalCache = models.CacheStep{
		Status: "hit",
		TimeMs: int(localCacheTime.Milliseconds()),
	}

	if err != nil {
		dnsResolution.Steps.LocalCache.Status = "miss"
	}

	// Perform recursive query
	recursiveStart := time.Now()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	// Use Google's DNS server
	resp, rtt, err := h.dnsResolver.Exchange(msg, "8.8.8.8:53")
	recursiveTime := time.Since(recursiveStart)

	dnsResolution.Steps.RecursiveQuery = models.RecursiveQueryStep{
		Status:     "success",
		ResolverIP: "8.8.8.8",
		TimeMs:     int(recursiveTime.Milliseconds()),
	}

	if err != nil {
		dnsResolution.Steps.RecursiveQuery.Status = "failed"
	}

	// Get authoritative nameserver information
	if resp != nil && len(resp.Answer) > 0 {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				dnsResolution.Steps.AuthoritativeNameserver = models.AuthoritativeStep{
					Status:   "success",
					ServerIP: a.A.String(),
					TimeMs:   int(rtt.Milliseconds()),
				}
				break
			}
		}
	}

	// Check DNSSEC
	if resp != nil && resp.AuthenticatedData {
		dnsResolution.Steps.DNSSECStatus = "valid"
	} else {
		dnsResolution.Steps.DNSSECStatus = "unsigned"
	}

	dnsResolution.LookupTimeMs = int(time.Since(startTime).Milliseconds())

	return dnsResolution, nil
}

func getClientIP(r *http.Request) string {
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

func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

func getTLSVersionString(version uint16) string {
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
