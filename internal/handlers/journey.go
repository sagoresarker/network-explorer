package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/miekg/dns"
	"github.com/sagoresarker/network-explorer/internal/models"
	"github.com/sagoresarker/network-explorer/internal/utils"
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
			if err != nil {
				log.Printf("TLS Handshake error: %v", err)
			} else {
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
		ClientIP:        utils.GetClientIP(originalReq),
		ServerIP:        serverIP,
		Port:            443,
	}
	journey.TotalTime.TCPConnectionTimeMs = int(tcpTime.Milliseconds())

	// Calculate TLS handshake time
	tlsTime := tlsDone.Sub(tlsStart)
	journey.TLSHandshake = models.TLSHandshake{
		HandshakeTimeMs: int(tlsTime.Milliseconds()),
		TLSVersion:      utils.GetTLSVersionString(tlsVersion),
		CipherSuite:     tls.CipherSuiteName(tlsCipherSuite),
	}
	journey.TotalTime.TLSHandshakeTimeMs = int(tlsTime.Milliseconds())

	// HTTP Request timing
	requestTime := wroteRequest.Sub(gotConn)
	journey.HTTPRequest = models.HTTPRequest{
		RequestTimeMs: int(requestTime.Milliseconds()),
		Method:        req.Method,
		Path:          req.URL.Path,
		Headers:       utils.ConvertHeaders(req.Header),
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
		Headers:        utils.ConvertHeaders(resp.Header),
	}
	journey.TotalTime.HTTPResponseTimeMs = int(responseTime.Milliseconds())

	return journey, nil
}

func (h *JourneyHandler) performDNSLookup(ctx context.Context, hostname string) (*models.DNSResolution, error) {
	dnsResolution := &models.DNSResolution{}
	startTime := time.Now()

	// Step 1: Query root servers
	rootServers := []string{
		"198.41.0.4",   // a.root-servers.net
		"199.9.14.201", // b.root-servers.net
		"192.33.4.12",  // c.root-servers.net
		// Add more root servers as needed
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.RecursionDesired = false

	var resp *dns.Msg
	var err error
	var rtt time.Duration

	// Query root servers
	for _, rootServer := range rootServers {
		resp, rtt, err = h.dnsResolver.Exchange(msg, rootServer+":53")
		if err == nil && len(resp.Answer) > 0 {
			dnsResolution.Steps.RootNameserver = models.NameserverStep{
				Status:   "success",
				ServerIP: rootServer,
				TimeMs:   int(rtt.Milliseconds()),
			}
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query root servers: %v", err)
	}

	// Step 2: Query TLD servers
	tldServers := utils.ExtractNameservers(resp)
	for _, tldServer := range tldServers {
		resp, rtt, err = h.dnsResolver.Exchange(msg, tldServer+":53")
		if err == nil && len(resp.Answer) > 0 {
			dnsResolution.Steps.TLDNameserver = models.NameserverStep{
				Status:   "success",
				ServerIP: tldServer,
				TimeMs:   int(rtt.Milliseconds()),
			}
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query TLD servers: %v", err)
	}

	// Step 3: Query authoritative nameservers
	authServers := utils.ExtractNameservers(resp)
	for _, authServer := range authServers {
		resp, rtt, err = h.dnsResolver.Exchange(msg, authServer+":53")
		if err == nil && len(resp.Answer) > 0 {
			dnsResolution.Steps.AuthoritativeNameserver = models.AuthoritativeStep{
				Status:   "success",
				ServerIP: authServer,
				TimeMs:   int(rtt.Milliseconds()),
			}
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query authoritative servers: %v", err)
	}

	// Check DNSSEC
	if resp.AuthenticatedData {
		dnsResolution.Steps.DNSSECStatus = "valid"
	} else {
		dnsResolution.Steps.DNSSECStatus = "unsigned"
	}

	dnsResolution.LookupTimeMs = int(time.Since(startTime).Milliseconds())

	return dnsResolution, nil
}
