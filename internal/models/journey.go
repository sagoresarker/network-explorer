package models

type VisitorJourney struct {
	DNSResolution    DNSResolution    `json:"dns_resolution"`
	TCPConnection    TCPConnection    `json:"tcp_connection"`
	TLSHandshake     TLSHandshake     `json:"tls_handshake"`
	HTTPRequest      HTTPRequest      `json:"http_request"`
	ServerProcessing ServerProcessing `json:"server_processing"`
	HTTPResponse     HTTPResponse     `json:"http_response"`
	TotalTime        TotalTime        `json:"total_time"`
}

type DNSResolution struct {
	LookupTimeMs int `json:"lookup_time_ms"`
	Steps        struct {
		LocalCache              CacheStep         `json:"local_cache"`
		RootNameserver          NameserverStep    `json:"root_nameserver"`
		TLDNameserver           NameserverStep    `json:"tld_nameserver"`
		AuthoritativeNameserver AuthoritativeStep `json:"authoritative_nameserver"`
		DNSSECStatus            string            `json:"dnssec_status"`
	} `json:"steps"`
}

type NameserverStep struct {
	Status   string `json:"status"`
	ServerIP string `json:"server_ip"`
	TimeMs   int    `json:"time_ms"`
}

type Steps struct {
	LocalCache              CacheStep          `json:"local_cache"`
	RecursiveQuery          RecursiveQueryStep `json:"recursive_query"`
	RootNameserver          NameserverStep     `json:"root_nameserver"`
	TLDNameserver           NameserverStep     `json:"tld_nameserver"`
	AuthoritativeNameserver AuthoritativeStep  `json:"authoritative_nameserver"`
	DNSSECStatus            string             `json:"dnssec_status"`
}

type CacheStep struct {
	Status string `json:"status"`
	TimeMs int    `json:"time_ms"`
}

type RecursiveQueryStep struct {
	Status     string `json:"status"`
	ResolverIP string `json:"resolver_ip"`
	TimeMs     int    `json:"time_ms"`
}

type AuthoritativeStep struct {
	Status   string `json:"status"`
	ServerIP string `json:"server_ip"`
	TimeMs   int    `json:"time_ms"`
}

type TCPConnection struct {
	HandshakeTimeMs int    `json:"handshake_time_ms"`
	ClientIP        string `json:"client_ip"`
	ServerIP        string `json:"server_ip"`
	Port            int    `json:"port"`
}

type TLSHandshake struct {
	HandshakeTimeMs int    `json:"handshake_time_ms"`
	TLSVersion      string `json:"tls_version"`
	CipherSuite     string `json:"cipher_suite"`
}

type HTTPRequest struct {
	RequestTimeMs int               `json:"request_time_ms"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
}

type ServerProcessing struct {
	ProcessingTimeMs int              `json:"processing_time_ms"`
	BackendProcesses []BackendProcess `json:"backend_processes"`
}

type BackendProcess struct {
	Name   string `json:"name"`
	TimeMs int    `json:"time_ms"`
}

type HTTPResponse struct {
	ResponseTimeMs int               `json:"response_time_ms"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
}

type TotalTime struct {
	DNSLookupTimeMs        int `json:"dns_lookup_time_ms"`
	TCPConnectionTimeMs    int `json:"tcp_connection_time_ms"`
	TLSHandshakeTimeMs     int `json:"tls_handshake_time_ms"`
	HTTPRequestTimeMs      int `json:"http_request_time_ms"`
	ServerProcessingTimeMs int `json:"server_processing_time_ms"`
	HTTPResponseTimeMs     int `json:"http_response_time_ms"`
	OverallTimeMs          int `json:"overall_time_ms"`
}
