package models

type Hop struct {
	Number int      `json:"number"`
	IPs    []string `json:"ips"`
	RTTs   []string `json:"rtts"`
}

type TracerouteResponse struct {
	Domain         string `json:"domain"`
	Hops           []Hop  `json:"hops"`
	TotalHops      int    `json:"total_hops"`
	ExecutionTime  string `json:"execution_time"`
	BackendInsight string `json:"backend_insight"`
	NetworkJourney string `json:"network_journey"`
	CacheStatus    string `json:"cache_status,omitempty"`
}
