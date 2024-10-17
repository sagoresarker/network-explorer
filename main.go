package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

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
}

func generateBackendInsight(hops []Hop, executionTime time.Duration) string {
	insights := []string{
		"👨‍💻 Backend Peek: Your request just traversed %d network hops in %s! Each hop represents a router in the vast internet infrastructure. This is how every piece of data you consume online finds its way to you.",
		"🌐 Network Adventure: We just traced your packet's journey through %d different routers in %s. This is the kind of behind-the-scenes magic that backend engineers work with every day!",
		"🚀 Tech Insight: Your request just completed an internet odyssey through %d different points in %s. This traceroute demonstrates how backend systems navigate the complex web of internet infrastructure.",
		"⚡ Backend Magic: Your packet just jumped through %d network points in %s! This is a glimpse into how backend engineers ensure data reaches its destination across the global internet.",
	}

	randomIndex := rand.Intn(len(insights))
	return fmt.Sprintf(insights[randomIndex], len(hops), executionTime.Round(time.Millisecond))
}

func generateNetworkJourney(hops []Hop) string {
	var distances []string
	lastRTT := 0.0

	for _, hop := range hops {
		if len(hop.RTTs) > 0 {
			currentRTT := 0.0
			fmt.Sscanf(hop.RTTs[0], "%f", &currentRTT)

			if lastRTT > 0 {
				diff := currentRTT - lastRTT
				if diff > 50 {
					distances = append(distances, "🌎 Long Jump")
				} else if diff > 20 {
					distances = append(distances, "🚀 Quick Hop")
				} else {
					distances = append(distances, "⚡ Local Leap")
				}
			}
			lastRTT = currentRTT
		}
	}

	if len(distances) > 0 {
		return fmt.Sprintf("Network Journey: %s", strings.Join(distances, " → "))
	}
	return "Network Journey: Path traced! 🎯"
}

func runTraceroute(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Validate domain using regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-\.]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$`)
	if !domainRegex.MatchString(domain) {
		return "", fmt.Errorf("invalid domain format")
	}

	cmd := exec.CommandContext(ctx, "traceroute", domain)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("traceroute timed out after 30 seconds")
		}
		return "", err
	}
	return string(output), nil
}

func parseTracerouteOutput(output string) ([]Hop, error) {
	lines := strings.Split(output, "\n")
	var hops []Hop

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract hop number
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		hopNumber := 0
		_, err := fmt.Sscanf(fields[0], "%d", &hopNumber)
		if err != nil {
			continue
		}

		// Extract IPs and RTTs
		var ips []string
		var rtts []string
		ipRegex := regexp.MustCompile(`\(([^\)]+)\)`)
		rttRegex := regexp.MustCompile(`\d+\.?\d* ms`)

		ipMatches := ipRegex.FindAllStringSubmatch(line, -1)
		for _, match := range ipMatches {
			if len(match) > 1 {
				ips = append(ips, match[1])
			}
		}

		rttMatches := rttRegex.FindAllString(line, -1)
		rtts = append(rtts, rttMatches...)

		hop := Hop{
			Number: hopNumber,
			IPs:    ips,
			RTTs:   rtts,
		}
		hops = append(hops, hop)
	}

	return hops, nil
}

func enableCORS(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler(w, r)
	}
}

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}

	output, err := runTraceroute(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error running traceroute: %v", err), http.StatusInternalServerError)
		return
	}

	hops, err := parseTracerouteOutput(output)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing traceroute output: %v", err), http.StatusInternalServerError)
		return
	}

	executionTime := time.Since(startTime)

	response := TracerouteResponse{
		Domain:         domain,
		Hops:           hops,
		TotalHops:      len(hops),
		ExecutionTime:  executionTime.Round(time.Millisecond).String(),
		BackendInsight: generateBackendInsight(hops, executionTime),
		NetworkJourney: generateNetworkJourney(hops),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func main() {
	http.HandleFunc("/traceroute", enableCORS(tracerouteHandler))

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
	}

	log.Println("Server is running on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
