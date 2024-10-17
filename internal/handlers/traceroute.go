package handlers

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

	"github.com/sagoresarker/traceroute-go-portfolio/internal/cache"
	"github.com/sagoresarker/traceroute-go-portfolio/internal/models"
	"github.com/sagoresarker/traceroute-go-portfolio/internal/ratelimit"
)

type TracerouteHandler struct {
	cache       *cache.Cache
	rateLimiter *ratelimit.RateLimiter
}

func NewTracerouteHandler() *TracerouteHandler {
	return &TracerouteHandler{
		cache:       cache.NewCache(10 * time.Minute),
		rateLimiter: ratelimit.NewRateLimiter(time.Minute, 10), // 10 requests per minute
	}
}

func (h *TracerouteHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := r.RemoteAddr
	if err := h.rateLimiter.Allow(clientIP); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	// Check cache first
	if cachedResponse, found := h.cache.Get(domain); found {
		cachedResponse.CacheStatus = "HIT"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cachedResponse)
		return
	}

	output, err := h.runTraceroute(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error running traceroute: %v", err), http.StatusInternalServerError)
		return
	}

	hops, err := h.parseTracerouteOutput(output)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing traceroute output: %v", err), http.StatusInternalServerError)
		return
	}

	executionTime := time.Since(startTime)

	response := models.TracerouteResponse{
		Domain:         domain,
		Hops:           hops,
		TotalHops:      len(hops),
		ExecutionTime:  executionTime.Round(time.Millisecond).String(),
		BackendInsight: h.generateBackendInsight(hops, executionTime),
		NetworkJourney: h.generateNetworkJourney(hops),
		CacheStatus:    "MISS",
	}

	// Cache the response
	h.cache.Set(domain, response)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func (h *TracerouteHandler) runTraceroute(domain string) (string, error) {
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

func (h *TracerouteHandler) parseTracerouteOutput(output string) ([]models.Hop, error) {
	lines := strings.Split(output, "\n")
	var hops []models.Hop

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

		hop := models.Hop{
			Number: hopNumber,
			IPs:    ips,
			RTTs:   rtts,
		}
		hops = append(hops, hop)
	}

	return hops, nil
}

func (h *TracerouteHandler) generateBackendInsight(hops []models.Hop, executionTime time.Duration) string {
	insights := []string{
		"👨‍💻 Backend Peek: Your request just traversed %d network hops in %s! Each hop represents a router in the vast internet infrastructure. This is how every piece of data you consume online finds its way to you.",
		"🌐 Network Adventure: We just traced your packet's journey through %d different routers in %s. This is the kind of behind-the-scenes magic that backend engineers work with every day!",
		"🚀 Tech Insight: Your request just completed an internet odyssey through %d different points in %s. This traceroute demonstrates how backend systems navigate the complex web of internet infrastructure.",
		"⚡ Backend Magic: Your packet just jumped through %d network points in %s! This is a glimpse into how backend engineers ensure data reaches its destination across the global internet.",
	}

	randomIndex := rand.Intn(len(insights))
	return fmt.Sprintf(insights[randomIndex], len(hops), executionTime.Round(time.Millisecond))
}

func (h *TracerouteHandler) generateNetworkJourney(hops []models.Hop) string {
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

func EnableCORS(handler http.HandlerFunc) http.HandlerFunc {
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
