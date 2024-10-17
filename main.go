package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
)

// Global variables for rate limiting and request tracking
var (
	rdb           *redis.Client
	memCache      *cache.Cache
	rateLimiter   = make(map[string]time.Time)
	dailyRequests = make(map[string]int)
	mutex         sync.RWMutex
)

const (
	RATE_LIMIT_SECONDS = 5
	MAX_DAILY_REQUESTS = 10
	CACHE_DURATION     = 10 * time.Minute
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
	CacheStatus    string `json:"cache_status,omitempty"`
}

func initRedis() {
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisPassword := getEnv("REDIS_PASSWORD", "")

	rdb = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisHost, redisPort),
		Password: redisPassword,
		DB:       0,
	})
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func initCache() {
	// Create a cache with 5 minute expiration and 10 minute cleanup interval
	memCache = cache.New(5*time.Minute, 10*time.Minute)
}

func getDailyRequestKey(ip string) string {
	now := time.Now()
	return fmt.Sprintf("daily_requests:%s:%s", ip, now.Format("2006-01-02"))
}

func checkRateLimit(ip string) error {
	mutex.Lock()
	defer mutex.Unlock()

	now := time.Now()

	// Check last request time
	if lastTime, exists := rateLimiter[ip]; exists {
		if now.Sub(lastTime) < time.Second*RATE_LIMIT_SECONDS {
			return fmt.Errorf("rate limit exceeded. Please wait %d seconds", RATE_LIMIT_SECONDS)
		}
	}

	// Update last request time
	rateLimiter[ip] = now
	return nil
}

func incrementDailyRequests(ip string) (int, error) {
	ctx := context.Background()
	key := getDailyRequestKey(ip)

	// Increment daily requests counter
	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set expiration if this is the first request of the day
	if count == 1 {
		rdb.Expire(ctx, key, 24*time.Hour)
	}

	return int(count), nil
}

func getCachedResponse(domain string) (*TracerouteResponse, bool) {
	if cached, found := memCache.Get(domain); found {
		if response, ok := cached.(TracerouteResponse); ok {
			response.CacheStatus = "HIT"
			return &response, true
		}
	}
	return nil, false
}

func cacheResponse(domain string, response TracerouteResponse) {
	memCache.Set(domain, response, CACHE_DURATION)
}

func generateBackendInsight(hops []Hop, executionTime time.Duration, requestCount int) string {
	if requestCount > MAX_DAILY_REQUESTS {
		return "You've reached the daily limit for detailed insights. Come back tomorrow for more backend exploration!"
	}

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
	clientIP := r.RemoteAddr

	// Check rate limit
	if err := checkRateLimit(clientIP); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	// Check and increment daily requests
	requestCount, err := incrementDailyRequests(clientIP)
	if err != nil {
		log.Printf("Error tracking daily requests: %v", err)
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	// Check cache first
	if cachedResponse, found := getCachedResponse(domain); found {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cachedResponse)
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
		BackendInsight: generateBackendInsight(hops, executionTime, requestCount),
		NetworkJourney: generateNetworkJourney(hops),
		CacheStatus:    "MISS",
	}

	// Cache the response
	cacheResponse(domain, response)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Check Redis connection
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "Redis connection failed",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"message": "Service is running",
	})
}

func main() {
	// Initialize Redis and in-memory cache
	initRedis()
	initCache()

	http.HandleFunc("/health", healthCheckHandler)
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
