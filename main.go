package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func runTraceroute(domain string) (string, error) {
	cmd := exec.Command("traceroute", domain)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func parseTracerouteOutput(output string) ([]string, error) {
	lines := strings.Split(output, "\n")
	var hops []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			hops = append(hops, fields[0])
		}
	}
	return hops, nil
}

func printHops(hops []string) {
	for _, hop := range hops {
		fmt.Println(hop)
	}
}

func tracerouteHandler(w http.ResponseWriter, r *http.Request) {
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

	printHops(hops)

	response := map[string]interface{}{
		"domain": domain,
		"hops":   hops,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func main() {
	http.HandleFunc("/traceroute", tracerouteHandler)
	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
