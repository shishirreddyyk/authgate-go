// Command loadtest drives authgate and prints measured latency
// percentiles and the status distribution.
//
// It exists so the numbers on a resume come from a run, not a guess.
//
//	go run ./cmd/loadtest -url http://localhost:8080/v1/echo \
//	  -token ag_demo_demo-secret -n 20000 -c 50
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8080/v1/echo", "target URL")
	token := flag.String("token", "ag_demo_demo-secret", "API token")
	n := flag.Int("n", 10000, "total requests")
	c := flag.Int("c", 50, "concurrent workers")
	flag.Parse()

	if *c < 1 {
		*c = 1
	}

	jobs := make(chan struct{}, *c)
	latencies := make([]time.Duration, 0, *n)
	statuses := map[int]int{}

	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: *c,
		},
	}

	start := time.Now()

	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(`{"ping":"pong"}`)
			for range jobs {
				req, err := http.NewRequest(http.MethodPost, *url, bytes.NewReader(body))
				if err != nil {
					continue
				}
				req.Header.Set("Authorization", "Bearer "+*token)
				req.Header.Set("Content-Type", "application/json")

				t0 := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(t0)
				code := 0
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					code = resp.StatusCode
				}

				mu.Lock()
				latencies = append(latencies, elapsed)
				statuses[code]++
				mu.Unlock()
			}
		}()
	}

	for i := 0; i < *n; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()

	total := time.Since(start)
	if len(latencies) == 0 {
		fmt.Fprintln(os.Stderr, "no responses recorded")
		os.Exit(1)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("requests      %d\n", len(latencies))
	fmt.Printf("workers       %d\n", *c)
	fmt.Printf("wall clock    %s\n", total.Round(time.Millisecond))
	fmt.Printf("throughput    %.0f req/s\n", float64(len(latencies))/total.Seconds())
	fmt.Printf("p50           %s\n", pct(latencies, 0.50).Round(10*time.Microsecond))
	fmt.Printf("p95           %s\n", pct(latencies, 0.95).Round(10*time.Microsecond))
	fmt.Printf("p99           %s\n", pct(latencies, 0.99).Round(10*time.Microsecond))
	fmt.Printf("max           %s\n", latencies[len(latencies)-1].Round(10*time.Microsecond))

	codes := make([]int, 0, len(statuses))
	for code := range statuses {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	fmt.Println("status counts")
	for _, code := range codes {
		label := fmt.Sprintf("%d", code)
		if code == 0 {
			label = "transport error"
		}
		fmt.Printf("  %-16s %d\n", label, statuses[code])
	}
}

func pct(sorted []time.Duration, p float64) time.Duration {
	idx := int(p*float64(len(sorted))+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
