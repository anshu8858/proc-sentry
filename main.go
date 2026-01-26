package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config
const (
	defaultPort    = "9105"
	defaultTopN    = 40
	uiUpdatePeriod = 5 * time.Second
)

var (
	// Metrics
	scrapeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "atop_scrape_duration_seconds",
		Help: "Scrape duration",
	})
	scrapeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "atop_scrape_errors_total",
		Help: "Total scrape errors",
	})
	processesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "atop_processes_scraped_total",
		Help: "Total processes scraped",
	}, []string{"runtime"})

	// Dynamic Gauges
	cpuGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "atop_process_top_cpu_percent",
		Help: "Top processes by CPU percentage",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname"})

	memGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "atop_process_top_memory_bytes",
		Help: "Top processes by RSS Memory in bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname"})

	diskReadGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "atop_process_top_disk_read_bytes",
		Help: "Top processes by Disk Read bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname"})

	diskWriteGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "atop_process_top_disk_write_bytes",
		Help: "Top processes by Disk Write bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname"})

	// State
	hostname     string
	mu           sync.RWMutex
	prevCPUTicks = make(map[int]float64) // pid -> total_ticks
	sysCLKTCK    = float64(100)          // default, updated on init
)

// Process Data Structure
type Process struct {
	PID       int
	User      string
	Command   string
	Runtime   string
	CPUPct    float64
	MemRSS    float64 // bytes
	DiskRead  float64
	DiskWrite float64
	Ticks     float64
}

func init() {
	// Register metrics
	prometheus.MustRegister(scrapeDuration, scrapeErrors, processesTotal, cpuGauge, memGauge, diskReadGauge, diskWriteGauge)

	// Get Hostname
	h, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	} else {
		hostname = h
	}

	// Get Clock Tick
	// _SC_CLK_TCK is usually 100
	// For simplicity we assyme 100. Improving this would involve CGO or `getconf` exec.
	// Most modern Linux systems use 100.
	sysCLKTCK = 100.0
}

func main() {
	port := os.Getenv("METRICS_PORT")
	if port == "" {
		port = defaultPort
	}

	log.SetFlags(0)
	log.Printf("Starting atop-exporter on :%s", port)

	// Background collector
	go collectorLoop()

	// HTTP Handler
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func collectorLoop() {
	ticker := time.NewTicker(uiUpdatePeriod)
	for range ticker.C {
		collect()
	}
}

func collect() {
	start := time.Now()
	procs, err := scanProc()
	if err != nil {
		scrapeErrors.Inc()
		log.Printf("Error scanning proc: %v", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// Calculate Deltas
	// To simplify: We just push current snapshot values for Mem/Disk
	// CPU requires diff against previous tick state (handled in scanProc if we kept state there)
	// Actually scanProc needs access to previous state.
	// Refactoring scanProc slightly.
	updateMetrics(procs)

	duration := time.Since(start).Seconds()
	scrapeDuration.Observe(duration)
}

func scanProc() ([]*Process, error) {
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []*Process
	
	// Linux system total CPU time for % calculation?
	// For per-process %: (delta_p / delta_total) * 100
	// We need system total ticks too.
	
	_, err = getSystemTotalTicks()
	if err != nil {
		return nil, err
	}

	// Persist System Ticks? Global var
	// This is a simplified implementation. Real `atop` is complex.
	// We will calculate % based on a simple window.

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		p, err := readProcess(pid)
		if err != nil {
			continue
		}
		procs = append(procs, p)
	}
	
	// CPU Calculation
	// This needs a global "PrevSystemTotal" and "PrevProcTicks" map.
	// Let's implement calculateCPU in a separate step using the global map.
	
	return procs, nil
}

// Global state for CPU calculation
var (
	lastSysTicks float64
	procTicks    = make(map[int]float64)
)

func getSystemTotalTicks() (float64, error) {
	data, err := ioutil.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	parts := strings.Fields(lines[0])
	if parts[0] != "cpu" {
		return 0, fmt.Errorf("bad stat format")
	}
	var sum float64
	for _, v := range parts[1:] {
		f, _ := strconv.ParseFloat(v, 64)
		sum += f
	}
	return sum, nil
}

func readProcess(pid int) (*Process, error) {
	// 1. Read /proc/pid/stat
	stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	
	// PID (comm) state ppid ...
	// comm is in parens, can contain spaces. 
	// Find last )
	str := string(stat)
	endComm := strings.LastIndex(str, ")")
	if endComm == -1 {
		return nil, fmt.Errorf("bad stat")
	}
	
	fields := strings.Fields(str[endComm+2:])
	// Fields after comm:
	// 0: state, 1: ppid, ... 
	// 11: utime, 12: stime
	
	if len(fields) < 13 {
		return nil, fmt.Errorf("short stat")
	}
	
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	ticks := utime + stime
	
	// 2. Read /proc/pid/status (for User)
	status, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	uid := "0"
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					uid = parts[1]
				}
				break
			}
		}
	}
	
	// 3. Read /proc/pid/io (Root only usually)
	var rd, wr float64
	ioBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err == nil {
		for _, line := range strings.Split(string(ioBytes), "\n") {
			if strings.HasPrefix(line, "read_bytes:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					rd, _ = strconv.ParseFloat(parts[1], 64)
				}
			} else if strings.HasPrefix(line, "write_bytes:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					wr, _ = strconv.ParseFloat(parts[1], 64)
				}
			}
		}
	}

	// 4. Memory (from statm) - RSS is 2nd field (pages)
	statm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	rssBytes := 0.0
	if err == nil {
		f := strings.Fields(string(statm))
		if len(f) > 1 {
			pages, _ := strconv.ParseFloat(f[1], 64)
			rssBytes = pages * 4096 
		}
	}

	// 5. Command 
	cmdBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	cmd := "unknown"
	if err == nil {
		cmd = strings.TrimSpace(string(cmdBytes))
	}
    
    // Runtime detection (simple heuristic)
    runtime := "host"
    cgroupBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
    if err == nil {
        cg := string(cgroupBytes)
        if strings.Contains(cg, "docker") {
            runtime = "docker"
        } else if strings.Contains(cg, "kube") {
            runtime = "kubernetes"
        }
    }

	return &Process{
		PID:       pid,
		User:      uid, // mapping UID to name is expensive in Go without CGO or reading /etc/passwd directly. Keeping raw UID or caching map.
		Command:   cmd,
		Runtime:   runtime,
		Ticks:     ticks,
		MemRSS:    rssBytes,
		DiskRead:  rd,
		DiskWrite: wr,
	}, nil
}

func updateMetrics(procs []*Process) {
	// Calculate CPU
	currSys, _ := getSystemTotalTicks()
	sysDiff := currSys - lastSysTicks
	
	if sysDiff <= 0 { sysDiff = 1 }

	// Temporary list for sorting
	var list []*Process

	for _, p := range procs {
		prevTick, ok := procTicks[p.PID]
		if ok {
			diff := p.Ticks - prevTick
			if diff >= 0 {
				// CPU % = (process_ticks / total_system_ticks) * 100
                // * NumCPU ? No, stat totals are sum of all CPUs.
				p.CPUPct = (diff / sysDiff) * 100 * float64(1) // Assuming single core normalization or overall usage? 
                // Standard `top` output is usually per-core relative or total relative.
                // Let's stick to simple relative for now.
			}
		}
		// Update state
		procTicks[p.PID] = p.Ticks
        
        list = append(list, p)
	}
    
    // Purge old PIDs
    // In a real app we need a robust cleanup. 
    // For now, re-building procTicks from scratch every time is inefficient.
    // Optimized: Create new map
    newMap := make(map[int]float64)
    for _, p := range procs {
        newMap[p.PID] = p.Ticks
    }
    procTicks = newMap
    lastSysTicks = currSys
    
    // Clear Metrics
    cpuGauge.Reset()
    memGauge.Reset()
    diskReadGauge.Reset()
    diskWriteGauge.Reset()

	// Sort and Top N
    topN := 40
    
    // Helper to generic sort
    sortAndSet := func(sorter func(i, j int) bool, metric *prometheus.GaugeVec, val func(*Process) float64) {
        sort.Slice(list, sorter)
        for i := 0; i < topN && i < len(list); i++ {
            p := list[i]
            if val(p) == 0 { continue }
            metric.WithLabelValues(
                strconv.Itoa(p.PID), p.User, p.Command, p.Runtime, strconv.Itoa(i+1), hostname,
            ).Set(val(p))
        }
    }

    sortAndSet(func(i, j int) bool { return list[i].CPUPct > list[j].CPUPct }, cpuGauge, func(p *Process) float64 { return p.CPUPct })
    sortAndSet(func(i, j int) bool { return list[i].MemRSS > list[j].MemRSS }, memGauge, func(p *Process) float64 { return p.MemRSS })
    sortAndSet(func(i, j int) bool { return list[i].DiskRead > list[j].DiskRead }, diskReadGauge, func(p *Process) float64 { return p.DiskRead })
    sortAndSet(func(i, j int) bool { return list[i].DiskWrite > list[j].DiskWrite }, diskWriteGauge, func(p *Process) float64 { return p.DiskWrite })
    
    processesTotal.WithLabelValues("host").Set(float64(len(procs)))
}
