package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config
var (
	defaultPort    = "9105"
	topN           = 40
	uiUpdatePeriod = 5 * time.Second
	enableDiskIO   = true
	enablePorts    = true
)

var (
	// Metrics
	scrapeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "proc_scrape_duration_seconds",
		Help: "Scrape duration",
	})
	scrapeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "proc_scrape_errors_total",
		Help: "Total scrape errors",
	})
	processesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proc_processes_scraped_total",
		Help: "Total processes scraped",
	}, []string{"runtime"})

	// Dynamic Gauges - Added 'ports' label
	cpuGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proc_process_top_cpu_percent",
		Help: "Top processes by CPU percentage",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname", "container_id", "ports"})

	memGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proc_process_top_memory_bytes",
		Help: "Top processes by RSS Memory in bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname", "container_id", "ports"})

	diskReadGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proc_process_top_disk_read_bytes",
		Help: "Top processes by Disk Read bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname", "container_id", "ports"})

	diskWriteGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proc_process_top_disk_write_bytes",
		Help: "Top processes by Disk Write bytes",
	}, []string{"pid", "user", "command", "runtime", "rank", "hostname", "container_id", "ports"})

	// State
	hostname     string
	mu           sync.RWMutex
	prevCPUTicks = make(map[int]float64) // pid -> total_ticks
	sysCLKTCK    = float64(100)          // default
	
	// User Cache
	userMap = make(map[string]string) // uid -> username
	
	// Regex for Container ID
	reContainerID = regexp.MustCompile(`([0-9a-fA-F]{64}|[0-9a-fA-F]{12})`)
)

// Process Data Structure
type Process struct {
	PID         int
	User        string
	Command     string
	Runtime     string
	ContainerID string
	CPUPct      float64
	MemRSS      float64 // bytes
	DiskRead    float64
	DiskWrite   float64
	Ticks       float64
	Ports       string // New field
}

func init() {
	// Register metrics
	prometheus.MustRegister(scrapeDuration, scrapeErrors, processesTotal, cpuGauge, memGauge, diskReadGauge, diskWriteGauge)

	// Get Hostname
	if env := os.Getenv("PROC_HOSTNAME"); env != "" {
		hostname = env
	} else {
		h, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		} else {
			hostname = h
		}
	}
	
	// Load User Map once
	loadUserMap()
}

func loadUserMap() {
    // Read /etc/passwd
    data, err := ioutil.ReadFile("/etc/passwd")
    if err != nil {
        log.Printf("Warning: Failed to read /etc/passwd: %v", err)
        return
    }
    
    lines := strings.Split(string(data), "\n")
    count := 0
    for _, line := range lines {
        parts := strings.Split(line, ":")
        if len(parts) >= 3 {
            name := parts[0]
            uid := parts[2]
            userMap[uid] = name
            count++
        }
    }
    log.Printf("Loaded %d users from /etc/passwd", count)
}

func main() {
	port := os.Getenv("METRICS_PORT")
	if port == "" {
		port = defaultPort
	}
	
	if n := os.Getenv("TOP_N"); n != "" {
		if val, err := strconv.Atoi(n); err == nil {
			topN = val
		}
	}
	
	if v := os.Getenv("ENABLE_DISK_IO"); v == "false" {
		enableDiskIO = false
	}
	
	if v := os.Getenv("ENABLE_PORTS"); v == "false" {
		enablePorts = false
	}

	log.SetFlags(0)
	log.Printf("Starting proc-sentry on :%s (TOP_N=%d, DiskIO=%v, Ports=%v)", port, topN, enableDiskIO, enablePorts)

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
	
	_, err = getSystemTotalTicks()
	if err != nil {
		return nil, err
	}

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
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Scan()
	line := scanner.Text()
	
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[0] != "cpu" {
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
	stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	
	str := string(stat)
	endComm := strings.LastIndex(str, ")")
	if endComm == -1 {
		return nil, fmt.Errorf("bad stat")
	}
	
	fields := strings.Fields(str[endComm+2:])
	if len(fields) < 13 {
		return nil, fmt.Errorf("short stat")
	}
	
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	ticks := utime + stime
	
	// User
	status, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	uid := "0"
	username := "root"
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
	if name, ok := userMap[uid]; ok {
	    username = name
	} else {
	    username = uid
	}
	
	// Disk I/O
	var rd, wr float64
	if enableDiskIO {
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
	}

	// Memory
	statm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	rssBytes := 0.0
	if err == nil {
		f := strings.Fields(string(statm))
		if len(f) > 1 {
			pages, _ := strconv.ParseFloat(f[1], 64)
			rssBytes = pages * 4096 
		}
	}

	// Command 
	cmdBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	cmd := "unknown"
	if err == nil {
		cmd = strings.TrimSpace(string(cmdBytes))
	}
    
    // Runtime
    runtime := "host"
    containerID := ""
    cgroupBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
    if err == nil {
        lines := strings.Split(string(cgroupBytes), "\n")
        for _, l := range lines {
        	if strings.Contains(l, "docker") || strings.Contains(l, "containerd") || strings.Contains(l, "kubepods") {
        		matches := reContainerID.FindStringSubmatch(l)
        		if len(matches) > 1 {
        			containerID = matches[1]
        		}
        		
        		if strings.Contains(l, "docker") {
        			runtime = "docker"
        		} else if strings.Contains(l, "kubepods") {
        			runtime = "kubernetes"
        		} else if strings.Contains(l, "containerd") {
        			runtime = "containerd"
        		}
        		if containerID != "" { break }
        	}
        }
    }

	return &Process{
		PID:         pid,
		User:        username,
		Command:     cmd,
		Runtime:     runtime,
		ContainerID: containerID,
		Ticks:       ticks,
		MemRSS:      rssBytes,
		DiskRead:    rd,
		DiskWrite:   wr,
	}, nil
}

func updateMetrics(procs []*Process) {
	// 1. Calculate CPU Deltas
	currSys, _ := getSystemTotalTicks()
	sysDiff := currSys - lastSysTicks
	if sysDiff <= 0 { sysDiff = 1 }

	var list []*Process
	for _, p := range procs {
		prevTick, ok := procTicks[p.PID]
		if ok {
			diff := p.Ticks - prevTick
			if diff >= 0 {
				p.CPUPct = (diff / sysDiff) * 100 * float64(1) 
			}
		}
		procTicks[p.PID] = p.Ticks
        list = append(list, p)
	}
    
    // Purge old state
    newMap := make(map[int]float64)
    for _, p := range procs { newMap[p.PID] = p.Ticks }
    procTicks = newMap
    lastSysTicks = currSys
    
    // Reset Gauges
    cpuGauge.Reset()
    memGauge.Reset()
    diskReadGauge.Reset()
    diskWriteGauge.Reset()

    // 2. Identify Unique Top N Processes
    // We want to resolve ports for any process that appears in ANY Top N list.
    // To avoid resolving the same PID multiple times or resolving unnecessary PIDs,
    // we first gather the winners.
    
    winners := make(map[int]*Process)
    
    addToWinners := func(sorter func(i, j int) bool, val func(*Process) float64) {
        sort.Slice(list, sorter)
        for i := 0; i < topN && i < len(list); i++ {
            p := list[i]
            if val(p) > 0 {
                winners[p.PID] = p
            }
        }
    }

    addToWinners(func(i, j int) bool { return list[i].CPUPct > list[j].CPUPct }, func(p *Process) float64 { return p.CPUPct })
    addToWinners(func(i, j int) bool { return list[i].MemRSS > list[j].MemRSS }, func(p *Process) float64 { return p.MemRSS })
    addToWinners(func(i, j int) bool { return list[i].DiskRead > list[j].DiskRead }, func(p *Process) float64 { return p.DiskRead })
    addToWinners(func(i, j int) bool { return list[i].DiskWrite > list[j].DiskWrite }, func(p *Process) float64 { return p.DiskWrite })

    // 3. Resolve Ports ONLY for Winners
    if enablePorts && len(winners) > 0 {
        inodeMap := buildSocketMap()
        for _, p := range winners {
            p.Ports = getProcessPorts(p.PID, inodeMap)
        }
    }

    // 4. Set Metrics (Re-sorting needed? Yes, or just reuse sorted lists?
    // We need to set metrics in Rank order. Rank is specific to the metric type.
    // So we must re-sort 'list' (which now contains pointers to enriched processes).
    
    setMetric := func(sorter func(i, j int) bool, metric *prometheus.GaugeVec, val func(*Process) float64) {
        sort.Slice(list, sorter)
        for i := 0; i < topN && i < len(list); i++ {
            p := list[i]
            if val(p) == 0 { continue }
            metric.WithLabelValues(
                strconv.Itoa(p.PID), p.User, p.Command, p.Runtime, strconv.Itoa(i+1), hostname, p.ContainerID, p.Ports,
            ).Set(val(p))
        }
    }

    setMetric(func(i, j int) bool { return list[i].CPUPct > list[j].CPUPct }, cpuGauge, func(p *Process) float64 { return p.CPUPct })
    setMetric(func(i, j int) bool { return list[i].MemRSS > list[j].MemRSS }, memGauge, func(p *Process) float64 { return p.MemRSS })
    setMetric(func(i, j int) bool { return list[i].DiskRead > list[j].DiskRead }, diskReadGauge, func(p *Process) float64 { return p.DiskRead })
    setMetric(func(i, j int) bool { return list[i].DiskWrite > list[j].DiskWrite }, diskWriteGauge, func(p *Process) float64 { return p.DiskWrite })
    
    processesTotal.WithLabelValues("host").Set(float64(len(procs)))
}

// --- Port Resolution Logic ---

func buildSocketMap() map[string]int {
    // Reads /proc/net/{tcp,tcp6,udp,udp6}
    // Returns Inode -> Port
    m := make(map[string]int)
    
    files := []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}
    for _, f := range files {
        data, err := ioutil.ReadFile(f)
        if err != nil { continue }
        
        lines := strings.Split(string(data), "\n")
        // Skip header
        for _, line := range lines[1:] {
            fields := strings.Fields(line)
            if len(fields) < 10 { continue }
            
            // State 0A = Listen (TCP). UDP doesn't key on state usually but 07.
            // Let's just grab listening ports? Or all? User said "ports". usually LISTEN.
            // TCP: 01 (ESTAB), 0A (LISTEN).
            state := fields[3]
            if strings.Contains(f, "tcp") && state != "0A" { continue }
            
            // local_address:port (hex)
            local := fields[1] // 00000000:0016
            parts := strings.Split(local, ":")
            if len(parts) < 2 { continue }
            
            portHex := parts[1]
            inode := fields[9]
            
            port, err := strconv.ParseInt(portHex, 16, 64)
            if err == nil {
                m[inode] = int(port)
            }
        }
    }
    return m
}

func getProcessPorts(pid int, inodeMap map[string]int) string {
    fdDir := fmt.Sprintf("/proc/%d/fd", pid)
    files, err := ioutil.ReadDir(fdDir)
    if err != nil { return "" }
    
    var ports []int
    seen := make(map[int]bool)
    
    for _, fd := range files {
        // Read link target
        target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
        if err != nil { continue }
        
        // socket:[12345]
        if strings.HasPrefix(target, "socket:[") {
            inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
            if port, ok := inodeMap[inode]; ok {
                if !seen[port] {
                    ports = append(ports, port)
                    seen[port] = true
                }
            }
        }
    }
    sort.Ints(ports)
    
    // Join
    var sb strings.Builder
    for i, p := range ports {
        if i > 0 { sb.WriteString(",") }
        sb.WriteString(strconv.Itoa(p))
    }
    return sb.String()
}
