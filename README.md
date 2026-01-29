# Proc-Sentry

**Proc-Sentry** is a specialized, lightweight Prometheus exporter designed to monitor the **Top N** resource-consuming processes on Linux systems. It is built for performance, efficiency, and container awareness.

![Dashboard Preview](https://via.placeholder.com/800x200?text=Proc-Sentry+Grafana+Dashboard+Preview)

## 📌 Purpose

Standard exporters like `node_exporter` provide great system-level metrics but lack granular process details. Conversely, exporters that track _every_ process often suffer from "cardinality explosions" in Prometheus, consuming massive amounts of storage and memory.

**Proc-Sentry bridges this gap.** It intelligently scans all processes but only exports metrics for the top consumers of CPU, Memory, and Disk I/O. This gives you deep visibility into what's actually slowing down your node, without the overhead of monitoring thousands of idle processes.

## ✨ Benefits

- **🚀 Ultra Lightweight**: Written in Go, deployed as a static binary in a scratch-based Docker image (~12MB).
- **📉 Low Overhead**: Uses ~8MB RAM and negligible CPU. Zero Disk I/O impact.
- **🐳 Container Aware**: Automatically detects `container_id` for processes running in Docker, Containerd, or Kubernetes (Cgroups v1 & v2).
- **👤 User Context**: Resolves numeric UIDs to human-readable usernames (e.g., `root`, `nginx`, `postgres`).
- **🛡️ Secure**: Capabilities-aware (`SYS_PTRACE`), read-only root filesystem, and AppArmor compatible.
- **🧠 Architecture**: Uses a "Sort-Then-Select" strategy to ensure even if a process is high in Memory but low in CPU, it is still captured in the Memory Top N list.

## 🏗️ Architecture

1.  **Metric Collection**: A background goroutine scans `/proc` every scrape interval.
2.  **Data Processing**:
    - Reads `stat` (CPU), `status` (Memory), and `io` (Disk) for _all_ processes.
    - **User Resolution**: Maps UIDs to names using a cached `/etc/passwd` map.
    - **Container Detection**: Parses `/proc/[pid]/cgroup` to extract Container IDs.
3.  **Top N Logic**: The collector maintains three separate sorted lists (CPU, Memory, Disk IO). It selects the top `TOP_N` (default: 50) from _each_ list.
4.  **Port Resolution**: _Optimization_: It scans `net` statistics to find open ports _only_ for the identified Top N processes, avoiding expensive full-system scans.
5.  **Exposition**: Metrics are served via HTTP on port `9105`.

## ⚙️ Prometheus Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "proc-sentry"
    scrape_interval: 15s
    static_configs:
      - targets: ["<YOUR_NODE_IP>:9105"]
```

For **Kubernetes**, use a `PodMonitor` or `ServiceMonitor` if using the Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: proc-sentry
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: proc-sentry
  endpoints:
    - port: metrics
```

## 📊 Grafana Dashboard

We provide a professional dashboard covering CPU, Memory, Disk I/O, and Container linkage.

1.  **Download**: Get `grafana_dashboard.json` from this repository.
2.  **Import**:
    - Open Grafana.
    - Go to **Dashboards** > **New** > **Import**.
    - Upload the JSON file.
    - Select your Prometheus Datasource.

## 🛠️ Troubleshooting & Diagnostics

Use these commands to verify verify `proc-sentry` is reporting accurate data.

### 1. Verify Metrics Output

Check if the exporter is running and collecting data:

```bash
# Get raw metrics for Top CPU processes
curl -s localhost:9105/metrics | grep "proc_process_top_cpu_percent" | sort -nr -k 2 | head -n 5
```

### 2. Compare with `ps` (CPU)

Verify the top CPU consumers match standard Linux tools:

```bash
ps -eo pid,user,comm,%cpu --sort=-%cpu | head -n 6
```

### 3. Compare with `ps` (Memory)

Verify top Memory consumers (RSS):

```bash
ps -eo pid,user,comm,rss,%mem --sort=-%mem | head -n 6
```

_(Note: `ps` reports RSS in KB, while `proc-sentry` reports Bytes)_

### 4. Check Container Logs

If metrics are missing, check startup logs for permission issues:

```bash
docker logs proc-sentry
```

_Expected: `Starting proc-sentry on :9105 ...`_

## 📦 Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed installation instructions:

- [Docker Run](DEPLOYMENT.md#2-quick-start-docker)
- [Docker Compose](DEPLOYMENT.md#3-docker-compose)
- [Kubernetes (DaemonSet)](DEPLOYMENT.md#4-kubernetes)

## License

MIT License
