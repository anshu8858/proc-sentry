# Proc-Sentry Deployment Guide

Proc-Sentry is designed to be lightweight and easy to deploy in any Linux container environment.

## 1. Prerequisites

- **Host OS**: Linux
- **Privileges**: Access to `/proc` is required. In Docker/K8s, this usually means mounting the host's `/proc` directory.
- **Capabilities**: `SYS_PTRACE` is required to inspect other processes.

## 2. Quick Start (Docker)

To run Proc-Sentry immediately with default settings:

```bash
docker run -d \
  --name proc-sentry \
  --restart always \
  --read-only \
  --cap-add=SYS_PTRACE \
  -v /proc:/host/proc:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /etc/passwd:/etc/passwd:ro \
  -p 9105:9105 \
  -e PROCFS_PATH=/host/proc \
  deziss/proc-sentry:latest
```

> **Note on `/proc`**: We mount the host's `/proc` to `/host/proc` inside the container and set `PROCFS_PATH=/host/proc`. This is the most compatible way to run on systems with strict AppArmor policies or Read-Only filesystems, preventing permission errors.

## 3. Docker Compose

For a more persistent setup, use `docker-compose.yml`.

### Configuration

Create a `docker-compose.yml` file:

```yaml
version: "3.8"

services:
  proc-sentry:
    image: deziss/proc-sentry:latest
    container_name: proc-sentry
    restart: always
    read_only: true
    cap_add:
      - SYS_PTRACE
    volumes:
      - /proc:/host/proc:ro # Monitor Host Processes
      - /sys/fs/cgroup:/sys/fs/cgroup:ro # Container ID detection
      - /etc/passwd:/etc/passwd:ro # User resolution
    environment:
      - PROCFS_PATH=/host/proc
      - TOP_N=50
      - ENABLE_DISK_IO=true
      - ENABLE_PORTS=true
    ports:
      - "9105:9105"
```

Start the service:

```bash
docker-compose up -d
```

## 4. Kubernetes

A `DaemonSet` is recommended to ensure `proc-sentry` runs on every node in your cluster.

### Apply Manifests

Use the included `k8s-manifest.yaml`:

```bash
kubectl apply -f k8s-manifest.yaml
```

This creates:

- A `DaemonSet` named `proc-sentry` in the `monitoring` namespace.
- A `Service` exposing port `9105`.

### Key Kubernetes Configurations

- **`hostPID: true`**: Crucial for visibility into all processes on the node.
- **`readOnlyRootFilesystem: true`**: Best practice for security.
- **`PROCFS_PATH`**: Configured to `/host/proc`.

## 5. Configuration Reference

The exporter is configured entirely via environment variables.

| Variable         | Default         | Description                                                            |
| :--------------- | :-------------- | :--------------------------------------------------------------------- |
| `TOP_N`          | `50`            | Number of top processes to track per metric (CPU, Mem, Disk).          |
| `ENABLE_DISK_IO` | `true`          | Enable/Disable Disk Read/Write metrics.                                |
| `ENABLE_PORTS`   | `true`          | Enable/Disable listening port resolution.                              |
| `PROCFS_PATH`    | `/proc`         | Path to the target `/proc` filesystem. Use `/host/proc` in containers. |
| `PROC_HOSTNAME`  | `os.Hostname()` | Override the `hostname` label value.                                   |
| `METRICS_PORT`   | `9105`          | Port to serve metrics on.                                              |

## 6. Prometheus Integration

Add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "proc-sentry"
    static_configs:
      - targets: ["<YOUR_HOST_IP>:9105"]
    # Or use kubernetes_sd_configs if deploying on K8s
```

## 7. Grafana Dashboard

A comprehensive Grafana dashboard is included (`grafana_dashboard.json`).

1. Open Grafana.
2. Go to **Dashboards** -> **Import**.
3. Upload `grafana_dashboard.json`.
4. Select your Prometheus datasource.

## 8. Troubleshooting

**Error: `permission denied` accessing `/inaccessible/path`**  
Ensure you are running with `--cap-add=SYS_PTRACE` and that AppArmor is not blocking ptrace. Using `PROCFS_PATH=/host/proc` usually mitigates AppArmor issues related to mounting `/proc` directly.

**Error: `read-only file system`**  
This is expected if you mounted volumes `:ro`. The application is designed to run with a read-only root file system. It writes no files.
