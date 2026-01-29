# Proc-Sentry

**Proc-Sentry** (formerly known as `atop-exporter`) is a lightweight, high-performance Prometheus exporter for Linux process metrics.

Unlike standard node exporters that give you aggregate system stats, or heavy full-system monitors, **Proc-Sentry** focuses on identifying the **Top N** resource-consuming processes (CPU, Memory, Disk I/O) and exposing their details to Prometheus.

![Dashboard Preview](https://via.placeholder.com/800x200?text=Proc-Sentry+Grafana+Dashboard+Preview)

## Key Features

- **Lightweight**: Static Go binary, scratch-based Docker image (~12MB).
- **Performance**: Extremely low CPU/Memory footprint.
- **Top N Monitoring**: Tracks top processes by CPU, Memory, and Disk I/O independently (Default: Top 50).
- **Container Aware**: Automatically detects `container_id` for processes running in Docker/Containerd (Cgroups v1 & v2).
- **User Resolution**: Resolves UIDs to usernames (e.g., `root`, `nginx`) by parsing `/etc/passwd`.
- **Smart Port Resolution**: Efficiently identifies listening ports for top processes without scanning the whole system.
- **Secure**: Designed to run with a Read-Only root filesystem and supports AppArmor environments via `PROCFS_PATH` redirection.

## Quick Start

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

Metrics will be available at `http://localhost:9105/metrics`.

## Documentation

- [Deployment Guide](DEPLOYMENT.md) - Full instructions for Docker, Compose, and Kubernetes.
- [Performance Report](PERFORMANCE.md) - Details on resource usage and scrape latency.

## Configuration

| Env Var          | Default | Description                                                                 |
| :--------------- | :------ | :-------------------------------------------------------------------------- |
| `TOP_N`          | `50`    | Number of top processes to track using separate sorters for CPU, Mem, Disk. |
| `ENABLE_DISK_IO` | `true`  | Set to `false` to disable disk stats.                                       |
| `ENABLE_PORTS`   | `true`  | Set to `false` to disable port resolution (saves resources).                |
| `PROCFS_PATH`    | `/proc` | Directory where `/proc` is mounted (use `/host/proc` in Docker).            |

## Grafana Dashboard

A ready-to-use Grafana dashboard is provided in [grafana_dashboard.json](grafana_dashboard.json).

## License

MIT License
