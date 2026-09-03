# Observability kit (plan B1 / B7)

- `prometheus.yml` — scrape `127.0.0.1:8081/metrics` (admin port, loopback only).
- `alert-rules.yml` — SLO and security alerts (Alertmanager); thresholds in `docs/OBSERVABILITY.md`.
- `grafana-dashboard.json` — import into Grafana; select the Prometheus datasource.
- `promtail.yml` — ship the systemd journal (JSON logs) to Loki.

Install on the VPS:

```bash
sudo install -m0644 deploy/observability/alert-rules.yml /etc/prometheus/socrate-alert-rules.yml
sudo install -m0644 deploy/observability/prometheus.yml  /etc/prometheus/prometheus.yml   # or merge the scrape job
sudo promtool check rules /etc/prometheus/socrate-alert-rules.yml && sudo systemctl reload prometheus
```

Never expose `/metrics` through Caddy: it is served on the admin port for a reason.
