# Systemd Service Configuration

## Installation

```bash
sudo cp hng-detector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hng-detector
sudo systemctl start hng-detector
```

## Management

```bash
sudo systemctl status hng-detector
sudo systemctl stop hng-detector
sudo systemctl restart hng-detector
sudo journalctl -u hng-detector -f
```

## Configuration

Edit `/etc/systemd/system/hng-detector.service` to:
- Change `NGINX_LOG_PATH`
- Enable/disable Slack alerts
- Change dashboard port
- Adjust resource limits

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart hng-detector
```
