#!/bin/bash

echo "=== HNG Detector Status ==="
echo "Service Status:"
sudo systemctl status hng-detector --no-pager

echo ""
echo "Recent Logs:"
sudo journalctl -u hng-detector -n 20 --no-pager

echo ""
echo "Resource Usage:"
ps aux | grep "python -m detector.main" | grep -v grep

echo ""
echo "Dashboard Accessibility:"
curl -s http://localhost:8080 | head -5
