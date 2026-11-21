.PHONY: up down logs test clean

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

test:
	docker compose config -q
	bash -n attacks/simulate_from_kali.sh
	python3 -m py_compile scripts/parse_alerts.py
	python3 scripts/parse_alerts.py --cowrie logs/cowrie/cowrie.json --suricata logs/suricata/eve.json --out reports/alert_summary.md

clean:
	docker compose down -v --remove-orphans
	rm -f reports/alert_summary.md
