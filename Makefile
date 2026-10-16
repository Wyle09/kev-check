# Everything runs in Docker. Run `make help` for the targets.

BUILDER_IMAGE := hexpm/elixir:1.20.3-erlang-29.0.5-debian-trixie-20260824-slim

# compose.yaml reads SECRET_KEY_BASE from .env, so every Compose command needs it, even ps and down.
COMPOSE := docker compose
# App containers, found by Compose's own labels.
APP := docker ps --format '{{.Names}}' --filter label=com.docker.compose.project=kev-check --filter label=com.docker.compose.service=app

N ?= 2
comma := ,
# The knobs you pass, as an Elixir keyword list: "latency_ms: 400, error_rate: 0.2".
FAULTS := $(if $(LATENCY_MS),latency_ms: $(LATENCY_MS))$(if $(and $(LATENCY_MS),$(ERROR_RATE)),$(comma) )$(if $(ERROR_RATE),error_rate: $(ERROR_RATE))

.PHONY: help up status scale redeploy reload faults faults-reset kill-pod metrics logs down clean check

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-13s %s\n", $$1, $$2}'

up: ## Build the image and start everything
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory status

status: ## Show the containers and the URLs
	@$(COMPOSE) ps --format 'table {{.Name}}\t{{.State}}\t{{.Ports}}'
	@echo
	@echo "  app           http://localhost:8080/process?id=CVE-2021-44228"
	@echo "  Prometheus    http://localhost:9090"
	@echo "  Alertmanager  http://localhost:9093"

scale: ## Run N app containers, for example make scale N=4
	$(COMPOSE) up -d --no-recreate --scale app=$(N) app

redeploy: ## Rebuild the image and recreate the app containers
	$(COMPOSE) up -d --build app

reload: ## Check the Prometheus and Alertmanager config and rules, then reload them
	docker exec kev-check-prometheus-1 promtool check config /etc/prometheus/prometheus.yml
	docker exec kev-check-prometheus-1 promtool test rules /etc/prometheus/rules_test.yml
	docker exec kev-check-alertmanager-1 amtool check-config /etc/alertmanager/alertmanager.yml
	curl -fsS -X POST localhost:9090/-/reload
	curl -fsS -X POST localhost:9093/-/reload

faults: ## Change fault knobs on every app container, for example make faults LATENCY_MS=400 ERROR_RATE=0.2
	@test -n "$(FAULTS)" || { echo "Pass LATENCY_MS, ERROR_RATE, or both."; exit 1; }
	@for c in $$($(APP)); do \
	  printf '%s: ' $$c; docker exec $$c bin/kev_check rpc 'IO.inspect(KevCheck.Faults.put($(FAULTS)))'; \
	done

faults-reset: ## Put every app container's fault knobs back to their boot values
	@for c in $$($(APP)); do \
	  printf '%s: ' $$c; docker exec $$c bin/kev_check rpc 'IO.inspect(KevCheck.Faults.reset())'; \
	done

kill-pod: ## Crash one app container. Docker restarts it under the same name
	@c=$$($(APP) | head -1); echo "crashing $$c"; \
	docker exec $$c bin/kev_check rpc 'System.halt(1)' >/dev/null 2>&1 || true

metrics: ## Print one app container's kev_ and http_ metrics
	@c=$$($(APP) | head -1); port=$$(docker port $$c 9568 | head -1 | cut -d: -f2); \
	echo "$$c"; curl -fsS localhost:$$port/metrics | grep -E '^(kev|http)_'

logs: ## Follow the JSON log lines from every app container
	$(COMPOSE) logs -f app

down: ## Stop and remove the containers, keeping Prometheus's history
	$(COMPOSE) down

clean: ## Like down, and also delete Prometheus's history
	$(COMPOSE) down -v

# Named volumes keep the Linux deps and build apart from a local macOS one, and keep
# Hex and Dialyzer's PLT between runs.
check: ## Run format, compile, credo, tests, and dialyzer in the Elixir image
	docker run --rm -v "$(CURDIR)":/app -w /app \
	  -v kev-check-deps:/app/deps -v kev-check-build:/app/_build \
	  -e MIX_HOME=/app/_build/.mix -e HEX_HOME=/app/_build/.hex \
	  $(BUILDER_IMAGE) sh -c '\
	    mix local.hex --force --if-missing && mix local.rebar --force --if-missing && mix deps.get && \
	    mix format --check-formatted && mix compile --warnings-as-errors && mix credo --strict && \
	    mix test && mix dialyzer'
