.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose -f keycloak/docker-compose.yml

.PHONY: help build up dev idp-up idp-down idp-logs idp-wait demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build both WASM components (release, wasm32-wasip1)
	cargo build --target wasm32-wasip1 --release

idp-up: ## Start Keycloak (imports the cp-demo realm on first run)
	$(COMPOSE) up -d

idp-wait: ## Block until Keycloak's OIDC discovery endpoint is live
	@echo "waiting for Keycloak discovery..."; \
	until curl -sf http://localhost:8080/realms/cp-demo/.well-known/openid-configuration >/dev/null; do \
	  sleep 2; printf '.'; done; echo " up"

idp-down: ## Stop and remove Keycloak (wipes the demo realm)
	$(COMPOSE) down -v

idp-logs: ## Tail Keycloak logs
	$(COMPOSE) logs -f

up: build ## Run the Spin app (assumes Keycloak already running)
	spin up --listen 127.0.0.1:3000

dev: ## Build + run with file-watch rebuilds
	spin up --build --listen 127.0.0.1:3000

demo: idp-up idp-wait build ## One command: start IdP, build, run the app
	spin up --listen 127.0.0.1:3000

clean: ## Remove build artifacts
	cargo clean
