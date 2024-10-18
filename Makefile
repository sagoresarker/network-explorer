.PHONY: build run stop clean logs test help

# Docker Compose files
COMPOSE_FILE=docker-compose.yml

# Colors for terminal output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_CYAN=\033[36m

help: ## Show this help message
	@echo '${COLOR_BOLD}Usage:${COLOR_RESET}'
	@echo '  make ${COLOR_CYAN}<target>${COLOR_RESET}'
	@echo ''
	@echo '${COLOR_BOLD}Targets:${COLOR_RESET}'
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  ${COLOR_CYAN}%-15s${COLOR_RESET} %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the application containers
	@echo "${COLOR_GREEN}Building application containers...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) build

run: ## Run the application
	@echo "${COLOR_GREEN}Starting application...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) up
	@echo "${COLOR_YELLOW}Application is running at http://localhost:8090${COLOR_RESET}"

stop: ## Stop the application
	@echo "${COLOR_GREEN}Stopping application...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) down

clean: stop ## Stop and remove containers, networks, images, and volumes
	@echo "${COLOR_GREEN}Cleaning up...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) down -v --rmi all

logs: ## View application logs
	@echo "${COLOR_GREEN}Showing logs...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) logs -f

test: ## Run tests
	@echo "${COLOR_GREEN}Running tests...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) exec app go test ./...

restart: stop run ## Restart the application

ps: ## Show running containers
	@echo "${COLOR_GREEN}Showing running containers...${COLOR_RESET}"
	docker-compose -f $(COMPOSE_FILE) ps

build-host:
	@echo "${COLOR_GREEN}Building application containers with host network...${COLOR_RESET}"
	docker build -t traceroute-app .

run-host:
	@echo "${COLOR_GREEN}Starting application with host network...${COLOR_RESET}"
	docker run -p 8090:8090 --network host traceroute-app

