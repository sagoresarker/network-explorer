.PHONY: build run test

build:
	docker build -t traceroute-app .

run:
	docker run -p 8080:8080 -v logs:/app/logs traceroute-app

test:
	docker run --rm -v $(PWD):/app -w /app golang:1.20 go test ./...