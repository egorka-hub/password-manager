BINARY := password-manager

.DEFAULT_GOAL := build
.PHONY: build run fmt fmt-check vet tidy check clean help

build: ## Собрать бинарник
	go build -o $(BINARY) .

run: ## Запустить без сборки бинарника
	go run .

fmt: ## Отформатировать код
	go fmt ./...

fmt-check: ## Проверить, что код отформатирован
	@test -z "$$(gofmt -l .)" || (echo "Не отформатированы:"; gofmt -l .; exit 1)

vet: ## Статический анализ
	go vet ./...

tidy: ## Привести в порядок go.mod и go.sum
	go mod tidy

check: fmt-check vet build ## Все проверки перед коммитом

clean: ## Удалить бинарник
	rm -f $(BINARY)

help: ## Список команд
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
