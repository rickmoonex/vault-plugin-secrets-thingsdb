test_acc:
	./test/test_acc.sh

build:
	go build -o vault/plugins/vault-plugin-secrets-thingsdb cmd/vault-plugin-secrets-thingsdb/main.go