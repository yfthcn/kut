LDFLAGS := -s -w

.PHONY: build linux sums test run-dry screenshots clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/kut .

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/kut-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/kut-linux-arm64 .
	$(MAKE) sums

# Yayın: ikililer kurulum betiğini gömülü taşır; yalnızca ikililer ve SHA256SUMS yüklenir.
sums:
	cd dist && sha256sum kut-linux-amd64 kut-linux-arm64 > SHA256SUMS

test:
	go vet ./...
	go test ./...

# Yerelde dene: wg/iptables'a dokunmaz.
run-dry: build
	@test -f ./data/server.json || ./dist/kut init -dry-run -data ./data -endpoint 203.0.113.10
	@test -f ./data/admin.json  || ./dist/kut passwd -data ./data
	./dist/kut serve -dry-run -data ./data

# README ekran görüntüleri: /tmp/kut-demo'da sahte verili dry-run, headless Chrome; sonunda demo dizini silinir.
screenshots:
	node tools/screenshots/shoot.mjs

clean:
	rm -rf dist data
