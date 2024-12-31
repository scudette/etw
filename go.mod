module github.com/Velocidex/etw

go 1.13

require (
	github.com/Microsoft/go-winio v0.5.0
	github.com/Velocidex/ordereddict v0.0.0-20230909174157-2aa49cc5d11d
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.20.0
	golang.org/x/text v0.21.0 // indirect
	www.velocidex.com/golang/binparsergen v0.1.1-0.20240404114946-8f66c7cf586e
	www.velocidex.com/golang/go-pe v0.1.1-0.20230228112150-ef2eadf34bc3
)

replace www.velocidex.com/golang/go-pe => ../go-pe
