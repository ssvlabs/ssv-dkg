package wire

//go:generate rm -f ./types_encoding.go
//go:generate go run github.com/ferranbt/fastssz/sszgen --include $GOPATH/pkg/mod/github.com/ssvlabs/dkg-spec@v1.0.2/ --path types.go --exclude-objs Identifier,TransportType,DepositDataCLI,KeySharesCLI,OperatorCLI,PongResult,Payload,ShareData,Data
