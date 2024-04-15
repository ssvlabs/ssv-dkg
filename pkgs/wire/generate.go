package wire

//go:generate rm -f ./types_encoding.go
//go:generate go run github.com/ferranbt/fastssz/sszgen --include $GOPATH/pkg/mod/github.com/bloxapp/dkg-spec@v0.0.0-20240411080414-3b15f3b8a745/ --path types.go --exclude-objs Identifier,TransportType,DepositDataCLI,KeySharesCLI,OperatorCLI,PongResult,Payload,ShareData,Data
