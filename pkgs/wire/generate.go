package wire

//go:generate rm -f ./types_encoding.go
//go:generate go run github.com/ferranbt/fastssz/sszgen --include $GOPATH/pkg/mod/github.com/ssvlabs/dkg-spec@v0.0.0-20240417085845-2f5e6b68f3ae/ --path types.go --exclude-objs Identifier,TransportType,DepositDataCLI,KeySharesCLI,OperatorCLI,PongResult,Payload,ShareData,Data
