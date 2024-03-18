package wire

//go:generate rm -f ./types_encoding.go
//go:generate go run github.com/ferranbt/fastssz/sszgen --path types.go --exclude-objs Identifier,TransportType,DepositDataCLI,KeySharesCLI,OperatorCLI,PongResult,Payload,ShareData,Data
