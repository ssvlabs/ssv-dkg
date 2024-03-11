package spec

//go:generate rm -f ./types_encoding.go
//go:generate go run github.com/ferranbt/fastssz/sszgen --path types.go --exclude-objs Operator,Init,Reshare,Result
