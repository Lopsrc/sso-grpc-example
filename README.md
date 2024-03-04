# sso-grpc-example

gRPC:       https://grpc.io/docs/languages/go/quickstart/
Protobuf:   https://protobuf.dev/getting-started/gotutorial/
Task:       https://taskfile.dev/installation/

# Usage

Run:
```
go run sso/cmd/sso/main.go
```
Generate a proto file:
```
cd protos/proto
task gen
```
Migrations:
```
cd sso
task mgrt
cd sso/tests
task mgrtst
```
