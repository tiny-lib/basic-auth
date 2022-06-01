# basic-auth

basic auth middleware for go-kratos

usage using go-kratos examples helloworld

```go
package main

import (
	"context"
	"fmt"
	"log"

	baseAuth "github.com/czyt/basic-auth"
	"github.com/go-kratos/examples/helloworld/helloworld"
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
)

type server struct {
	helloworld.UnimplementedGreeterServer

	hc helloworld.GreeterClient
}

func (s *server) SayHello(ctx context.Context, in *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	return &helloworld.HelloReply{Message: fmt.Sprintf("hello,%s", in.Name)}, nil
}

func main() {
	httpSrv := http.NewServer(
		http.Address(":8000"),
		http.Middleware(
			baseAuth.Server(baseAuth.WithAuthentication("czyt", "admin")),
		),
	)
	grpcSrv := grpc.NewServer(
		grpc.Address(":9000"),
		grpc.Middleware(
			baseAuth.Server(baseAuth.WithValidator(func(user string, pwd string, ctx context.Context) (bool, error) {
				if user == "czyt" && pwd == "grpc" {
					return true, nil
				}
				return false, errors.New(401, "授权失败", "账号或密码不正确！")
			})),
		),
	)
	con, _ := grpc.DialInsecure(
		context.Background(),
		grpc.WithEndpoint("dns:///127.0.0.1:9001"),
		grpc.WithMiddleware(
			baseAuth.Client(baseAuth.WithAuthentication("czyt", "admin")),
		),
	)
	s := &server{
		hc: helloworld.NewGreeterClient(con),
	}
	helloworld.RegisterGreeterServer(grpcSrv, s)
	helloworld.RegisterGreeterHTTPServer(httpSrv, s)
	app := kratos.New(
		kratos.Name("helloworld"),
		kratos.Server(
			httpSrv,
			grpcSrv,
		),
	)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

```