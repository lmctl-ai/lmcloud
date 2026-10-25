// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0

package providers

import (
	"context"
	"net"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/opentofu/opentofu/internal/plugin6"
	"github.com/opentofu/opentofu/internal/providers"
	proto6 "github.com/opentofu/opentofu/internal/tfplugin6"
)

func init() {
	if os.Getenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT") == "" {
		_ = os.Setenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT", "warn")
	}
	if os.Getenv("TF_LOG_SDK") == "" {
		_ = os.Setenv("TF_LOG_SDK", "off")
	}
	if os.Getenv("TF_LOG_SDK_PROTO") == "" {
		_ = os.Setenv("TF_LOG_SDK_PROTO", "off")
	}
	if os.Getenv("TF_LOG_PROVIDER") == "" {
		_ = os.Setenv("TF_LOG_PROVIDER", "off")
	}
}

// InProcessFrameworkFactory creates an in-process providers.Factory for a
// terraform-plugin-framework based provider. It runs completely in-memory
// via bufconn without subprocesses, network sockets, or external dependencies.
func InProcessFrameworkFactory(name string, p func() provider.Provider) providers.Factory {
	return func() (providers.Interface, error) {
		serverFunc := providerserver.NewProtocol6(p())
		lis := bufconn.Listen(1024 * 1024)
		s := grpc.NewServer()

		pluginServer := &tf6server.GRPCProviderPlugin{
			Name:         name,
			GRPCProvider: serverFunc,
			Opts: []tf6server.ServeOpt{
				tf6server.WithGoPluginLogger(hclog.NewNullLogger()),
			},
		}
		if err := pluginServer.GRPCServer(nil, s); err != nil {
			s.Stop()
			lis.Close()
			return nil, err
		}

		go func() {
			_ = s.Serve(lis)
		}()

		ctx := context.Background()
		conn, err := grpc.DialContext(ctx, "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			s.Stop()
			lis.Close()
			return nil, err
		}

		client := proto6.NewProviderClient(conn)
		return plugin6.NewInProcessGRPCProvider(ctx, client, s), nil
	}
}
