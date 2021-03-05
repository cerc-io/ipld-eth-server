package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vulcanize/gap-filler/pkg/mux"
	"github.com/vulcanize/gap-filler/pkg/qlservices"
)

var ErrNoRpcEndpoints = errors.New("no rpc endpoints is available")

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "serve chain data from PG-IPFS or proxy geths",
	Long: `This command configures a VulcanizeDB ipld-eth-server graphql server.

`,
	Run: func(cmd *cobra.Command, args []string) {
		subCommand = cmd.CalledAs()
		logWithCommand = *logrus.WithField("SubCommand", subCommand)
		proxy()
	},
}

func proxy() {
	gqlDefaultAddr, err := url.Parse(viper.GetString("gql.default"))
	if err != nil {
		logWithCommand.Fatal(err)
	}

	gqlTracingAPIAddr, err := url.Parse(viper.GetString("gql.tracing"))
	if err != nil {
		logWithCommand.Fatal(err)
	}

	rpcClients, err := parseRpcAddresses(viper.GetString("rpc.eth"))
	if err != nil {
		logrus.Error("bad rpc.eth addresses")
		logWithCommand.Fatal(err)
	}

	rpcBalancer, err := qlservices.NewBalancer(rpcClients)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	tracingClients, err := parseRpcAddresses(viper.GetString("rpc.tracing"))
	if err != nil {
		logrus.Error("bad rpc.tracing addresses")
		logWithCommand.Fatal(err)
	}

	tracingBalancer, err := qlservices.NewBalancer(tracingClients)
	if err != nil {
		logWithCommand.Fatal(err)
	}

	router, err := mux.NewServeMux(&mux.Options{
		BasePath:       viper.GetString("http.path"),
		EnableGraphiQL: viper.GetBool("gql.gui"),
		Postgraphile: mux.PostgraphileOptions{
			Default:    gqlDefaultAddr,
			TracingAPI: gqlTracingAPIAddr,
		},
		RPC: mux.RPCOptions{
			DefaultBalancer: rpcBalancer,
			TracingBalancer: tracingBalancer,
		},
	})
	if err != nil {
		logWithCommand.Fatal(err)
	}

	addr := fmt.Sprintf("%s:%s", viper.GetString("http.host"), viper.GetString("http.port"))
	if err := http.ListenAndServe(addr, router); err != nil {
		logWithCommand.Fatal(err)
	}
}

func parseRpcAddresses(value string) ([]*rpc.Client, error) {
	rpcAddresses := strings.Split(value, ",")
	rpcClients := make([]*rpc.Client, 0, len(rpcAddresses))
	for _, address := range rpcAddresses {
		rpcClient, err := rpc.Dial(address)
		if err != nil {
			logWithCommand.Errorf("couldn't connect to %s. Error: %s", address, err)
			continue
		}

		rpcClients = append(rpcClients, rpcClient)
	}

	if len(rpcClients) == 0 {
		logWithCommand.Error(ErrNoRpcEndpoints)
		return nil, ErrNoRpcEndpoints
	}

	return rpcClients, nil
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	// flags
	proxyCmd.PersistentFlags().String("http-host", "127.0.0.1", "http host")
	proxyCmd.PersistentFlags().String("http-port", "8080", "http port")
	proxyCmd.PersistentFlags().String("http-path", "/", "http base path")

	proxyCmd.PersistentFlags().String("rpc-eth", "http://127.0.0.1:8545", "comma separated ethereum rpc addresses. Example http://127.0.0.1:8545,http://127.0.0.2:8545")
	proxyCmd.PersistentFlags().String("rpc-tracing", "http://127.0.0.1:8000", "comma separated traicing api addresses")

	proxyCmd.PersistentFlags().String("gql-default", "http://127.0.0.1:5020/graphql", "postgraphile address")
	proxyCmd.PersistentFlags().String("gql-tracing", "http://127.0.0.1:5020/graphql", "tracing api postgraphile address")
	proxyCmd.PersistentFlags().Bool("gql-gui", false, "enable graphiql interface")

	// and their .toml config bindings
	viper.BindPFlag("http.host", proxyCmd.PersistentFlags().Lookup("http-host"))
	viper.BindPFlag("http.port", proxyCmd.PersistentFlags().Lookup("http-port"))
	viper.BindPFlag("http.path", proxyCmd.PersistentFlags().Lookup("http-path"))

	viper.BindPFlag("rpc.eth", proxyCmd.PersistentFlags().Lookup("rpc-eth"))
	viper.BindPFlag("rpc.tracing", proxyCmd.PersistentFlags().Lookup("rpc-tracing"))

	viper.BindPFlag("gql.default", proxyCmd.PersistentFlags().Lookup("gql-default"))
	viper.BindPFlag("gql.tracing", proxyCmd.PersistentFlags().Lookup("gql-tracing"))
	viper.BindPFlag("gql.gui", proxyCmd.PersistentFlags().Lookup("gql-gui"))
}
