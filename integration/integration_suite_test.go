package integration_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "integration test suite")
}

var (
	gethHttpPath    = "http://127.0.0.1:8545"
	ipldEthHttpPath = "http://127.0.0.1:8081"

	gethClient    *ethclient.Client
	ipldClient    *ethclient.Client
	gethRPCClient *rpc.Client
	ipldRPCClient *rpc.Client

	testChainId int64 = 99
)

var _ = BeforeSuite(func() {
	var err error

	envChainID := os.Getenv("ETH_CHAIN_ID")
	if len(envChainID) == 0 {
		panic("ETH_CHAIN_ID must be set")
	}
	testChainId, err = strconv.ParseInt(envChainID, 10, 64)
	Expect(err).ToNot(HaveOccurred())

	if path := os.Getenv("ETH_HTTP_PATH"); len(path) != 0 {
		gethHttpPath = "http://" + path
	}
	if path := os.Getenv("SERVER_HTTP_PATH"); len(path) != 0 {
		ipldEthHttpPath = "http://" + path
	}

	gethClient, err = ethclient.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldClient, err = ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())
})
