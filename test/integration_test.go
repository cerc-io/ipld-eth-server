package integration_test

import (
	"context"
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ethereum/go-ethereum/ethclient"
)

var _ = Describe("Integration test", func() {
	gethHttpPath := "http://127.0.0.1:8545"
	gethClient, err := ethclient.Dial(gethHttpPath)
	Expect(err).ToNot(HaveOccurred())

	ipldEthHttpPath := "http://127.0.0.1:8081"
	ipldClient, err := ethclient.Dial(ipldEthHttpPath)
	Expect(err).ToNot(HaveOccurred())

	Describe("get Block", func() {
		ctx := context.Background()

		gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(1))
		Expect(err).ToNot(HaveOccurred())
		Expect(gethBlock).ToNot(BeEmpty())

		ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(1))
		Expect(err).ToNot(HaveOccurred())
		Expect(ipldBlock).ToNot(BeEmpty())

	})

})

//func Test1(t *testing.T) {
//	gethHttpPath := "http://127.0.0.1:8545"
//	gethClient, err := ethclient.Dial(gethHttpPath)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	ipldEthHttpPath := "http://127.0.0.1:8081"
//	ipldClient, err := ethclient.Dial(ipldEthHttpPath)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	ctx := context.Background()
//
//	gethBlock, err := gethClient.BlockByNumber(ctx, big.NewInt(1))
//	if err != nil {
//		t.Fatal(err)
//	}
//	ipldBlock, err := ipldClient.BlockByNumber(ctx, big.NewInt(1))
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	t.Logf("Geth Block header: %+v", gethBlock.Header())
//	t.Logf("IPLD Block header: %+v", ipldBlock.Header())
//
//	t.Log("asdasd")
//}
