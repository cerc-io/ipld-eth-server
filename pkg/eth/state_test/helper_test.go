package eth_state_test

import (
	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
	. "github.com/onsi/gomega"
)

func CheckGetSliceResponse(sliceResponse eth.GetSliceResponse, expectedResponse eth.GetSliceResponse) {
	Expect(sliceResponse.SliceID).To(Equal(expectedResponse.SliceID))
	Expect(sliceResponse.TrieNodes).To(Equal(expectedResponse.TrieNodes))
	Expect(sliceResponse.Leaves).To(Equal(expectedResponse.Leaves))
	Expect(sliceResponse.MetaData.NodeStats).To(Equal(expectedResponse.MetaData.NodeStats))
}
