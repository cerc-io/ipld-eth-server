package eth_state_test

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"

	"github.com/cerc-io/ipld-eth-server/v5/pkg/eth"
)

func CheckGetSliceResponse(sliceResponse eth.GetSliceResponse, expectedResponse eth.GetSliceResponse) {
	Expect(sliceResponse.SliceID).To(Equal(expectedResponse.SliceID))
	Expect(sliceResponse.TrieNodes).To(Equal(expectedResponse.TrieNodes))
	Expect(sliceResponse.Leaves).To(Equal(expectedResponse.Leaves))
	Expect(sliceResponse.MetaData.NodeStats).To(Equal(expectedResponse.MetaData.NodeStats))
}

// EqualBigInt compares a hexutil.Big for equality with a big.Int or hexutil.Big value.
// It is an error for both actual and expected to be nil.  Use BeNil() instead.
func EqualBigInt(expected *big.Int) types.GomegaMatcher {
	return &BigIntEqualMatcher{
		Expected: expected,
	}
}

// EqualBigHex compares a hexutil.Big for equality with a big.Int or hexutil.Big value.
// It is an error for both actual and expected to be nil.  Use BeNil() instead.
func EqualBigHex(expected *hexutil.Big) types.GomegaMatcher {
	return &BigIntEqualMatcher{
		Expected: expected.ToInt(),
	}
}

type BigIntEqualMatcher struct {
	Expected *big.Int
}

func (matcher *BigIntEqualMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && matcher.Expected == nil {
		return false, fmt.Errorf("Refusing to compare <nil> to <nil>.\nBe explicit and use BeNil() instead.  This is to avoid mistakes where both sides of an assertion are erroneously uninitialized.")
	}

	var asInt *big.Int
	switch casted := actual.(type) {
	case *big.Int:
		asInt = casted
	case *hexutil.Big:
		asInt = (*big.Int)(casted)
	default:
		return false, fmt.Errorf("BigIntEqualMatcher expects a hexutil.Big or big.Int. Got:\n%s", format.Object(actual, 1))
	}
	return matcher.Expected.Cmp(asInt) == 0, nil
}

func (matcher *BigIntEqualMatcher) FailureMessage(actual interface{}) (message string) {
	actualString, actualOK := actual.(string)
	expectedString := matcher.Expected.String()
	if actualOK {
		return format.MessageWithDiff(actualString, "to equal", expectedString)
	}

	return format.Message(actual, "to equal", matcher.Expected)
}

func (matcher *BigIntEqualMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(actual, "not to equal", matcher.Expected)
}
