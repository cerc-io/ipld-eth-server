package fill_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFill(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ipld eth server fill test suite")
}
