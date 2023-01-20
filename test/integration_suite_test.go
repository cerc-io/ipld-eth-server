package integration_test

import (
	"io/ioutil"
	"testing"

	"github.com/cerc-io/ipld-eth-server/v4/pkg/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "integration test suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(ioutil.Discard)
})
