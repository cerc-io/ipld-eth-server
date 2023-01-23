package eth

import "fmt"

type RequiresProxyError struct {
	method string
}

var _ error = RequiresProxyError{}

func (e RequiresProxyError) SetMethod(method string) {
	e.method = method
}

func (e RequiresProxyError) Error() string {
	return fmt.Sprintf("%s requires a configured proxy geth node", e.method)
}
