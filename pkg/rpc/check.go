package rpc

import "github.com/ethereum/go-ethereum/rpc"

// checkModuleAvailability check that all names given in modules are actually
// available API services.
func checkModuleAvailability(modules []string, apis []rpc.API) (bad, available []string) {
	availableSet := make(map[string]struct{})
	for _, api := range apis {
		if _, ok := availableSet[api.Namespace]; !ok {
			availableSet[api.Namespace] = struct{}{}
			available = append(available, api.Namespace)
		}
	}
	for _, name := range modules {
		if _, ok := availableSet[name]; !ok {
			bad = append(bad, name)
		}
	}
	return bad, available
}
