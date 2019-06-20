package byzcoin

import "sync"

// This static variable is a struct that contains the registry. It should be
// only accessed via the RegisterContract and GetContractConstructor methods.
var cr = contractRegistry{
	registry: make(map[string]ContractFn),
}

// We wrap registry to a struct with a mutex for thread safe operations.
type contractRegistry struct {
	sync.Mutex
	registry map[string]ContractFn
}

// RegisterContract adds a new contract constructor, or updates it
func RegisterContract(contractName string, contractFn ContractFn) {
	cr.Lock()
	defer cr.Unlock()
	cr.registry[contractName] = contractFn
}

// GetContractConstructor tries fo find a contract's constructor and returns it
func GetContractConstructor(contractName string) (fn ContractFn, exist bool) {
	cr.Lock()
	defer cr.Unlock()
	fn, exist = cr.registry[contractName]
	return
}
