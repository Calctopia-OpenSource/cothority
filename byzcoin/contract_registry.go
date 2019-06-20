package byzcoin

import "sync"

// This static variable is a struct that contains the registry. It should be
// only accessed via the RegisterContract and GetContractConstructor methods.

// ContractRegistry wraps registry to a struct with a mutex for thread safe
// operations.
type ContractRegistry struct {
	sync.Mutex
	registry map[string]ContractFn
}

// NewContractRegistry ...
func NewContractRegistry() ContractRegistry {
	return ContractRegistry{
		registry: make(map[string]ContractFn),
	}
}

// RegisterContract adds a new contract constructor, or updates it
func (c *ContractRegistry) RegisterContract(contractName string, contractFn ContractFn) {
	c.Lock()
	defer c.Unlock()
	c.registry[contractName] = contractFn
}

// GetContractConstructor tries fo find a contract's constructor and returns it
func (c *ContractRegistry) GetContractConstructor(contractName string) (fn ContractFn, exist bool) {
	c.Lock()
	defer c.Unlock()
	fn, exist = c.registry[contractName]
	return
}
