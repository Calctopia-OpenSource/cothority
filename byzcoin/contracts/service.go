package contracts

import "go.dedis.ch/cothority/v3/byzcoin"

func init() {
	byzcoin.Registry.RegisterContract(ContractValueID, contractValueFromBytes)
	byzcoin.Registry.RegisterContract(ContractCoinID, contractCoinFromBytes)
	byzcoin.Registry.RegisterContract(ContractInsecureDarcID, contractInsecureDarcFromBytes)
}
