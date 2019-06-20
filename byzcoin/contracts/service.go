package contracts

import "go.dedis.ch/cothority/v3/byzcoin"

func init() {
	byzcoin.RegisterContract(ContractValueID, contractValueFromBytes)
	byzcoin.RegisterContract(ContractCoinID, contractCoinFromBytes)
	byzcoin.RegisterContract(ContractInsecureDarcID, contractInsecureDarcFromBytes)
}
