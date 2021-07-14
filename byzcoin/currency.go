package byzcoin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"

	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/onet/v3/log"
)

/*
 Each node must have their own coin instance associated to their public key in order
  for them to receive crypto-currency rewards. An administrator must run:

	bcadmin mint bc-xxx.cfg key-xxx.cfg public-key #coins

  where bc-xxx.cfg is the configuration of the roster, key-xxx.cfg is the secret key
 of the admin, public-key is the public key of the node without a coin instance and 
 #coins the number of coins that are going to be minted to said account.
*/

// Reward for proposing a block (ProposeBlock @ byzcoin/tx_pipeline.go)
var CreateBlockReward = 20

// Reward for spawning BEVM contracts (executeInstruction @ byzcoin/service.go)
var SpawnBEVMReward = 10

// Reward for invoking BEVM contracts (executeInstruction @ byzcoin/service.go)
var InvokeBEVMReward = 10

// Reward for deleting BEVM contracts (executeInstruction @ byzcoin/service.go)
var DeleteBEVMReward = 10

// Reward for spawning contracts (executeInstruction @ byzcoin/service.go)
var SpawnContractReward = 10

// Reward for invoking contracts (executeInstruction @ byzcoin/service.go)
var InvokeContractReward = 10

// Reward for deleting contracts (executeInstruction @ byzcoin/service.go)
var DeleteContractReward = 10

// MintRewardsTx returns a transaction minting coins to the serverIdentity
func MintRewardsTx(serverIdentity *network.ServerIdentity, coins uint64, signerCounter uint64) (ClientTransaction, error) {

	signer := darc.NewSignerEd25519(serverIdentity.Public, serverIdentity.GetPrivate())

	pubBuf, err := hex.DecodeString(serverIdentity.Public.String())
	if err != nil {
		return ClientTransaction{}, err
	}

	h := sha256.New()
	h.Write([]byte("coin"))
	h.Write(pubBuf)
	account := NewInstanceID(h.Sum(nil))

	coinsBuf := make([]byte, 8)
	trueBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(coinsBuf, coins)
	binary.LittleEndian.PutUint64(trueBuf, 1)

	// build transaction
	ctx := ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: account,
			Invoke: &Invoke{
				ContractID: "coin",
				Command:    "mint",
				// mark transaction as a reward transaction
				Args: []Argument{
					{
						Name:  "coins",
						Value: coinsBuf,
					},
					{
						Name: "rewardTx",
						Value: trueBuf,
					},
				},
			},
			SignerIdentities: []darc.Identity{signer.Identity()},
			SignerCounter:    []uint64{signerCounter+1},
		}},
	}
	ctx.Instructions.SetVersion(CurrentVersion)

	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return ClientTransaction{}, err
	}

	return ctx, nil
}

// CreateBlockRewardTx returns a transaction rewarding block creation (createNewBlock @ byzcoin/service.go)
func CreateBlockRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("CreateBlockRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(CreateBlockReward), signerCounter+1)
}

// SpawnBEVMRewardTx returns a transaction that rewards spawning BEVM contracts (executeInstruction @ byzcoin/service.go)
func SpawnBEVMRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("SpawnBEVMRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(SpawnBEVMReward), signerCounter)
}

// InvokeBEVMRewardTx returns a transaction that rewards invoking BEVM contracts (executeInstruction @ byzcoin/service.go)
func InvokeBEVMRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("InvokeBEVMRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(InvokeBEVMReward), signerCounter)
}

// DeleteBEVMRewardTx returns a transaction that rewards deleting BEVM contracts (executeInstruction @ byzcoin/service.go)
func DeleteBEVMRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("DeleteBEVMRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(DeleteBEVMReward), signerCounter)
}

// SpawnContractRewardTx returns a transaction that rewards spawning contracts (executeInstruction @ byzcoin/service.go)
func SpawnContractRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("SpawnContractRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(SpawnContractReward), signerCounter)
}

// InvokeContractRewardTx returns a transaction that rewards invoking contracts (executeInstruction @ byzcoin/service.go)
func InvokeContractRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("InvokeContractRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(InvokeContractReward), signerCounter)
}

// DeleteContractRewardTx returns a transaction that rewards deleting contracts (executeInstruction @ byzcoin/service.go)
func DeleteContractRewardTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {
	log.Lvl1("DeleteContractRewardTx invoked")
	return MintRewardsTx(serverIdentity, uint64(DeleteContractReward), signerCounter)
}
