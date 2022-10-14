package byzcoin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"

	"os"
	"bytes"
	"math/big"
	"math/rand"
	"encoding/gob"
	"strconv"
	"hash/fnv"

	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/pairing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	gnarkeddsa "github.com/consensys/gnark/std/signature/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std"
	"github.com/nswekosk/fred_go_toolkit"
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

// FRED configuration
var fredConfig = fred_go_toolkit.FredConfig{
	APIKey:   "ce1e45e6551de5db555a09b88d23682f",
	FileType: fred_go_toolkit.FileTypeXML,
	LogFile:  "fred.log",
}

type MonetaryCircuit struct {
	InflationPublicKey gnarkeddsa.PublicKey         `gnark:",public"`
	InflationSignature gnarkeddsa.Signature         `gnark:",public"`
	InflationMessage   frontend.Variable `gnark:",public"`
	OutputPublicKey gnarkeddsa.PublicKey         `gnark:",public"`
	OutputSignature gnarkeddsa.Signature         `gnark:",public"`
	OutputMessage   frontend.Variable `gnark:",public"`

	MonetaryPolicy   frontend.Variable `gnark:",public"`
	MonetaryPolicySignature gnarkeddsa.Signature         `gnark:",public"`
	NodePublicKey gnarkeddsa.PublicKey         `gnark:",public"`
}

func (circuit *MonetaryCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the inflation signature in the cs
	err = gnarkeddsa.Verify(curve, circuit.InflationSignature, circuit.InflationMessage, circuit.InflationPublicKey, &mimc)
	if err != nil {
		return err
	}

	// verify the output signature in the cs
	mimc.Reset()
	gnarkeddsa.Verify(curve, circuit.OutputSignature, circuit.OutputMessage, circuit.OutputPublicKey, &mimc)
	if err != nil {
		return err
	}

	// exemplary monetary policy
	monetaryPolicy := api.Add(api.Mul(circuit.InflationMessage, 2), api.Mul(circuit.OutputMessage, 3))
	api.AssertIsEqual(circuit.MonetaryPolicy, monetaryPolicy)

	// verify the node signature in the cs
	mimc.Reset()
	gnarkeddsa.Verify(curve, circuit.MonetaryPolicySignature, circuit.MonetaryPolicy, circuit.NodePublicKey, &mimc)
	if err != nil {
		return err
	}

	return err
}

func ProveMonetaryPolicy(serverIdentity *network.ServerIdentity) ([]byte, []byte, uint64, error) {
	var witness MonetaryCircuit

	// open ccs, pk
	ccsPtr, err := os.OpenFile("ccs.bin", os.O_RDONLY, 0666)
	if err != nil {
		log.Lvlf3("Error opening CCS: %s:", err)
		return nil, nil, 0, err
	}
	defer ccsPtr.Close()
	pkPtr, err := os.OpenFile("pk.bin", os.O_RDONLY, 0666)
	if err != nil {
		log.Lvlf3("Error opening Public Key: %s:", err)
		return nil, nil, 0, err
	}
	defer pkPtr.Close()

	ccs := plonk.NewCS(ecc.BN254)
	_, err = ccs.ReadFrom(ccsPtr)
	if err != nil {
		log.Lvlf3("Error reading CCS: %s:", err)
		return nil, nil, 0, err
	}

	pk := plonk.NewProvingKey(ecc.BN254)
	decG := gob.NewDecoder(pkPtr)
	err = decG.Decode(pk)
	if err != nil {
		log.Lvlf3("Public Key deserialization error (GOB): %s:", err)
		return nil, nil, 0, err
	}

	// generate private keys from the hash of Byzcoin service's private key
	privKeyService := serverIdentity.ServiceIdentities[0].GetPrivate()
	hexPrivKey, err := encoding.ScalarToStringHex(pairing.NewSuiteBn256(), privKeyService)
	if err != nil {
		log.Lvlf3("Private key encoding error: %s:", err)
		return nil, nil, 0, err
	}
	var h64 = fnv.New64()
	h64.Write([]byte(hexPrivKey))
	seed := int64(h64.Sum64())

	randomness := rand.New(rand.NewSource(seed))
	randomness2 := rand.New(rand.NewSource(seed))
	randomness3 := rand.New(rand.NewSource(seed))

	snarkCurve, err := twistededwards.GetSnarkCurve(tedwards.BN254)

	// generate parameters for the signatures
	privKey, err := eddsa.New(tedwards.BN254, randomness)
	privKey2, err := eddsa.New(tedwards.BN254, randomness2)
	privKeyNode, err := eddsa.New(tedwards.BN254, randomness3)

	// pick messages to sign
	var msgInflation, msgOutput *big.Int
	var monPolicy *big.Int

	// get inflation and output gap from FRED
	xmlFredClient, _ := fred_go_toolkit.CreateFredClient(fredConfig)
	params := make(map[string]interface{})

	// Median Consumer Price Index
	params["series_id"] = "MEDCPIM158SFRBCLE"
	srsObs, _ := xmlFredClient.GetSeriesObservations(params)
	inflation := srsObs.Observations[len(srsObs.Observations)-1].Value

	//Output gap calculation
	params["series_id"] = "GDPC1"
	srsObs, _ = xmlFredClient.GetSeriesObservations(params)
	rgdp, _ := strconv.ParseFloat(srsObs.Observations[len(srsObs.Observations)-1].Value, 8)
	lastDate := srsObs.Observations[len(srsObs.Observations)-1].Date

	params["series_id"] = "GDPPOT"
	params["observation_end"] = lastDate
	srsObs, _ = xmlFredClient.GetSeriesObservations(params)
	rpgdp, _ := strconv.ParseFloat(srsObs.Observations[len(srsObs.Observations)-1].Value, 8)

	outputGap := 100 * ((rgdp - rpgdp) / rpgdp)

	msgInflation, ok := big.NewInt(0).SetString(inflation, 10)
	if !ok {
		log.Lvlf3("SetString error on inflation conversion: %s", err)
		return nil, nil, 0, err
	}
	bigOutput := new(big.Float).SetFloat64(outputGap)
	msgOutput = big.NewInt(0)
	bigOutput.Int(msgOutput)

	// exemplary monetary policy
	monPolicy = big.NewInt(0).Add( big.NewInt(0).Mul(msgInflation, big.NewInt(2)), big.NewInt(0).Mul(msgOutput, big.NewInt(3)))
	msgData := msgInflation.Bytes()
	msgData2 := msgOutput.Bytes()
	monPolicyData := monPolicy.Bytes()

	// generate signatures
	signature, err := privKey.Sign(msgData[:], hash.MIMC_BN254.New())
	//assert.NoError(err, "signing message")
	signature2, err := privKey2.Sign(msgData2[:], hash.MIMC_BN254.New())
	//assert.NoError(err, "signing message")
	signatureMonPolicy, err := privKeyNode.Sign(monPolicyData[:], hash.MIMC_BN254.New())
	//assert.NoError(err, "signing message")

	// check if there is no problem in the signatures
	pubKey := privKey.Public()
	pubKey2 := privKey2.Public()
	pubKeyMonPolicy := privKeyNode.Public()


	witness.InflationMessage = msgInflation
	witness.InflationPublicKey.Assign(snarkCurve, pubKey.Bytes())
	witness.InflationSignature.Assign(snarkCurve, signature)
	witness.OutputMessage = msgOutput
	witness.OutputPublicKey.Assign(snarkCurve, pubKey2.Bytes())
	witness.OutputSignature.Assign(snarkCurve, signature2)

	witness.MonetaryPolicy = monPolicy
	witness.NodePublicKey.Assign(snarkCurve, pubKeyMonPolicy.Bytes())
	witness.MonetaryPolicySignature.Assign(snarkCurve, signatureMonPolicy)

	witnessInst, err := frontend.NewWitness(&witness, ecc.BN254)
	if err != nil {
		log.Lvlf3("Error generating witness: %s:", err)
		return nil, nil, 0, err
	}

	witnessPublic, err := frontend.NewWitness(&witness, ecc.BN254, frontend.PublicOnly())
	if err != nil {
		log.Lvlf3("Error generating public witness: %s:", err)
		return nil, nil, 0, err
	}

	//RegisterHints
	std.RegisterHints()

	proof, err := plonk.Prove(ccs, pk, witnessInst)
	if err != nil {
		log.Lvlf3("Error proving (PLONK): %s:", err)
		return nil, nil, 0, err
	}

	// encode proof
	buffProof := bytes.NewBuffer(nil)
	encGP := gob.NewEncoder(buffProof)
	err = encGP.Encode(proof)
	if err != nil {
		log.Lvlf3("Proof serialization error (GOB): %s:", err)
		return nil, nil, 0, err
	}

	// encode witnessPublic
	abWitness, err := witnessPublic.MarshalBinary() 
	if err != nil {
		log.Lvlf3("Witness serialization error: %s:", err)
		return nil, nil, 0, err
	}

	return buffProof.Bytes(), abWitness, monPolicy.Uint64(), nil
}


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

// ZKMintRewardsTx returns a transaction minting coins to the serverIdentity (with a ZK-proof)
func ZKMintRewardsTx(serverIdentity *network.ServerIdentity, signerCounter uint64) (ClientTransaction, error) {

	signer := darc.NewSignerEd25519(serverIdentity.Public, serverIdentity.GetPrivate())

	pubBuf, err := hex.DecodeString(serverIdentity.Public.String())
	if err != nil {
		return ClientTransaction{}, err
	}

	h := sha256.New()
	h.Write([]byte("coin"))
	h.Write(pubBuf)
	account := NewInstanceID(h.Sum(nil))

	proof, witness, coins, err := ProveMonetaryPolicy(serverIdentity)
	if (err != nil) {
		return ClientTransaction{}, err
	}

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
					// aprox. 1339 bytes
					{
						Name: "zkproof",
						Value: proof,
					},
					// aprox. 783 bytes
					{
						Name: "witness",
						Value: witness,
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
	//return MintRewardsTx(serverIdentity, uint64(CreateBlockReward), signerCounter+1)
	return ZKMintRewardsTx(serverIdentity, signerCounter+1)
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
