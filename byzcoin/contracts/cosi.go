package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/protobuf"
)

// The cosi contract stands for "Collective Signing" and allows a group of
// signers to agree on and sign a proposed transaction, the "root transaction".

// ContractCosiID denotes a contract that can aggregate signatures for a "root"
// instruction
var ContractCosiID = "cosi"

// CosiData ...
type CosiData struct {
	RootTransaction byzcoin.ClientTransaction
	Timestamp       uint64
	ExpireSec       uint64
	Hash            []byte
}

type contractCosi struct {
	byzcoin.BasicContract
	CosiData
	s *byzcoin.Service
}

func (s *Service) contractCosiFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &contractCosi{s: s.byzService()}

	err := protobuf.Decode(in, &c.CosiData)
	if err != nil {
		return nil, errors.New("couldn't unmarshal instance data: " + err.Error())
	}
	return c, nil
}

func (c *contractCosi) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	// This method should do the following:
	//   1. Check if the given root darc ID is allowed to use the given root
	//      command.
	//   2. Store the root command, root darc id, current timestamp, and expire
	//      sec.
	//
	// Spawn should have those input arguments:
	// - (name: []byte)
	// - rootTransaction:  ...
	// - rootDarcID:   ...
	// - expire sec:   ...
	cout = coins

	// Find the darcID for this instance.
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	rootTransaction := byzcoin.ClientTransaction{}
	err = protobuf.Decode(inst.Spawn.Args.Search("rootTransaction"), &rootTransaction)
	timestamp := uint64(time.Now().Unix())
	expireSec, err := strconv.ParseUint(string(inst.Spawn.Args.Search("expireSec")), 10, 64)
	if err != nil {
		return nil, nil, errors.New("couldn't convert expireSec: " + err.Error())
	}
	hash := hashCosi(rootTransaction.Instructions[0], timestamp)

	data := CosiData{
		rootTransaction,
		timestamp,
		expireSec,
		hash,
	}
	var dataBuf []byte
	dataBuf, err = protobuf.Encode(&data)
	if err != nil {
		return nil, nil, errors.New("couldn't encode CosiData: " + err.Error())
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""),
			ContractCosiID, dataBuf, darcID),
	}
	return
}

func (c *contractCosi) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	// This method should do the following:
	//   1. Check if the identity matches the given signature with respect to
	//      the root command and the root darc ID.
	//   2. If the check is successful, add the identity the the list of
	//      identities.
	//
	// Invoke:addProof should have the following input argument:
	//   - (name: []byte)
	//   - identity:  ... of type darc.Identity
	//   - signature: ... of type string
	cout = coins

	// Find the darcID for this instance.
	var darcID darc.ID

	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	switch inst.Invoke.Command {
	case "addProof":
		identityBuf := inst.Invoke.Args.Search("identity")
		if identityBuf == nil {
			return nil, nil, errors.New("Identity args is nil")
		}
		identity := darc.Identity{}
		err = protobuf.Decode(identityBuf, &identity)
		if err != nil {
			return nil, nil, errors.New("Couldn't decode Identity")
		}
		signature := inst.Invoke.Args.Search("signature")
		if signature == nil {
			return nil, nil, errors.New("Signature args is nil")
		}
		c.CosiData.RootTransaction.Instructions[0].SignerIdentities = append(c.CosiData.RootTransaction.Instructions[0].SignerIdentities, identity)
		c.CosiData.RootTransaction.Instructions[0].Signatures = append(c.CosiData.RootTransaction.Instructions[0].Signatures, signature)
		cosiDataBuf, err2 := protobuf.Encode(&c.CosiData)
		if err2 != nil {
			return nil, nil, errors.New("Couldn't encode CosidData")
		}
		sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
			ContractCosiID, cosiDataBuf, darcID))
		return
	case "execRoot":
		instruction := c.CosiData.RootTransaction.Instructions[0]

		rootInstructionID := instruction.DeriveID("").Slice()

		sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
			ContractCosiID, rootInstructionID, darcID))

		instructionType := instruction.GetType()
		if instructionType == byzcoin.SpawnType {
			fn, exists := c.s.GetContractConstructor(instruction.Spawn.ContractID)
			if !exists {
				return nil, nil, errors.New("Couldn't get the root function")
			}
			rootInstructionBuff, err := protobuf.Encode(&c.CosiData.RootTransaction.Instructions[0])
			if err != nil {
				return nil, nil, errors.New("Couldn't encode the root instruction buffer")
			}
			contract, err := fn(rootInstructionBuff)
			if err != nil {
				return nil, nil, errors.New("Couldn't get the root contract")
			}

			err = contract.VerifyDeferedInstruction(rst, instruction, c.CosiData.Hash)
			if err != nil {
				return nil, nil, fmt.Errorf("Verifying the root instruction failed: %s", err)
			}

			rootSc, _, err := contract.Spawn(rst, c.CosiData.RootTransaction.Instructions[0], coins)
			sc = append(sc, rootSc...)
		}
		return
	default:
		return nil, nil, errors.New("Cosi contract can only addProof and execRoot")
	}
}

func (c *contractCosi) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	// This method should do the following:
	//   1. Check if the stored identities satisfy the referenced darc ID.
	//   2. If the check passes, execute the rootTransaction and destroy the
	//      stored identities.
	cout = coins

	// Find the darcID for this instance.
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	sc = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractCosiID, nil, darcID),
	}
	return
}

// VerifyInstruction overrides the basic VerifyInstruction in case of a "mine" command, because this command
// is not protected by a darc, but by a linkable ring signature.
func (c *contractCosi) VerifyInstruction(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, ctxHash []byte) error {
	if inst.GetType() == byzcoin.InvokeType && inst.Invoke.Command == "addProof" {
		// Standard check if the client can actually perform an "addProof"
		err := c.BasicContract.VerifyInstruction(rst, inst, ctxHash)
		if err != nil {
			return err
		}
		// Second check if the client has the right to sign the rootInstruction
		// TODO...
		// ...
		return nil
	}
	if inst.GetType() == byzcoin.InvokeType && inst.Invoke.Command == "execRoot" {
		// Here we need to build the instruction from the root instruction and
		// verify it without taking the counters into account.
		return nil
	}
	// Should never reach this point
	return nil
}

// This is a modified version of computing the hash of a transaction. In this
// version, we do not take into account the signers nor the signers counters. We
// also add to the hash a timestamp.
func hashCosi(instr byzcoin.Instruction, timestamp uint64) []byte {
	h := sha256.New()
	h.Write(instr.InstanceID[:])
	var args []byzcoin.Argument
	switch instr.GetType() {
	case byzcoin.SpawnType:
		h.Write([]byte{0})
		h.Write([]byte(instr.Spawn.ContractID))
		args = instr.Spawn.Args
	case byzcoin.InvokeType:
		h.Write([]byte{1})
		h.Write([]byte(instr.Invoke.ContractID))
		args = instr.Invoke.Args
	case byzcoin.DeleteType:
		h.Write([]byte{2})
		h.Write([]byte(instr.Delete.ContractID))
	}
	for _, a := range args {
		nameBuf := []byte(a.Name)
		nameLenBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(nameLenBuf, uint64(len(nameBuf)))
		h.Write(nameLenBuf)
		h.Write(nameBuf)

		valueLenBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueLenBuf, uint64(len(a.Value)))
		h.Write(valueLenBuf)
		h.Write(a.Value)
	}
	timestampBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBuf, timestamp)
	h.Write(timestampBuf)

	return h.Sum(nil)
}
