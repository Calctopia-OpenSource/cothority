package contracts

import (
	"errors"
	"strconv"
	"time"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/protobuf"
)

// The value contract can simply store a value in an instance and serves
// mainly as a template for other contracts. It helps show the possibilities
// of the contracts and how to use them at a very simple example.

// ContractCosiID denotes a contract that can aggregate signatures for a "root"
// instruction
var ContractCosiID = "cosi"

// ContractValue is a simple key/value storage where you
// can put any data inside as wished.
// It can spawn new value instances and will store the "value" argument in these
// new instances. Existing value instances can be updated and deleted.

// CosiData ...
type CosiData struct {
	RootCommand []byte
	RootDarcID  []byte
	Timestamp   int
	ExpireSec   int
}

type contractCosi struct {
	byzcoin.BasicContract
	CosiData
}

func contractCosiFromBytes(in []byte) (byzcoin.Contract, error) {
	// TODO: actuall fill it
	c := &contractCosi{}
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
	// - rootCommand:  ...
	// - rootDarcID:   ...
	// - expire sec:   ...
	cout = coins

	// Find the darcID for this instance.
	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	rootCommand := inst.Spawn.Args.Search("rootCommand")
	rootDarcID := inst.Spawn.Args.Search("rootDarcID")
	timestamp := int(time.Now().Unix())
	expireSec, err := strconv.Atoi(string(inst.Spawn.Args.Search("expireSec")))
	if err != nil {
		return nil, nil, errors.New("couldn't convert expireSec: " + err.Error())
	}

	data := CosiData{
		rootCommand,
		rootDarcID,
		timestamp,
		expireSec,
	}
	var ciBuf []byte
	ciBuf, err = protobuf.Encode(&data)
	if err != nil {
		return nil, nil, errors.New("couldn't encode CosiData: " + err.Error())
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, inst.DeriveID(""),
			ContractCosiID, ciBuf, darcID), // Sending only the rootCommand for the moment
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
	// Invoke should have the following input argument:
	//   - (name: []byte)
	//   - identity:  ...
	//   - signature: ...
	cout = coins

	// Find the darcID for this instance.
	var darcID darc.ID

	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	switch inst.Invoke.Command {
	case "update":
		sc = []byzcoin.StateChange{
			byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
				ContractCosiID, inst.Invoke.Args.Search("signature"), darcID),
		}
		return
	default:
		return nil, nil, errors.New("Cosi contract can only update")
	}
}

func (c *contractCosi) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	// This method should do the following:
	//   1. Check if the stored identities satisfy the referenced darc ID.
	//   2. If the check passes, execute the rootCommand and destroy the
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
