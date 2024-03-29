package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

// ContractCoinID denotes a contract that can store and transfer coins.
const ContractCoinID = "coin"

// CoinName is a well-known InstanceID that identifies coins as belonging
// to this contract.
var CoinName = iid("byzCoin")

// ContractCoin is a coin implementation that holds one instance per coin.
// If you spawn a new ContractCoin, it will create an account with a value
// of 0 coins.
// The following methods are available:
//  - mint will add the number of coins in the argument "coins" to the
//    current coin instance. The argument must be a 64-bit uint in LittleEndian
//  - transfer will send the coins given in the argument "coins" to the
//    instance given in the argument "destination". The "coins"-argument must
//    be a 64-bit uint in LittleEndian. The "destination" must be a 64-bit
//    instanceID
//  - fetch takes "coins" out of the account and returns it as an output
//    parameter for the next instruction to interpret.
//  - store puts the coins given to the instance back into the account.
// You can only delete a contractCoin instance if the account is empty.

func contractCoinFromBytes(in []byte) (byzcoin.Contract, error) {
	c := &contractCoin{}
	err := protobuf.Decode(in, &c.Coin)
	if err != nil {
		return nil, xerrors.Errorf("couldn't unmarshal instance data: %v", err)
	}
	return c, nil
}

type contractCoin struct {
	byzcoin.BasicContract
	byzcoin.Coin
}

func (c *contractCoin) Spawn(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	// Spawn creates a new coin account as a separate instance.
	ca := inst.DeriveID("")
	// Previous versions had the 'public' argument to define which coinID to create. Later versions
	// use a more meaningful name of "coinID". For backwards-compatibility, we need both here, letting
	// the previous "public" have precedence over an eventual later "coinID".
	coinID := inst.Spawn.Args.Search("public")
	if coinID == nil {
		coinID = inst.Spawn.Args.Search("coinID")
	}
	if coinID != nil {
		ca = ContractCoinDeriveID(coinID)
	}
	if did := inst.Spawn.Args.Search("darcID"); did != nil {
		darcID = darc.ID(did)
	}
	log.Lvlf2("Spawning coin to %x, with darc %x", ca.Slice(), darcID[:])
	if t := inst.Spawn.Args.Search("type"); t != nil {
		if len(t) != len(byzcoin.InstanceID{}) {
			return nil, nil, xerrors.New("type needs to be an InstanceID")
		}
		c.Name = byzcoin.NewInstanceID(t)
	} else {
		c.Name = CoinName
	}
	c.Coin.Active = true
	var ciBuf []byte
	ciBuf, err = protobuf.Encode(&c.Coin)
	if err != nil {
		return nil, nil, xerrors.Errorf("couldn't encode CoinInstance: %v", err)
	}
	sc = []byzcoin.StateChange{
		byzcoin.NewStateChange(byzcoin.Create, ca, ContractCoinID, ciBuf, darcID),
	}
	return
}

func (c *contractCoin) Invoke(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	// Invoke is one of "mint", "transfer", "fetch", or "store".
	var coinsArg uint64
	if inst.Invoke.Command != "store" || inst.Invoke.Command != "toggleActive" {
		coinsBuf := inst.Invoke.Args.Search("coins")
		if coinsBuf == nil {
			err = xerrors.New("argument \"coins\" is missing")
			return
		}
		if len(coinsBuf) != 8 {
			err = xerrors.New("argument \"coins\" is wrong length")
			return
		}
		coinsArg = binary.LittleEndian.Uint64(coinsBuf)
	}

	switch inst.Invoke.Command {
	case "mint":
		if !c.Coin.Active { return }
		// mint simply adds this amount of coins to the account.
		log.Lvl2("minting", coinsArg)
		err = c.SafeAdd(coinsArg)
		if err != nil {
			return
		}
	case "transfer":
		if !c.Coin.Active { return }
		// transfer sends a given amount of coins to another account.
		target := inst.Invoke.Args.Search("destination")
		var (
			v   []byte
			cid string
			did darc.ID
		)
		if inst.InstanceID.Equal(byzcoin.NewInstanceID(target)) {
			err = xerrors.New("cannot send coins to ourselves")
			return
		}
		v, _, cid, did, err = rst.GetValues(target)
		if err == nil && cid != ContractCoinID {
			err = xerrors.New("destination is not a coin contract")
		}
		if err != nil {
			return
		}

		var targetCI byzcoin.Coin
		err = protobuf.Decode(v, &targetCI)
		if err != nil {
			return nil, nil, xerrors.Errorf("couldn't unmarshal target account: %v", err)
		}
		err = c.SafeSub(coinsArg)
		if err != nil {
			return
		}
		err = targetCI.SafeAdd(coinsArg)
		if err != nil {
			return
		}
		targetBuf, err := protobuf.Encode(&targetCI)
		if err != nil {
			return nil, nil, xerrors.Errorf("couldn't marshal target account: %v", err)
		}
		log.Lvlf2("transferring %d to %x", coinsArg, target)
		sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, byzcoin.NewInstanceID(target),
			ContractCoinID, targetBuf, did))
	case "fetch":
		if !c.Coin.Active { return }
		// fetch removes coins from the account and passes it on to the next
		// instruction.
		err = c.SafeSub(coinsArg)
		if err != nil {
			log.Warn("Tried to fetch", coinsArg, "but only had", c.Value)
			return
		}
		cout = append(cout, byzcoin.Coin{Name: c.Name, Value: coinsArg})
	case "store":
		if !c.Coin.Active { return }
		// store moves all coins from this instruction into the account.
		cout = []byzcoin.Coin{}
		for _, co := range coins {
			if c.Name.Equal(co.Name) {
				err = c.SafeAdd(co.Value)
				if err != nil {
					return
				}
			} else {
				cout = append(cout, co)
			}
		}
	case "toggleActive":
		// toggle active state of the coin
		log.Lvl2("toggling state of coin")
		c.Coin.Active = !c.Coin.Active
	default:
		err = xerrors.New("coin contract can only mine and transfer")
		return
	}

	// Finally update the coin value.
	var ciBuf []byte
	ciBuf, err = protobuf.Encode(&c.Coin)
	sc = append(sc, byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID,
		ContractCoinID, ciBuf, darcID))
	return
}

func (c *contractCoin) Delete(rst byzcoin.ReadOnlyStateTrie, inst byzcoin.Instruction, coins []byzcoin.Coin) (sc []byzcoin.StateChange, cout []byzcoin.Coin, err error) {
	cout = coins

	var darcID darc.ID
	_, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	if err != nil {
		return
	}

	if c.Value > 0 {
		err = xerrors.New("cannot destroy a coinInstance that still has coins in it")
		return
	}
	sc = byzcoin.StateChanges{
		byzcoin.NewStateChange(byzcoin.Remove, inst.InstanceID, ContractCoinID, nil, darcID),
	}
	return
}

// iid uses sha256(in) in order to manufacture an InstanceID from in
// thereby handling the case where len(in) != 32.
//
// TODO: Find a nicer way to make well-known instance IDs.
func iid(in string) byzcoin.InstanceID {
	h := sha256.New()
	h.Write([]byte(in))
	return byzcoin.NewInstanceID(h.Sum(nil))
}

// ContractCoinDeriveID derives a coin contract ID from a coinID argument.
func ContractCoinDeriveID(coinID []byte) byzcoin.InstanceID {
	h := sha256.New()
	h.Write([]byte(ContractCoinID))
	h.Write(coinID)
	return byzcoin.NewInstanceID(h.Sum(nil))
}

// ContractCoinSpawn returns the instruction necessary to spawn a coin,
// as well as the coinID.
// If the coinType is nil, the standard coinType will be used.
func ContractCoinSpawn(spawnerDarcID darc.ID,
	coinType *byzcoin.InstanceID) (byzcoin.Instruction,
	byzcoin.InstanceID) {
	coinID := random.Bits(256, true, random.New())
	instr := byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(spawnerDarcID),
		Spawn: &byzcoin.Spawn{
			ContractID: ContractCoinID,
			Args: byzcoin.Arguments{
				{Name: "coinID", Value: coinID},
				{Name: "darcID", Value: spawnerDarcID},
			},
		},
	}
	if coinType != nil {
		instr.Spawn.Args = append(instr.Spawn.Args, byzcoin.Argument{
			Name: "type", Value: coinType[:]})
	}
	return instr, ContractCoinDeriveID(coinID)
}

// ContractCoinMint returns the instruction necessary to mint coins.
// It supposes that the darc of the coin actually has a 'mint' rule.
func ContractCoinMint(coinID byzcoin.InstanceID, value uint64) byzcoin.Instruction {
	valueBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(valueBuf, value)
	return byzcoin.Instruction{
		InstanceID: coinID,
		Invoke: &byzcoin.Invoke{
			ContractID: ContractCoinID,
			Command:    "mint",
			Args: byzcoin.Arguments{
				{Name: "coins", Value: valueBuf},
			},
		},
	}
}

// ContractCoinTransfer returns the instruction necessary to transfer "value"
// coins from coinSrc to coinDst.
func ContractCoinTransfer(coinSrc, coinDst byzcoin.InstanceID,
	value uint64) byzcoin.Instruction {
	valueBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(valueBuf, value)
	return byzcoin.Instruction{
		InstanceID: coinSrc,
		Invoke: &byzcoin.Invoke{
			ContractID: ContractCoinID,
			Command:    "transfer",
			Args: byzcoin.Arguments{
				{Name: "coins", Value: valueBuf},
				{Name: "destination", Value: coinDst[:]},
			},
		},
	}
}
