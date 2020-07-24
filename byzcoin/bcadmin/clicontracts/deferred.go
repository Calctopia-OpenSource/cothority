package clicontracts

import (
	"encoding/binary"
	"encoding/hex"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/xerrors"

	"go.dedis.ch/onet/v3/log"

	"github.com/urfave/cli"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/byzcoin/bcadmin/lib"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/protobuf"
)

// DeferredSpawn is used to spawn a new deferred contract. It expects stdin to
// contain the proposed transaction.
func DeferredSpawn(c *cli.Context) error {
	// Here is what this function does:
	//   1. Parses the stdin in order to get the proposed transaction
	//   2. Fires a spawn instruction for the deferred contract
	//   3. Gets the response back

	// ---
	// 1.
	// ---
	proposedTransactionBuf, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return xerrors.Errorf("failed to read from stding: %v", err)
	}

	proposedTransaction := byzcoin.ClientTransaction{}
	err = protobuf.Decode(proposedTransactionBuf, &proposedTransaction)
	if err != nil {
		return xerrors.Errorf("failed to decode transaction, did you use --export ?: %v", err)
	}

	// ---
	// 2.
	// ---
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	dstr := c.String("darc")
	if dstr == "" {
		dstr = cfg.AdminDarc.GetIdentityString()
	}
	d, err := lib.GetDarcByString(cl, dstr)
	if err != nil {
		return err
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return err
	}

	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return xerrors.Errorf("couldn't get signer counters: %+v", err)
	}

	spawn := byzcoin.Spawn{
		ContractID: byzcoin.ContractDeferredID,
		Args: []byzcoin.Argument{
			{
				Name:  "proposedTransaction",
				Value: proposedTransactionBuf,
			},
		},
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID(d.GetBaseID()),
		Spawn:         &spawn,
		SignerCounter: []uint64{counters.Counters[0] + 1},
	})
	if err != nil {
		return err
	}

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}

	if lib.FindRecursivefBool("export", c) {
		return lib.ExportTransaction(ctx)
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	instID := ctx.Instructions[0].DeriveID("").Slice()
	log.Infof("Spawned a new deferred contract. Its instance id is:\n%x", instID)

	// ---
	// 3.
	// ---
	proof, err := cl.WaitProof(byzcoin.NewInstanceID(instID), time.Second, nil)
	if err != nil {
		return xerrors.Errorf("couldn't get proof for admin-darc: %+v", err)
	}

	_, resultBuf, _, _, err := proof.KeyValue()
	if err != nil {
		return xerrors.Errorf("couldn't get value out of proof: %v", err)
	}

	result := byzcoin.DeferredData{}
	err = protobuf.Decode(resultBuf, &result)
	if err != nil {
		return xerrors.Errorf("couldn't decode the result: %v", err)
	}

	log.Infof("Here is the deferred data:\n%s", result)

	return lib.WaitPropagation(c, cl)
}

// DeferredInvokeAddProof is used to add the proof of a proposed transaction's
// instruction. The proof is computed on the given --hash and based on the
// identity provided by --sign or, by default, the admin.
func DeferredInvokeAddProof(c *cli.Context) error {
	// Here is what this function does:
	//   1. Parses the inoput arguments
	//   2. Computes the signature based on the identity (--sign), the
	//      instruction id (--instrIdx), and the hash (--hash)
	//   3. Sends the addProof transaction
	//   4. Reads the transaction return value (deferred data)

	// ---
	// 1.
	// ---
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return err
	}

	hashStr := c.String("hash")
	if hashStr == "" {
		return xerrors.New("--hash not found")
	}
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		return xerrors.Errorf("coulndn't decode the hash string: %v", err)
	}

	instID := c.String("instid")
	if instID == "" {
		return xerrors.New("--instid flag is required")
	}
	instIDBuf, err := hex.DecodeString(instID)
	if err != nil {
		return xerrors.Errorf("failed to decode the instid string: %v", err)
	}

	instrIdx := c.Uint("instrIdx")
	index := uint32(instrIdx)
	indexBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBuf, uint32(index))

	// ---
	// 2.
	// ---
	identity := signer.Identity()
	identityBuf, err := protobuf.Encode(&identity)
	if err != nil {
		return xerrors.Errorf("coulndn't encode the identity: %v", err)
	}

	signature, err := signer.Sign(hash)
	if err != nil {
		return xerrors.Errorf("couldn't sign the hash: %v", err)
	}

	// ---
	// 3.
	// ---
	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return xerrors.Errorf("couldn't get signer counters: %+v", err)
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(instIDBuf),
		Invoke: &byzcoin.Invoke{
			ContractID: byzcoin.ContractDeferredID,
			Command:    "addProof",
			Args: []byzcoin.Argument{
				{
					Name:  "identity",
					Value: identityBuf,
				},
				{
					Name:  "signature",
					Value: signature,
				},
				{
					Name:  "index",
					Value: indexBuf,
				},
			},
		},
		SignerCounter: []uint64{counters.Counters[0] + 1},
	})
	if err != nil {
		return err
	}

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}

	if lib.FindRecursivefBool("export", c) {
		return lib.ExportTransaction(ctx)
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	// ---
	// 4.
	// ---
	err = lib.WaitPropagation(c, cl)
	if err != nil {
		return err
	}
	pr, err := cl.GetProofFromLatest(instIDBuf)
	if err != nil {
		return xerrors.Errorf("couldn't get proof for admin-darc: %v", err)
	}

	_, resultBuf, _, _, err := pr.Proof.KeyValue()
	if err != nil {
		return xerrors.Errorf("couldn't get value out of proof: %v", err)
	}

	result := byzcoin.DeferredData{}
	err = protobuf.Decode(resultBuf, &result)
	if err != nil {
		return xerrors.Errorf("couldn't decode the result: %v", err)
	}

	log.Infof("Here is the deferred data: \n%s", result)

	return lib.WaitPropagation(c, cl)
}

// ExecProposedTx is used to execute the proposed transaction if all the
// instructions are correctly signed.
func ExecProposedTx(c *cli.Context) error {
	// Here is what this function does:
	//   1. Parses the input argument
	//   2. Sends an "execProposedTx" transaction
	//   3. Reads the return back and prints it

	// ---
	// 1.
	// ---
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return xerrors.Errorf("couldn't load config: %+v", err)
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return xerrors.Errorf("couldn't load key: %+v", err)
	}

	instID := c.String("instid")
	if instID == "" {
		return xerrors.New("--instid flag is required")
	}
	instIDBuf, err := hex.DecodeString(instID)
	if err != nil {
		return xerrors.New("failed to decode the instid string")
	}

	// ---
	// 2.
	// ---
	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return xerrors.Errorf("couldn't get counters: %+v", err)
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(instIDBuf),
		Invoke: &byzcoin.Invoke{
			ContractID: byzcoin.ContractDeferredID,
			Command:    "execProposedTx",
		},
		SignerCounter: []uint64{counters.Counters[0] + 1},
	})
	if err != nil {
		return xerrors.Errorf("couldn't create transaction: %+v", err)
	}

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return xerrors.Errorf("couldn't fill signers and sign: %+v", err)
	}

	if lib.FindRecursivefBool("export", c) {
		return lib.ExportTransaction(ctx)
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return xerrors.Errorf("couldn't add transaction: %+v", err)
	}

	// ---
	// 3.
	// ---
	err = lib.WaitPropagation(c, cl)
	if err != nil {
		return xerrors.Errorf("waiting on propagation failed: %+v", err)
	}
	pr, err := cl.GetProofFromLatest(instIDBuf)
	if err != nil {
		return xerrors.Errorf("couldn't get proof for admin-darc: %+v", err)
	}

	_, resultBuf, _, _, err := pr.Proof.KeyValue()
	if err != nil {
		return xerrors.Errorf("couldn't get value out of proof: %+v", err)
	}

	result := byzcoin.DeferredData{}
	err = protobuf.Decode(resultBuf, &result)
	if err != nil {
		return xerrors.Errorf("couldn't decode the result: %+v", err)
	}

	log.Infof("Here is the deferred data: \n%s", result)

	return nil
}

// DeferredGet checks the proof and retrieves the value of a deferred contract.
func DeferredGet(c *cli.Context) error {

	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	_, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	instID := c.String("instid")
	if instID == "" {
		return xerrors.New("--instid flag is required")
	}
	instIDBuf, err := hex.DecodeString(instID)
	if err != nil {
		return xerrors.New("failed to decode the instid string")
	}

	pr, err := cl.GetProofFromLatest(instIDBuf)
	if err != nil {
		return xerrors.Errorf("couldn't get proof: %v", err)
	}
	proof := pr.Proof

	exist, err := proof.InclusionProof.Exists(instIDBuf)
	if err != nil {
		return xerrors.Errorf("error while checking if proof exist: %v", err)
	}
	if !exist {
		return xerrors.New("proof not found")
	}

	match := proof.InclusionProof.Match(instIDBuf)
	if !match {
		return xerrors.New("proof does not match")
	}

	_, resultBuf, _, _, err := proof.KeyValue()
	if err != nil {
		return xerrors.Errorf("couldn't get value out of proof: %v", err)
	}

	result := byzcoin.DeferredData{}
	err = protobuf.Decode(resultBuf, &result)
	if err != nil {
		return xerrors.Errorf("Failed to decode the result: %v", err)
	}

	log.Infof("%s", result)

	return nil
}

// DeferredDelete delete the deferred instance
func DeferredDelete(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	instID := c.String("instid")
	if instID == "" {
		return xerrors.New("--instid flag is required")
	}
	instIDBuf, err := hex.DecodeString(instID)
	if err != nil {
		return xerrors.New("failed to decode the instid string")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return err
	}

	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return xerrors.Errorf("couldn't get signer counters: %+v", err)
	}

	delete := byzcoin.Delete{
		ContractID: byzcoin.ContractDeferredID,
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID([]byte(instIDBuf)),
		Delete:        &delete,
		SignerCounter: []uint64{counters.Counters[0] + 1},
	})
	if err != nil {
		return err
	}
	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}

	if lib.FindRecursivefBool("export", c) {
		return lib.ExportTransaction(ctx)
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	newInstID := ctx.Instructions[0].DeriveID("").Slice()
	log.Infof("Deferred contract deleted! (instance ID is %x)", newInstID)

	return lib.WaitPropagation(c, cl)
}
