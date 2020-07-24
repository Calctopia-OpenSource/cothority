package clicontracts

import (
	"encoding/hex"
	"fmt"

	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"

	"github.com/urfave/cli"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/byzcoin/bcadmin/lib"
	"go.dedis.ch/cothority/v3/byzcoin/contracts"
	"go.dedis.ch/cothority/v3/darc"
)

// ValueSpawn is used to spawn a new contract.
func ValueSpawn(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	value := c.String("value")
	if value == "" {
		return xerrors.New("--value flag is required")
	}
	valueBuf := []byte(value)

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
		return fmt.Errorf("couldn't get signer counters: %v", err)
	}

	spawn := byzcoin.Spawn{
		ContractID: contracts.ContractValueID,
		Args: []byzcoin.Argument{
			{
				Name:  "value",
				Value: valueBuf,
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
	log.Infof("Spawned a new value contract. Its instance id is:\n%x", instID)

	return lib.WaitPropagation(c, cl)
}

// ValueInvokeUpdate is able to update the value of a value contract
func ValueInvokeUpdate(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return xerrors.New("--bc flag is required")
	}

	value := c.String("value")
	if value == "" {
		return xerrors.New("--value flag is required")
	}
	valueBuf := []byte(value)

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
		return fmt.Errorf("couldn't get signer counters: %v", err)
	}

	invoke := byzcoin.Invoke{
		ContractID: contracts.ContractValueID,
		Command:    "update",
		Args: []byzcoin.Argument{
			{
				Name:  "value",
				Value: valueBuf,
			},
		},
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID([]byte(instIDBuf)),
		Invoke:        &invoke,
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
	fmt.Printf("Value contract updated! (instance ID is %x)\n", newInstID)

	return lib.WaitPropagation(c, cl)
}

// ValueGet checks the proof and retrieves the value of a value contract.
func ValueGet(c *cli.Context) error {

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
		return xerrors.New("failed to decode the instID string" + instID)
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

	log.Infof("%s", resultBuf)

	return nil
}

// ValueDelete delete the value instance
func ValueDelete(c *cli.Context) error {
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
		return fmt.Errorf("couldn't get signer counters: %v", err)
	}

	delInst := byzcoin.Delete{
		ContractID: contracts.ContractValueID,
	}

	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID([]byte(instIDBuf)),
		Delete:        &delInst,
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
	log.Infof("Value contract deleted! (instance ID is %x)", newInstID)

	return lib.WaitPropagation(c, cl)
}
