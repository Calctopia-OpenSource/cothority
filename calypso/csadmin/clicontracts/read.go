package clicontracts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"go.dedis.ch/onet/v3/log"

	"github.com/urfave/cli"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/byzcoin/bcadmin/lib"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/protobuf"
)

// ReadSpawn spawns an instance of a read contract. This contract uses the darc
// of the Write contract, which means that the signer of this transaction must
// be allowed by the owner of the targeted write contract. The Write instance is
// specified by the --instid argument. By default, the function uses the public
// key of the signer to encrypt the requested data. However, a different public
// key can be given a an hexadecimal string representation with --key.
// With the --export option, the instance id is sent to STDOUT.
func ReadSpawn(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return errors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return fmt.Errorf("reading config: %v", err)
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return fmt.Errorf("failed to parse the signer: %v", err)
	}

	instidstr := c.String("instid")
	if instidstr == "" {
		return errors.New("please provide the write instance ID with --instid")
	}

	instidbuf, err := hex.DecodeString(instidstr)
	if err != nil {
		return fmt.Errorf("failed to decode instance id: %v", err)
	}

	pr, err := cl.GetProofFromLatest(instidbuf)
	if err != nil {
		return fmt.Errorf("couldn't get proof: %v", err)
	}
	proof := pr.Proof

	exist, err := proof.InclusionProof.Exists(instidbuf)
	if err != nil {
		return fmt.Errorf("error while checking if proof exist: %v", err)
	}
	if !exist {
		return errors.New("proof not found")
	}

	match := proof.InclusionProof.Match(instidbuf)
	if !match {
		return errors.New("proof does not match")
	}

	var write calypso.Write
	err = proof.VerifyAndDecode(cothority.Suite, calypso.ContractWriteID, &write)
	if err != nil {
		return fmt.Errorf("didn't get a write instance: %v", err)
	}

	var xc kyber.Point
	key := c.String("key")
	if key == "" {
		xc = signer.Ed25519.Point
	} else {
		keyBuf, err := hex.DecodeString(key)
		if err != nil {
			return fmt.Errorf("failed to decode public key: %v", err)
		}
		pubPoint := cothority.Suite.Point()
		err = pubPoint.UnmarshalBinary(keyBuf)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pub key point: %v", err)
		}
		xc = pubPoint
	}

	var readBuf []byte
	read := &calypso.Read{
		Write: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
		Xc:    xc,
	}
	reply := &calypso.ReadReply{}
	readBuf, err = protobuf.Encode(read)
	if err != nil {
		return fmt.Errorf("failed to encode read struct: %v", err)
	}

	projectInstID := c.String("projectInstID")
	projectInstIDBuff, err := hex.DecodeString(projectInstID)
	if err != nil {
		return errors.New("failed to decode the projectInstID string")
	}

	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return fmt.Errorf("failed to get the signer counters: %v", err)
	}

	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractReadID,
				Args: byzcoin.Arguments{
					{Name: "read", Value: readBuf},
					{Name: "projectInstID", Value: projectInstIDBuff},
				},
			},
			SignerCounter: []uint64{counters.Counters[0] + 1},
		},
	)

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return fmt.Errorf("failed to fill signers and sign: %v", err)
	}

	reply.InstanceID = ctx.Instructions[0].DeriveID("")
	reply.AddTxResponse, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return fmt.Errorf("failed to add transaction: %v", err)
	}

	err = lib.WaitPropagation(c, cl)
	if err != nil {
		return fmt.Errorf("waiting for block propagation: %v", err)
	}

	iidStr := hex.EncodeToString(reply.InstanceID.Slice())
	if c.Bool("export") {
		reader := bytes.NewReader([]byte(iidStr))
		_, err = io.Copy(os.Stdout, reader)
		if err != nil {
			return fmt.Errorf("failed to copy to stdout: %v", err)
		}
		return nil
	}

	log.Infof("Spawned a new read instance. "+
		"Its instance id is:\n%s", iidStr)

	return nil
}
