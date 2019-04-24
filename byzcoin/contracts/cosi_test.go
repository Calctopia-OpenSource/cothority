package contracts

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/cothority/v3/darc"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

func TestCosi_Spawn(t *testing.T) {
	// In this test I am just trying to see if a spawn successfully stores
	// the given argument and if I am able to retrieve them after. It was
	// interesting to play with the encode/decode protobuf.
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:cosi"}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	cl, _, err := byzcoin.NewLedger(genesisMsg, false)
	require.Nil(t, err)

	rootCommand := []byte("invoke:xxx")
	rootDarcID := []byte("darc:aef12")
	expireSec := []byte("6000")
	expireSecInt, _ := strconv.Atoi(string(expireSec))

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(gDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractCosiID,
				Args: []byzcoin.Argument{
					{
						Name:  "rootCommand",
						Value: rootCommand,
					},
					{
						Name:  "rootDarcID",
						Value: rootDarcID,
					},
					{
						Name:  "expireSec",
						Value: expireSec,
					},
				},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))

	_, err = cl.AddTransaction(ctx)
	require.Nil(t, err)

	pr, err := cl.WaitProof(byzcoin.NewInstanceID(ctx.Instructions[0].DeriveID("").Slice()), 2*genesisMsg.BlockInterval, nil)
	require.Nil(t, err)
	require.True(t, pr.InclusionProof.Match(ctx.Instructions[0].DeriveID("").Slice()))
	v0, _, _, err := pr.Get(ctx.Instructions[0].DeriveID("").Slice())
	require.Nil(t, err)
	fmt.Printf("Here is the result: %s\n", v0)
	result := CosiData{}
	err = protobuf.Decode(v0, &result)
	require.Nil(t, err)

	require.Equal(t, result.RootCommand, rootCommand)
	require.Equal(t, result.RootDarcID, rootDarcID)
	require.Equal(t, result.ExpireSec, expireSecInt)

	local.WaitDone(genesisMsg.BlockInterval)
}
