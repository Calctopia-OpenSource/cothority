package byzcoin

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.dedis.ch/cothority/v3/darc/expression"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"

	"github.com/stretchr/testify/require"
)

func TestNKCR(t *testing.T) {
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer1 := darc.NewSignerEd25519(nil, nil)
	signer2 := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(5, true)

	genesisMsg, err := DefaultGenesisMsg(CurrentVersion, roster, []string{}, signer1.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc

	genesisMsg.BlockInterval = time.Second

	client, _, err := NewLedger(genesisMsg, false)
	require.Nil(t, err)

	secDarc := gDarc.Copy()
	action := darc.Action("invoke:darc.evolve")
	exp := expression.InitAndExpr(
		signer1.Identity().String(),
		signer2.Identity().String(),
	)
	secDarc.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc.EvolveFrom(gDarc))
		secDarcBuf, err := secDarc.ToProto()
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1))
		_, err = client.AddTransactionAndWait(ctx, 10)
		require.NoError(t, err)
	}

	{
		log.Info("check the darc")
		resp, err := client.GetProof(secDarc.GetBaseID())
		require.NoError(t, err)
		myDarc := darc.Darc{}
		require.NoError(t, resp.Proof.VerifyAndDecode(cothority.Suite, ContractDarcID, &myDarc))
		log.Info("\n\n\n")
		log.Info(fmt.Printf("%s", myDarc.Rules))
		require.Equal(t, string(myDarc.Rules.Get("invoke:darc.evolve")), signer1.Identity().String()+" & "+signer2.Identity().String())
	}

	// ---
	// Now that we need signer1 AND signer2 to make the darc evolve, let's check
	// if signer1 can still perform a change on its own. We expect an error.
	secDarc2 := secDarc.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
		signer2.Identity().String(),
	)
	secDarc.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		secDarcBuf, err := secDarc2.ToProto()
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc2.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{2},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1))
		_, err = client.AddTransactionAndWait(ctx, 10)
		require.Error(t, err)
	}

	// ---
	// Now lets try to update the darc using the two signers and add a third
	// one, signer3. This should work
	signer3 := darc.NewSignerEd25519(nil, nil)
	secDarc2 = secDarc.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
		signer2.Identity().String(),
		signer3.Identity().String(),
	)
	secDarc2.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		secDarcBuf, err := secDarc2.ToProto()
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc2.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{2, 1},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1, signer2))
		_, err = client.AddTransactionAndWait(ctx, 10)
		require.NoError(t, err)
	}

	{
		log.Info("check the darc")
		resp, err := client.GetProof(secDarc.GetBaseID())
		require.NoError(t, err)
		myDarc := darc.Darc{}
		require.NoError(t, resp.Proof.VerifyAndDecode(cothority.Suite, ContractDarcID, &myDarc))
		log.Info("\n\n\n")
		log.Info(fmt.Printf("%s", myDarc.Rules))
		require.Equal(t, string(myDarc.Rules.Get("invoke:darc.evolve")), signer1.Identity().String()+" & "+signer2.Identity().String()+" & "+signer3.Identity().String())
	}

	// Ok, so having multiple signers using an expression is fine. However, this
	// requires to manually collect the signatures of every parties involved and
	// manually synchronize them. Moreover, each party can not send any
	// transaction that would change their nonce until the transaction is
	// finished. So lets try so take care of the sync.

	// First of all, signer1 will sign the instruction. It will get rejected.
	secDarc3 := secDarc2.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
	)
	secDarc3.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc3.EvolveFrom(secDarc))
		secDarcBuf, err := secDarc3.ToProto()
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc3.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{2},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1))
		_, err = client.AddTransactionAndWait(ctx, 10)
		require.Error(t, err)
		// Here is the instruction hash, but I don't need it yet
		hash := ctx.Instructions[0].Hash()
		log.Infof("Here is the hash: %x", hash)

		// Let's rather get the block id, which is what I really need
		var proofResponse *GetProofResponse
		proofResponse, err = client.GetProof(hash)
		require.Nil(t, err)
		blockId := proofResponse.Proof.Latest.Hash
		log.Infof("Here is the block hash: %x", blockId)

		// Now that I have the blockId, I need signer2 to say that he aggres to
		// sign what is stored in this block
		secDarc3 = secDarc2.Copy()
		myAction := fmt.Sprintf("multisign:%x", blockId)
		log.Infof("Here is the multi sign action: %s", myAction)
		action = darc.Action(myAction)
		exp = expression.InitAndExpr(signer2.Identity().String())
		secDarc3.Rules.AddRule(action, exp)

		require.NoError(t, secDarc3.EvolveFrom(secDarc))
		secDarcBuf, err = secDarc3.ToProto()

		ctx = ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc3.GetBaseID()),
				Multisign: &Multisign{
					BlockId: blockId,
				},
				SignerCounter: []uint64{2},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer2))
		_, err = client.AddTransactionAndWait(ctx, 10)
		require.NoError(t, err)

		// Now lets check what contains the last block
		hash = ctx.Instructions[0].Hash()
		proofResponse, err = client.GetProof(hash)
		require.Nil(t, err)
		blockId = proofResponse.Proof.Latest.Hash
		log.Infof("Here is the block hash: %x", blockId)

	}

}

func Test2NKCR(t *testing.T) {
	var s *ser

	s = newSer(t, 1, testInterval)

	defer s.local.CloseAll()

	signer1 := s.signer
	signer2 := darc.NewSignerEd25519(nil, nil)

	gDarc := s.darc

	//
	// CHAPTER I
	// ---------
	// Update the darc to acctect only signer1 AND signer2
	//
	secDarc := gDarc.Copy()
	action := darc.Action("invoke:darc.evolve")
	exp := expression.InitAndExpr(
		signer1.Identity().String(),
		signer2.Identity().String(),
	)
	secDarc.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc.EvolveFrom(gDarc))
		secDarcBuf, err := secDarc.ToProto()
		require.NoError(t, err)
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1))
		_, err = s.services[0].AddTransaction(&AddTxRequest{
			Version:       CurrentVersion,
			SkipchainID:   s.genesis.SkipChainID(),
			Transaction:   ctx,
			InclusionWait: 10,
		})
		require.Nil(t, err)
	}

	//
	// CHAPTER II
	// ----------
	// Try now to only change with signer1. We expect it not to work
	//
	secDarc2 := secDarc.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
	)
	secDarc2.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		secDarcBuf, err := secDarc2.ToProto()
		require.NoError(t, err)
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc2.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{2},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1))
		_, err = s.services[0].AddTransaction(&AddTxRequest{
			Version:       CurrentVersion,
			SkipchainID:   s.genesis.SkipChainID(),
			Transaction:   ctx,
			InclusionWait: 10,
		})
		require.Error(t, err)
	}

	//
	// CHAPTER III
	// -----------
	// Try now to update the Darc using signer1 AND signer2 to evolve as
	// signer1 AND signer2 AND signer3. We expect it to work
	//
	signer3 := darc.NewSignerEd25519(nil, nil)
	secDarc2 = secDarc.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
		signer2.Identity().String(),
		signer3.Identity().String(),
	)
	secDarc2.Rules.UpdateRule(action, exp)
	{
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		secDarcBuf, err := secDarc2.ToProto()
		require.NoError(t, err)
		ctx := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc2.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarcBuf,
					}},
				},
				SignerCounter: []uint64{2, 1},
			}},
		}
		require.Nil(t, ctx.FillSignersAndSignWith(signer1, signer2))
		_, err = s.services[0].AddTransaction(&AddTxRequest{
			Version:       CurrentVersion,
			SkipchainID:   s.genesis.SkipChainID(),
			Transaction:   ctx,
			InclusionWait: 10,
		})
		require.Nil(t, err)
	}

	//
	// CHAPTER IV
	// ----------
	// Now signer1 wants to update the darc. So he will start by sending a
	// transaction that will obviously fail since it must be signed by signer1
	// AND signer2 AND signer3
	//
	secDarc3 := secDarc2.Copy()
	action = darc.Action("invoke:darc.evolve")
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
	)
	secDarc3.Rules.UpdateRule(action, exp)

	require.NoError(t, secDarc3.EvolveFrom(secDarc2))
	secDarcBuf, err := secDarc3.ToProto()
	require.NoError(t, err)
	ctx := ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(secDarc3.GetBaseID()),
			Invoke: &Invoke{
				ContractID: ContractDarcID,
				Command:    cmdDarcEvolve,
				Args: []Argument{{
					Name:  "darc",
					Value: secDarcBuf,
				}},
			},
			SignerCounter: []uint64{3},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer1))
	_, err = s.services[0].AddTransaction(&AddTxRequest{
		Version:       CurrentVersion,
		SkipchainID:   s.genesis.SkipChainID(),
		Transaction:   ctx,
		InclusionWait: 10,
	})
	require.Error(t, err)

	// CHAPTER V
	// ---------
	// Now that signer1 failed his transaction, he can get back the instruction
	// hash and the block id. Remember, even if the transaction failed, it is
	// written on the blockchain.

	// Here is the instruction hash
	instructionId := ctx.Instructions[0].Hash()
	log.Infof("Here is the instruction id: %x", instructionId)

	// Here is the last skipblock
	proof := s.waitProof(t, NewInstanceID(secDarc3.GetBaseID()))
	blockId := proof.Latest.Hash
	log.Infof("Here is the block id: %x", blockId)
	_, skipBblock, err := s.service().getBlockTx(blockId)
	require.Nil(t, err)
	log.Infof("Here is the payload of the skipblock: %s", skipBblock.Payload)

	//
	// CHAPTER VI
	// ----------
	// Now that signer1 sent his failed block, he can ask signer2 to send a
	// "multisign" instruction telling that he accepts the rejected block of
	// signer1
	//
	secDarc4 := secDarc3.Copy()
	myAction := fmt.Sprintf("multisign:%x.%x", blockId, instructionId)
	action = darc.Action(myAction)
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
	)
	secDarc4.Rules.UpdateRule(action, exp)

	log.Infof("Here is the multi sign action: %s", myAction)
	action = darc.Action(myAction)
	exp = expression.InitAndExpr(signer2.Identity().String())
	secDarc4.Rules.AddRule(action, exp)
	require.NoError(t, secDarc4.EvolveFrom(secDarc3))
	secDarcBuf, err = secDarc4.ToProto()

	ctx = ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(secDarc4.GetBaseID()),
			Multisign: &Multisign{
				BlockId:       blockId,
				InstructionId: instructionId,
			},
			SignerCounter: []uint64{2},
		}},
	}

	require.Nil(t, ctx.FillSignersAndSignWith(signer2))
	_, err = s.services[0].AddTransaction(&AddTxRequest{
		Version:       CurrentVersion,
		SkipchainID:   s.genesis.SkipChainID(),
		Transaction:   ctx,
		InclusionWait: 10,
	})
	require.Nil(t, err)

	//
	// CHAPTER VII
	// -----------
	// Now lets see if our multisign transaction has been saved on the
	// skipchain. We should be able to retrieve the same blockId and the
	// same instructionId that we saved previously.
	//
	proof = s.waitProof(t, NewInstanceID(secDarc4.GetBaseID()))
	blockId2 := proof.Latest.Hash
	log.Infof("Here is the block id: %x", blockId2)
	txResults, skipBblock, err := s.service().getBlockTx(blockId2)
	require.Nil(t, err)
	// The payload should contain the blockId we sent in the multisign
	require.True(t, strings.Contains(
		fmt.Sprintf("%x", skipBblock.Payload),
		fmt.Sprintf("%x", blockId),
	))

	// "ms" stands for MultiSign
	msBlockId := txResults[0].ClientTransaction.Instructions[0].Multisign.BlockId
	msInstructionId := txResults[0].ClientTransaction.Instructions[0].Multisign.InstructionId

	require.True(t, bytes.Equal(msBlockId, blockId))
	require.True(t, bytes.Equal(msInstructionId, instructionId))

	// Those are manually given to signer3:
	instructionId = ctx.Instructions[0].Hash()
	proof = s.waitProof(t, NewInstanceID(secDarc4.GetBaseID()))
	blockId = proof.Latest.Hash

	//
	// CHAPTER IIX
	// -----------
	// Now if signer3 do the same as signer2, the transaction should pass
	//
	secDarc5 := secDarc4.Copy()
	myAction = fmt.Sprintf("multisign:%x.%x", blockId, instructionId)
	action = darc.Action(myAction)
	exp = expression.InitAndExpr(
		signer1.Identity().String(),
	)
	secDarc5.Rules.UpdateRule(action, exp)

	log.Infof("Here is the multi sign action: %s", myAction)
	action = darc.Action(myAction)
	exp = expression.InitAndExpr(signer3.Identity().String())
	secDarc5.Rules.AddRule(action, exp)
	require.NoError(t, secDarc5.EvolveFrom(secDarc4))
	secDarcBuf, err = secDarc5.ToProto()

	ctx = ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(secDarc5.GetBaseID()),
			Multisign: &Multisign{
				BlockId:       blockId,
				InstructionId: instructionId,
			},
			SignerCounter: []uint64{1},
		}},
	}

	require.Nil(t, ctx.FillSignersAndSignWith(signer3))
	_, err = s.services[0].AddTransaction(&AddTxRequest{
		Version:       CurrentVersion,
		SkipchainID:   s.genesis.SkipChainID(),
		Transaction:   ctx,
		InclusionWait: 10,
	})
	require.Nil(t, err)

}

// -
// --

// ------

// ------

// --
// -

// -
// --

// ------

// ------

// --
// -

// -
// --

// ------

// ------

// --
// -

func TestSecureDarc(t *testing.T) {
	local := onet.NewTCPTest(cothority.Suite)
	defer local.CloseAll()

	signer := darc.NewSignerEd25519(nil, nil)
	_, roster, _ := local.GenTree(3, true)

	genesisMsg, err := DefaultGenesisMsg(CurrentVersion, roster, []string{}, signer.Identity())
	require.Nil(t, err)
	gDarc := &genesisMsg.GenesisDarc
	genesisMsg.BlockInterval = time.Second
	cl, _, err := NewLedger(genesisMsg, false)
	require.Nil(t, err)

	restrictedSigner := darc.NewSignerEd25519(nil, nil)
	unrestrictedSigner := darc.NewSignerEd25519(nil, nil)
	invokeEvolve := darc.Action("invoke:" + ContractDarcID + "." + cmdDarcEvolve)
	invokeEvolveUnrestricted := darc.Action("invoke:" + ContractDarcID + "." + cmdDarcEvolveUnrestriction)

	log.Info("spawn a new secure darc with spawn:insecure_darc - fail")
	secDarc := gDarc.Copy()
	require.NoError(t, secDarc.Rules.AddRule("spawn:insecure_darc", []byte(restrictedSigner.Identity().String())))
	secDarcBuf, err := secDarc.ToProto()
	require.NoError(t, err)
	ctx := ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(gDarc.GetBaseID()),
			Spawn: &Spawn{
				ContractID: ContractDarcID,
				Args: []Argument{{
					Name:  "darc",
					Value: secDarcBuf,
				}},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))
	_, err = cl.AddTransactionAndWait(ctx, 10)
	require.Error(t, err)

	log.Info("do the same but without spawn:insecure_darc - pass")
	require.NoError(t, secDarc.Rules.DeleteRules("spawn:insecure_darc"))
	require.NoError(t, secDarc.Rules.UpdateRule(invokeEvolve, []byte(restrictedSigner.Identity().String())))
	require.NoError(t, secDarc.Rules.UpdateRule(invokeEvolveUnrestricted, []byte(unrestrictedSigner.Identity().String())))
	secDarcBuf, err = secDarc.ToProto()
	require.NoError(t, err)
	ctx = ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(gDarc.GetBaseID()),
			Spawn: &Spawn{
				ContractID: ContractDarcID,
				Args: []Argument{{
					Name:  "darc",
					Value: secDarcBuf,
				}},
			},
			SignerCounter: []uint64{1},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))
	_, err = cl.AddTransactionAndWait(ctx, 10)
	require.NoError(t, err)

	log.Info("spawn a darc with a version > 0 - fail")
	secDarc.Version = 1
	secDarcBuf, err = secDarc.ToProto()
	ctx = ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: NewInstanceID(gDarc.GetBaseID()),
			Spawn: &Spawn{
				ContractID: ContractDarcID,
				Args: []Argument{{
					Name:  "darc",
					Value: secDarcBuf,
				}},
			},
			SignerCounter: []uint64{2},
		}},
	}
	require.Nil(t, ctx.FillSignersAndSignWith(signer))
	_, err = cl.AddTransactionAndWait(ctx, 10)
	require.Error(t, err)

	secDarc.Version = 0
	log.Info("evolve to add rules - fail")
	{
		secDarc2 := secDarc.Copy()
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		require.NoError(t, secDarc2.Rules.AddRule("spawn:coin", secDarc.Rules.Get(invokeEvolveUnrestricted)))
		secDarc2Buf, err := secDarc2.ToProto()
		ctx2 := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarc2Buf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx2.FillSignersAndSignWith(restrictedSigner))
		_, err = cl.AddTransactionAndWait(ctx2, 10)
		require.Error(t, err)
	}

	log.Info("evolve to modify the unrestrict_evolve rule - fail")
	{
		secDarc2 := secDarc.Copy()
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		// changing the signer to something else, then it should fail
		require.NoError(t, secDarc2.Rules.UpdateRule(invokeEvolveUnrestricted, []byte(restrictedSigner.Identity().String())))
		secDarc2Buf, err := secDarc2.ToProto()
		ctx2 := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarc2Buf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx2.FillSignersAndSignWith(restrictedSigner))
		_, err = cl.AddTransactionAndWait(ctx2, 10)
		require.Error(t, err)
	}

	log.Info("evolve to modify existing rules - pass")
	{
		secDarc2 := secDarc.Copy()
		require.NoError(t, secDarc2.EvolveFrom(secDarc))
		secDarc2Buf, err := secDarc2.ToProto()
		ctx2 := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(secDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolve,
					Args: []Argument{{
						Name:  "darc",
						Value: secDarc2Buf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx2.FillSignersAndSignWith(restrictedSigner))
		_, err = cl.AddTransactionAndWait(ctx2, 10)
		require.NoError(t, err)
	}

	// get the latest darc
	resp, err := cl.GetProof(secDarc.GetBaseID())
	require.NoError(t, err)
	myDarc := darc.Darc{}
	require.NoError(t, resp.Proof.VerifyAndDecode(cothority.Suite, ContractDarcID, &myDarc))
	// secDarc is copied from genesis DARC, after one evolution the version
	// should increase by one
	require.Equal(t, myDarc.Version, gDarc.Version+1)

	log.Info("evolve_unrestricted fails with the wrong signer")
	{
		myDarc2 := myDarc.Copy()
		require.NoError(t, myDarc2.EvolveFrom(&myDarc))
		require.NoError(t, myDarc2.Rules.AddRule("spawn:coin", myDarc.Rules.Get(invokeEvolveUnrestricted)))
		myDarc2Buf, err := myDarc2.ToProto()
		ctx2 := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(myDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolveUnrestriction,
					Args: []Argument{{
						Name:  "darc",
						Value: myDarc2Buf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx2.FillSignersAndSignWith(restrictedSigner)) // here we use the wrong signer
		_, err = cl.AddTransactionAndWait(ctx2, 10)
		require.Error(t, err)
	}

	log.Info("evolve_unrestricted to add rules - pass")
	{
		myDarc2 := myDarc.Copy()
		require.NoError(t, myDarc2.EvolveFrom(&myDarc))
		require.NoError(t, myDarc2.Rules.AddRule("spawn:coin", myDarc2.Rules.Get(invokeEvolveUnrestricted)))
		myDarc2Buf, err := myDarc2.ToProto()
		ctx2 := ClientTransaction{
			Instructions: []Instruction{{
				InstanceID: NewInstanceID(myDarc.GetBaseID()),
				Invoke: &Invoke{
					ContractID: ContractDarcID,
					Command:    cmdDarcEvolveUnrestriction,
					Args: []Argument{{
						Name:  "darc",
						Value: myDarc2Buf,
					}},
				},
				SignerCounter: []uint64{1},
			}},
		}
		require.Nil(t, ctx2.FillSignersAndSignWith(unrestrictedSigner)) // here we use the correct signer
		_, err = cl.AddTransactionAndWait(ctx2, 10)
		require.NoError(t, err)
	}

	// try to get the DARC again and it should have the "spawn:coin" rule
	{
		resp, err := cl.GetProof(secDarc.GetBaseID())
		require.NoError(t, err)
		myDarc := darc.Darc{}
		require.NoError(t, resp.Proof.VerifyAndDecode(cothority.Suite, ContractDarcID, &myDarc))
		require.Equal(t, myDarc.Rules.Get("spawn:coin"), myDarc.Rules.Get("invoke:darc."+cmdDarcEvolveUnrestriction))
	}

	require.NoError(t, local.WaitDone(genesisMsg.BlockInterval))
}
