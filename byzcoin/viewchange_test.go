package byzcoin

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3/byzcoin/viewchange"
	"go.dedis.ch/onet/v3/log"
)

// TestService_ViewChange is an end-to-end test for view-change. We kill the
// first nFailures nodes, where the nodes at index 0 is the current leader. The
// node at index nFailures should become the new leader. Then, we try to send a
// transaction to a follower, at index nFailures+1. The new leader (at index
// nFailures) should poll for new transactions and eventually make a new block
// containing that transaction. The new transaction should be stored on all
// followers. Finally, we bring the failed nodes back up and they should
// contain the transactions that they missed.
func TestViewChange_Basic(t *testing.T) {
	testViewChange(t, 4, 1, testInterval)
}

func TestViewChange_Basic2(t *testing.T) {
	if testing.Short() {
		// Block interval needs to be big enough so that the protocol
		// timeout is big enough but the test takes too much time then.
		t.Skip("protocol timeout too short for Travis")
	}

	testViewChange(t, 7, 2, 4*testInterval)
}

func TestViewChange_Basic3(t *testing.T) {
	if testing.Short() {
		t.Skip("protocol timeout too short for Travis")
	}

	// Enough nodes and failing ones to test what happens when propagation
	// fails due to offline nodes in the higher level of the tree.
	testViewChange(t, 10, 3, 4*testInterval)
}

func testViewChange(t *testing.T, nHosts, nFailures int, interval time.Duration) {
	rw := time.Duration(3)
	s := newSerN(t, 1, interval, nHosts, rw)
	defer s.local.CloseAll()

	for _, service := range s.services {
		service.SetPropagationTimeout(2 * interval)
	}

	// Wait for all the genesis config to be written on all nodes.
	genesisInstanceID := InstanceID{}
	for i := range s.services {
		s.waitProofWithIdx(t, genesisInstanceID.Slice(), i)
	}

	// Stop the first nFailures hosts then the node at index nFailures
	// should take over.
	for i := 0; i < nFailures; i++ {
		log.Lvl1("stopping node at index", i)
		s.services[i].TestClose()
		s.hosts[i].Pause()
	}
	// Wait for proof that the new expected leader, s.services[nFailures],
	// has taken over. First, we sleep for the duration that an honest node
	// will wait before starting a view-change. Then, we sleep a little
	// longer for the view-change transaction to be stored in the block.
	time.Sleep(s.interval * rw)

	for i := 0; i < nFailures; i++ {
		time.Sleep(time.Duration(math.Pow(2, float64(i+1))) * s.interval * rw)
	}
	s.waitPropagation(t, 0)
	config, err := s.services[nFailures].LoadConfig(s.genesis.SkipChainID())
	require.NoError(t, err)
	log.Lvl2("Verifying roster", config.Roster.List)
	require.True(t, config.Roster.List[0].Equal(s.services[nFailures].ServerIdentity()))

	// try to send a transaction to the node on index nFailures+1, which is
	// a follower (not the new leader)
	tx1, err := createOneClientTx(s.darc.GetBaseID(), dummyContract, s.value, s.signer)
	require.NoError(t, err)
	s.sendTxTo(t, tx1, nFailures+1)

	// check that the leader is updated for all nodes
	// Note: check is done after a tx has been sent so that nodes catch up if the
	// propagation failed
	s.waitPropagation(t, 0)
	for _, service := range s.services[nFailures:] {
		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[nFailures].ServerIdentity()), fmt.Sprintf("%v", leader))
	}

	// wait for the transaction to be stored on the new leader, because it
	// polls for new transactions
	pr := s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), nFailures)
	require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))

	// The transaction should also be stored on followers
	for i := nFailures + 1; i < nHosts; i++ {
		pr = s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), i)
		require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))
	}

	// We need to bring the failed (the first nFailures) nodes back up and
	// check that they can synchronise to the latest state.
	for i := 0; i < nFailures; i++ {
		log.Lvl1("starting node at index", i)
		s.hosts[i].Unpause()
		require.NoError(t, s.services[i].TestRestart())
	}
	for i := 0; i < nFailures; i++ {
		pr = s.waitProofWithIdx(t, tx1.Instructions[0].InstanceID.Slice(), i)
		require.True(t, pr.InclusionProof.Match(tx1.Instructions[0].InstanceID.Slice()))
	}
	s.waitPropagation(t, 0)

	log.Lvl1("Sending 1st tx")
	tx1, err = createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 2)
	require.NoError(t, err)
	s.sendTxToAndWait(t, tx1, nFailures, 10)
	log.Lvl1("Sending 2nd tx")
	tx1, err = createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 3)
	require.NoError(t, err)
	s.sendTxToAndWait(t, tx1, nFailures, 10)
	log.Lvl1("Sent two tx")
	s.waitPropagation(t, -1)
}

// Tests that a view change can happen when the leader index is out of bound
func TestViewChange_LeaderIndex(t *testing.T) {
	s := newSerN(t, 1, time.Second, 5, defaultRotationWindow)
	defer s.local.CloseAll()

	err := s.services[0].sendViewChangeReq(viewchange.View{LeaderIndex: -1})
	require.Error(t, err)
	require.Equal(t, "leader index must be positive", err.Error())

	view := viewchange.View{
		ID:          s.genesis.SkipChainID(),
		Gen:         s.genesis.SkipChainID(),
		LeaderIndex: 7,
	}
	for i := 0; i < 5; i++ {
		s.services[i].viewChangeMan.addReq(viewchange.InitReq{
			SignerID: s.services[i].ServerIdentity().ID,
			View:     view,
		})
		err := s.services[i].sendViewChangeReq(view)
		require.NoError(t, err)
	}

	time.Sleep(2 * s.interval)

	for _, service := range s.services {
		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[2].ServerIdentity()))
	}
}

// Test that old states of a view change that got stuck in the middle of the protocol
// are correctly cleaned if a new block is discovered.
func TestViewChange_LostSync(t *testing.T) {
	s := newSerN(t, 1, time.Second, 5, defaultRotationWindow)
	defer s.local.CloseAll()

	target := s.hosts[1].ServerIdentity

	// Simulate the beginning of a view change
	req := &viewchange.InitReq{
		SignerID: s.services[0].ServerIdentity().ID,
		View: viewchange.View{
			ID:          s.genesis.Hash,
			Gen:         s.genesis.Hash,
			LeaderIndex: 3,
		},
		Signature: []byte{},
	}
	require.NoError(t, req.Sign(s.services[0].ServerIdentity().GetPrivate()))

	err := s.services[0].SendRaw(target, req)
	require.NoError(t, err)

	// worst case scenario where the conode lost connectivity
	// and the view change fails in the other hand so the failing
	// conode is still waiting for requests

	// then new blocks have been added
	tx1, err := createOneClientTxWithCounter(s.darc.GetBaseID(), dummyContract, s.value, s.signer, 1)
	require.NoError(t, err)
	_, err = s.services[1].AddTransaction(&AddTxRequest{
		Version:       CurrentVersion,
		SkipchainID:   s.genesis.SkipChainID(),
		Transaction:   tx1,
		InclusionWait: 5,
	})
	require.NoError(t, err)

	// give enough time for the propagation to be processed
	time.Sleep(1 * time.Second)

	sb, err := s.services[1].db().GetLatestByID(s.genesis.Hash)
	require.NoError(t, err)
	require.NotEqual(t, sb.Hash, s.genesis.Hash)

	// Start a new view change with a different block ID
	req = &viewchange.InitReq{
		SignerID: s.services[0].ServerIdentity().ID,
		View: viewchange.View{
			ID:          sb.Hash,
			Gen:         s.genesis.SkipChainID(),
			LeaderIndex: 3,
		},
	}
	require.NoError(t, req.Sign(s.services[0].ServerIdentity().GetPrivate()))

	log.OutputToBuf()
	defer log.OutputToOs()

	err = s.services[0].SendRaw(target, req)
	require.NoError(t, err)

	time.Sleep(1 * time.Second) // request handler is asynchronous
	require.NotContains(t, log.GetStdOut(), "a request has been ignored")
	log.OutputToOs()

	// make sure a view change can still happen later
	view := viewchange.View{
		ID:          sb.Hash,
		Gen:         s.genesis.SkipChainID(),
		LeaderIndex: 3,
	}
	for i := 0; i < 4; i++ {
		err := s.services[i].sendViewChangeReq(view)
		require.NoError(t, err)
	}
	for i := 0; i < 4; i++ {
		s.services[i].viewChangeMan.addReq(viewchange.InitReq{
			SignerID: s.services[i].ServerIdentity().ID,
			View:     view,
		})
	}

	log.Lvl1("Waiting for the new block to be propagated")
	s.waitPropagation(t, 2)
	for _, service := range s.services {
		// everyone should have the same leader after the genesis block is stored
		leader, err := service.getLeader(s.genesis.SkipChainID())
		require.NoError(t, err)
		require.NotNil(t, leader)
		require.True(t, leader.Equal(s.services[3].ServerIdentity()))
	}
}

func TestViewChange_MonitorFailure(t *testing.T) {
	s := newSerN(t, 1, time.Second, 3, defaultRotationWindow)
	defer s.local.CloseAll()

	log.OutputToBuf()
	defer log.OutputToOs()

	// heartbeats an unknown skipchain: this should NOT panic or crash
	s.service().heartbeatsTimeout <- "abc"

	time.Sleep(1 * time.Second)

	stderr := log.GetStdErr()
	require.Contains(t, stderr, "heartbeat monitors are started after the creation")
	require.Contains(t, stderr, "failed to get the latest block")
}

// Test to make sure the view change triggers a proof propagation when a conode
// is sending request for old blocks, meaning it is out-of-sync and as the leader
// is offline, it will never catch up.
func TestViewChange_NeedCatchUp(t *testing.T) {
	rw := time.Duration(3)
	s := newSerN(t, 1, testInterval, 5, rw)
	defer s.local.CloseAll()

	for _, service := range s.services {
		service.SetPropagationTimeout(2 * testInterval)
	}

	s.hosts[3].Pause()

	// Create a block that host 4 will miss
	tx1, err := createOneClientTx(s.darc.GetBaseID(), dummyContract, s.value, s.signer)
	require.NoError(t, err)
	s.sendTxTo(t, tx1, 0)

	time.Sleep(5 * time.Second)

	// Kill the leader, but the view change won't happen as
	// 2 nodes are down
	s.services[0].TestClose()
	s.hosts[0].Pause()

	s.hosts[3].Unpause()
	// This will trigger the proof to be propagated. In that test, the catch up
	// won't be trigger as only one block is missing.
	s.services[3].sendViewChangeReq(viewchange.View{
		ID:          s.genesis.Hash,
		Gen:         s.genesis.SkipChainID(),
		LeaderIndex: 1,
	})

	// It will need a few seconds if it catches the leader index 1 and a bit
	// more if it goes to the leader index 2 so we give enough time.
	sb := s.genesis
	for i := 0; i < 60 && sb.Index != 2; i++ {
		proof, err := s.services[4].skService().GetDB().GetProof(s.genesis.Hash)
		require.NoError(t, err)
		sb = proof[len(proof)-1]

		// wait for the view change to happen
		time.Sleep(1 * time.Second)
	}

	// Check that a view change was finally executed
	leader, err := s.services[4].getLeader(s.genesis.SkipChainID())
	require.NoError(t, err)
	require.NotNil(t, leader)
	require.False(t, leader.Equal(s.services[0].ServerIdentity()))
}
