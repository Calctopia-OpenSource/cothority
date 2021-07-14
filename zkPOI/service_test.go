package zkPOI

import (
	"flag"
	"testing"
	"time"
	"encoding/hex"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	uuid "gopkg.in/satori/go.uuid.v1"
)

var testBlockInterval = 500 * time.Millisecond

func TestMain(m *testing.M) {
	flag.Parse()
	log.MainTest(m)
}

func TestService(t *testing.T) {
	suite := suites.MustFind("ed25519")
	e, c := newEnv(t)
	defer e.local.CloseAll()

	nPartic := len(e.services)
	require.Equal(t, nPartic, 5)

	pubs := make([]kyber.Point, nPartic)
	for i := 0; i < nPartic; i++ {
		pubs[i] = e.roster.List[i].Public
	}

	// Call NewPublicKey to add a new ServerIdentity
	id := uuid.NewV1()
	nsis := make([]ServerIdentityStringified, 1)
	pub, err := encoding.StringHexToPoint(suite, "0bcdaebde16f50fb65b717a0501e7ede020045286d6ece10fdea1bdd8f37af39")
	require.NoError(t, err)
	sids := make([]ServiceIdentityStringified, 2)
	sids[0] = ServiceIdentityStringified{ Name: "Byzcoin",
		Suite: "bn256.adapter",
		Public: "6f69dc10dbef8f4d80072aa9d1bee191b0f68b137a9d06d006c39fe6667738fa2d3439caf428a1dcb6f4a5bd2ce6ff6f1462ebb1b7374080d95310bc6e1115e105d7ae38f9fed1585094b0cb13dc3a0f3e74daeaa794ca10058e44ef339055510f4d12a7234779f8db2e093dd8a14a03440a7d5a8ef04cac8fd735f20440b589"}
	sids[1] = ServiceIdentityStringified{ Name: "Skipchain",
		Suite: "bn256.adapter",
		Public: "32ba0cccec06ac4259b39102dcba13677eb385e0fdce99c93406542c5cbed3ec6ac71a81b01207451346402542923449ecf71fc0d69b1d019df34407b532fb2a09005c801e359afb377cc3255e918a096912bf6f7b7e4040532404996e05f78c408760b57fcf9e04c50eb7bc413438aca9d653dd0b6a8353d128370ebd4bdb10"}
	nsis[0] = ServerIdentityStringified{ ID: network.ServerIdentityID(id),
		Description: "New User's zkPOI registration",
		Address: "tls://conode.newuser.com:7770",
		URL: "tls://conode.newuser.com:7771",
		Public: pub, 
		ServiceIdentities: sids}
	req := &NewPublicKey{ 
		Publics:     nsis,
		Sig: []byte("TESTSIG"),
		ByzcoinID: hex.EncodeToString(c.ByzCoin.ID) }

	s:= e.services[0]
	_, err = s.NewPublicKey(req)
	require.NoError(t, err)

	// to check that the roster has been updated with the new ServerIdentity, first obtain new roster list
	serv := s.Context.Service(byzcoin.ServiceName)
	bcService, _ := serv.(*byzcoin.Service)
	require.NoError(t, err)

	reqProof := &byzcoin.GetProof{
		Version: byzcoin.CurrentVersion,
		Key:     byzcoin.ConfigInstanceID.Slice(),
		ID:      c.ByzCoin.ID,
	}
	pr, err := bcService.GetProof(reqProof)
	require.NoError(t, err)

	proof := pr.Proof
	_, value, _, _, err := proof.KeyValue()
	require.NoError(t, err)

	var chainCfg byzcoin.ChainConfig
	err = protobuf.DecodeWithConstructors(value, &chainCfg, network.DefaultConstructors(cothority.Suite))
	require.NoError(t, err)

	// the roster list has increased by 1 to a total of 6
	require.Equal(t, len(chainCfg.Roster.List), 6)
}

type Client struct {
	ByzCoin *byzcoin.Client
	DarcID darc.ID
	Signers    []darc.Signer
	c          *onet.Client
	sc         *skipchain.Client
	signerCtrs []uint64
}

func NewClient(ol *byzcoin.Client) *Client {
	return &Client{
		ByzCoin:    ol,
		c:          onet.NewClient(cothority.Suite, ServiceName),
		sc:         skipchain.NewClient(),
		signerCtrs: nil,
	}
}

type env struct {
	local    *onet.LocalTest
	hosts    []*onet.Server
	roster   *onet.Roster
	services []*Service
	id       skipchain.SkipBlockID
	owner    darc.Signer
	req      *byzcoin.CreateGenesisBlock
	gen      darc.Darc
}

func newEnv(t *testing.T) (s *env, c *Client) {
	s = &env{ owner: darc.NewSignerEd25519(nil, nil) }
	s.local = onet.NewLocalTestT(cothority.Suite, t)
	s.hosts, s.roster, _ = s.local.GenTree(5, true)

	for _, sv := range s.local.GetServices(s.hosts, zkPOIService) {
		s.services = append(s.services, sv.(*Service))
	}

	var err error
	s.req, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster,
		[]string{"spawn:dummy"}, s.owner.Identity())
	if err != nil {
		t.Fatal(err)
	}
	s.gen = s.req.GenesisDarc
	s.req.BlockInterval = testBlockInterval
	cl := onet.NewClient(cothority.Suite, byzcoin.ServiceName)

	var resp byzcoin.CreateGenesisBlockResponse
	err = cl.SendProtobuf(s.roster.List[0], s.req, &resp)
	if err != nil {
		t.Fatal(err)
	}
	s.id = resp.Skipblock.Hash

	ol := byzcoin.NewClient(s.id, *onet.NewRoster([]*network.ServerIdentity{s.roster.List[0]}))

	c = NewClient(ol)
	c.DarcID = s.gen.GetBaseID()
	c.Signers = []darc.Signer{s.owner}

	// Need to update the default "invoke:config.update_config" darc rule to include first node on the roster
	action := "invoke:config.update_config"
	var identities [2]string
	identities[0] = s.owner.Identity().String()
	identities[1] = "ed25519:" + s.roster.List[0].Public.String()

	Y := expression.InitParser(func(s string) bool { return true })
	for _, id := range identities {
		expr := []byte(id)
		_, err := expression.Evaluate(Y, expr)
		require.NoError(t, err)
	}

	var groupExpr expression.Expr
	groupExpr = expression.InitOrExpr(identities[0], identities[1])

	d2 := s.gen.Copy()
	err = d2.EvolveFrom(&s.gen)
	require.NoError(t, err)

	err = d2.Rules.UpdateRule(darc.Action(action), groupExpr)
	require.NoError(t, err)

	d2Buf, err := d2.ToProto()
	require.NoError(t, err)

	counters, err := c.ByzCoin.GetSignerCounters(s.owner.Identity().String())

	invoke := byzcoin.Invoke{
		ContractID: byzcoin.ContractDarcID,
		Command:    "evolve_unrestricted",
		Args: []byzcoin.Argument{
			{
				Name:  "darc",
				Value: d2Buf,
			},
		},
	}

	ctx, err := c.ByzCoin.CreateTransaction(byzcoin.Instruction{
		InstanceID:    byzcoin.NewInstanceID(d2.GetBaseID()),
		Invoke:        &invoke,
		SignerCounter: []uint64{counters.Counters[0] + 1},
	})
	require.NoError(t, err)

	err = ctx.FillSignersAndSignWith(s.owner)
	require.NoError(t, err)

	_, err = c.ByzCoin.AddTransactionAndWait(ctx, 10)
	require.NoError(t, err)

	err = c.ByzCoin.WaitPropagation(-1)
	require.NoError(t, err)

	return
}
