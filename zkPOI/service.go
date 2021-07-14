package zkPOI

import (
	"sync"
	"net"
	"encoding/hex"
	
	"golang.org/x/xerrors"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)


const ServiceName = "zkPOI"

var zkPOIService onet.ServiceID

const dbVersion = 1
var storageKey = []byte("storage")

// Service handles.Storage.Identities
type Service struct {
	*onet.ServiceProcessor
	Storage            *storage1
	storageMutex       sync.Mutex
	skipchain          *skipchain.Service
}

func init() {
	var err error
	zkPOIService, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessage(&storage1{})
}

// saves all data.
func (s *Service) save() error {
    log.Lvl2("Saving service")
	s.storageMutex.Lock()
	defer s.storageMutex.Unlock()
	err := s.Save(storageKey, s.Storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
	if err := s.SaveVersion(dbVersion); err != nil {
		log.Error(err)
	}
	return nil
}

// Tries to load the configuration and updates if a configuration
// is found, else it returns an error.
func (s *Service) tryLoad() error {
    s.Storage = &storage1{}
	defer func() {
		if s.Storage.Auth == nil {
				s.Storage.Auth = &authData1{}
	    }
    }()
	buf, err := s.LoadRaw(storageKey)
	if err != nil {
		return err
	}
	if len(buf) <= 16 {
		return nil
	}
	return protobuf.DecodeWithConstructors(buf[16:], s.Storage,
			network.DefaultConstructors(cothority.Suite))
}

// byzcoin admin must grant permissions to a node of the current roster (e.g., 7f9fd54039faac7590387c593137eaf7641deaa890625ffb92edc9097c11a27a) so said node is able to update the roster
// bcadmin -c . darc rule -bc bc-b22a7c22a8100995fb85ba395e18e21da9398e8e7f864b49c376a7e6226d95c0.cfg -rule invoke:config.update_config -replace -identity "ed25519:7f9fd54039faac7590387c593137eaf7641deaa890625ffb92edc9097c11a27a | ed25519:b8fb65918720f04538d8ad333779bf8ffc705471e4e738de8bda26a66f568bf2" 

// NewPublicKey accepts new public key, verifies it and saves public credentials from it
func (s *Service) NewPublicKey(req *NewPublicKey) (network.Message, error) {
	// Check whether connection comes from localhost
	na := s.ServerIdentity().Address.NetworkAddress()
	if na == "" {
		log.Error("Network address not available")
		return nil, xerrors.New("Network address not available")
	}
	h, _, err := net.SplitHostPort(na)
	if err != nil {
		log.Error("Unable to split host:port")
		return nil, xerrors.New("Network Unable to split host:port")
	}
    if h != "localhost" {
	    IP := net.ParseIP(h)
	    if IP == nil {
			log.Error("Unable to parse IP address")
			return nil, xerrors.Errorf("Unable to parse IP address: %w, %w", h, na)
	    } else if !IP.IsLoopback() {
			log.Error("DENIED: Connection not from localhost")
			return nil, xerrors.New("DENIED: Connection not from localhost")
	    }
    }
	
	log.Lvl3("Store new public key: ", s.ServerIdentity())

	if req.Publics == nil || len(req.Publics) == 0 {
			log.Error("No public keys in request")
			return nil, xerrors.New("Invalid request")
	}

	signer := darc.NewSignerEd25519(s.ServerIdentity().Public, s.ServerIdentity().GetPrivate())

	log.Lvl2("Getting latest chainConfig")
	id, err := hex.DecodeString(req.ByzcoinID)
	if err != nil || len(id) != 32 {
		return nil, xerrors.New("request does not contain a valid byzcoin ID")
	}

	cl := byzcoin.NewClient(nil, onet.Roster{})
	reply, err := cl.GetAllByzCoinIDs(s.ServerIdentity())
	if err != nil {
		return nil, err
	}
	found := false
	for _, idc := range reply.IDs {
		if idc.Equal(id) {
			found = true
			break
		}
	}
	if !found {
		return nil, xerrors.New("couldn't find byzcoinID on current server")
	}
	cl = byzcoin.NewClient(id, *onet.NewRoster([]*network.ServerIdentity{s.ServerIdentity()}))
	chainCfg, err := cl.GetChainConfig()
	if err != nil {
		cl = nil
		return nil, xerrors.New("couldn't get chain config from current server")
	}
	cl.Roster = chainCfg.Roster

	// convert ServerIdentityStringified to network.ServerIdentity
	publics := make([]network.ServerIdentity, len(req.Publics))
	for i, public := range req.Publics {
		serviceIdentities := make([]network.ServiceIdentity, len(public.ServiceIdentities))
		for j, serviceIdentity := range public.ServiceIdentities {
			pub, _ := encoding.StringHexToPoint(suites.MustFind(serviceIdentity.Suite), serviceIdentity.Public)
			serviceIdentities[j] = network.ServiceIdentity { Name: serviceIdentity.Name,
									  Suite: serviceIdentity.Suite,
									  Public: pub}
		}
		publics[i] = network.ServerIdentity { Public: public.Public,
							ServiceIdentities: serviceIdentities,
							ID: public.ID,
							Address: public.Address,
							Description: public.Description,
							URL: public.URL }
	}
	
	// updating configuration (rosterAdd)
	log.Lvl2("Old roster is:", chainCfg.Roster.List)
	old := chainCfg.Roster
	//for _, k := range req.Publics {
	for _, k := range publics {
		if i,_ := old.Search(k.ID); i < 0 {
			old := chainCfg.Roster
			chainCfg.Roster = *old.Concat(&k)
		}
	}
	log.Lvl2("New roster is:", chainCfg.Roster.List)

	err = updateConfig(cl, &signer, *chainCfg)
	if err != nil {
		return nil, err
	}
	log.Lvl1("New roster is now active")

	return nil, nil
}

func updateConfig(cl *byzcoin.Client, signer *darc.Signer, chainConfig byzcoin.ChainConfig) error {
	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return xerrors.Errorf("couldn't get counters: %v", err)
	}
	counters.Counters[0]++
	ccBuf, err := protobuf.Encode(&chainConfig)
	if err != nil {
		return xerrors.Errorf("couldn't encode chainConfig: %v", err)
	}
	ctx, err := cl.CreateTransaction(byzcoin.Instruction{
		InstanceID: byzcoin.ConfigInstanceID,
		Invoke: &byzcoin.Invoke{
			ContractID: byzcoin.ContractConfigID,
			Command:    "update_config",
			Args:       byzcoin.Arguments{{Name: "config", Value: ccBuf}},
		},
		SignerCounter: counters.Counters,
	})
	if err != nil {
		return err
	}

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return xerrors.Errorf("couldn't sign the clientTransaction: %v", err)
	}

	log.Lvl1("Sending new roster to byzcoin")
	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return xerrors.Errorf("client transaction wasn't accepted: %v", err)
	}
	return nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		skipchain:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}

	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	if err := s.RegisterHandler(s.NewPublicKey); err != nil {
		log.Error("Registration error:", err)
		return nil, err
	}
	return s, nil
}

// storage1 holds the map to the storages so it can be marshaled.
type storage1 struct {
	// The key that is stored in the skipchain service to authenticate
	// new blocks.
	SkipchainKeyPair *key.Pair
	Auth *authData1
}

type authData1 struct {
	// list of AdminKeys
	AdminKeys []kyber.Point
}
