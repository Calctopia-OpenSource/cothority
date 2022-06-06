package protocol

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/xerrors"
	"sync"
	"time"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// sub_protocol is run by each sub-leader and each node once, and n times by
// the root leader, where n is the number of sub-leader.

// SubBlsCosi holds the different channels used to receive the different protocol messages.
type SubBlsCosi struct {
	*onet.TreeNodeInstance
	Msg            []byte
	Data           []byte
	Timeout        time.Duration
	Threshold      int
	stoppedOnce    sync.Once
	verificationFn VerificationFn
	suite          *pairing.SuiteBn256
	startChan      chan bool
	closeChan      chan struct{}

	// protocol/subprotocol channels
	// these are used to communicate between the subprotocol and the main protocol
	subleaderNotResponding chan bool
	subResponse            chan StructResponse

	// internodes channels
	ChannelAnnouncement chan StructAnnouncement
	ChannelResponse     chan StructResponse
	ChannelRefusal      chan StructRefusal

	// Crypto functions
	Sign      SignFn
	Verify    VerifyFn
	Aggregate AggregateFn
}

// NewDefaultSubProtocol is the default sub-protocol function used for registration
// with an always-true verification.
func NewDefaultSubProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	vf := func(a, b []byte) bool { return true }
	return NewSubBlsCosi(n, vf, pairing.NewSuiteBn256())
}

// NewSubBlsCosi is used to define the subprotocol and to register
// the channels where the messages will be received.
func NewSubBlsCosi(n *onet.TreeNodeInstance, vf VerificationFn, suite *pairing.SuiteBn256) (onet.ProtocolInstance, error) {
	// tests if it's a three level tree
	moreThreeLevel := false
	n.Tree().Root.Visit(0, func(depth int, n *onet.TreeNode) {
		if depth > 2 {
			moreThreeLevel = true
		}
	})
	if moreThreeLevel {
		return nil, fmt.Errorf("subBlsCosi launched with a more than three level tree")
	}

	c := &SubBlsCosi{
		TreeNodeInstance: n,
		Sign:             bls.Sign,
		Verify:           bls.Verify,
		Aggregate: func(suite pairing.Suite, mask *sign.Mask, sigs [][]byte) ([]byte, error) {
			return bls.AggregateSignatures(suite, sigs...)
		},
		verificationFn: vf,
		suite:          suite,
		startChan:      make(chan bool, 1),
		closeChan:      make(chan struct{}),
	}

	if n.IsRoot() {
		c.subleaderNotResponding = make(chan bool, 1)
		c.subResponse = make(chan StructResponse, 1)
	}

	err := c.RegisterChannels(&c.ChannelAnnouncement, &c.ChannelResponse, &c.ChannelRefusal)
	if err != nil {
		return nil, errors.New("couldn't register channels: " + err.Error())
	}
	err = c.RegisterHandler(c.HandleStop)
	if err != nil {
		return nil, errors.New("couldn't register stop handler: " + err.Error())
	}
	return c, nil
}

// Dispatch runs the protocol for each node in the protocol acting according
// to its type
func (p *SubBlsCosi) Dispatch() error {
	defer p.Done()

	// Send announcement to start sending signatures
	if p.IsRoot() {
		return p.dispatchRoot()
	} else if p.Parent().Equal(p.Root()) {
		return p.dispatchSubLeader()
	}

	return p.dispatchLeaf()
}

// HandleStop is called when a Stop message is send to this node.
// It broadcasts the message to all the nodes in tree and each node will stop
// the protocol by calling p.Done.
func (p *SubBlsCosi) HandleStop(stop StructStop) error {
	if !stop.TreeNode.Equal(p.Root()) {
		log.Warn(p.ServerIdentity(), "received a Stop from node", stop.ServerIdentity,
			"that is not the root, ignored")
	}
	log.Lvl3("Received stop", p.ServerIdentity())

	return p.Shutdown()
}

// Shutdown closes the different channel to stop the current work
func (p *SubBlsCosi) Shutdown() error {
	p.stoppedOnce.Do(func() {
		log.Lvlf3("Subprotocol shut down on %v", p.ServerIdentity())
		// Only this channel is closed to cut off expensive operations
		// and select statements but we let other channels be cleaned
		// by the GC to avoid sending to closed channel
		close(p.startChan)
		close(p.closeChan)
	})
	return nil
}

// Start is done only by root and starts the subprotocol
func (p *SubBlsCosi) Start() error {
	log.Lvl3(p.ServerIdentity(), "Starting subCoSi")
	if err := p.checkIntegrity(); err != nil {
		p.startChan <- false
		p.Done()
		return err
	}

	p.startChan <- true
	return nil
}

// waitAnnouncement waits for an announcement of the right node
func (p *SubBlsCosi) waitAnnouncement(parent *onet.TreeNode) *Announcement {
	var a *Announcement
	// Keep looping until the correct announcement to prevent
	// an attacker from killing the protocol with false message
	for a == nil {
		select {
		case <-p.closeChan:
			return nil
		case msg := <-p.ChannelAnnouncement:
			if parent.Equal(msg.TreeNode) {
				a = &msg.Announcement
			}
		}
	}

	p.Msg = a.Msg
	p.Data = a.Data
	p.Timeout = a.Timeout
	p.Threshold = a.Threshold

	return a
}

// dispatchRoot takes care of sending announcements to the children and
// waits for the response with the signatures of the children
func (p *SubBlsCosi) dispatchRoot() error {
	defer func() {
		err := p.Broadcast(&Stop{})
		if err != nil {
			log.Error("error while broadcasting stopping message:", err)
		}
	}()

	// make sure we're ready to go
	hasStarted := <-p.startChan
	if !hasStarted {
		return nil
	}

	subLeaderActive := make(chan error, 1)
	// Because SendToChildren blocks on some firewalls instead of returning
	// an error, this call is put in a go-routine.
	go func() {
		subLeaderActive <- p.SendToChildren(&Announcement{
			Msg:       p.Msg,
			Data:      p.Data,
			Timeout:   p.Timeout,
			Threshold: p.Threshold,
		})
	}()

	for {
		select {
		case err := <-subLeaderActive:
			if err != nil {
				p.subleaderNotResponding <- true
				return xerrors.Errorf("Couldn't contact subleader: %v", err)
			}
		case <-p.closeChan:
			return nil
		case reply := <-p.ChannelResponse:
			if reply.Equal(p.Root().Children[0]) {
				// Transfer the response to the parent protocol
				p.subResponse <- reply
			}
			return nil
		case <-time.After(p.Timeout):
			// It might be only the subleader then we send a notification
			// to let the parent protocol take actions
			log.Warnf("%s: timed out while waiting for subleader response while %s",
				p.ServerIdentity(), p.Tree().Dump())
			p.subleaderNotResponding <- true
			return nil
		}
	}
}

// dispatchSubLeader takes care of synchronizing the children
// responses and aggregate them to eventually send that to
// the root
func (p *SubBlsCosi) dispatchSubLeader() error {
	a := p.waitAnnouncement(p.Root())
	if a == nil {
		return nil
	}

	// generate the challenge nonce for potential refusals
	a.Nonce = make([]byte, 8)
	_, err := rand.Read(a.Nonce)
	if err != nil {
		return err
	}

	if len(p.Children()) > 0 {
		for _, node := range p.Children() {
			go func(node *onet.TreeNode) {
				err := p.SendTo(node, a)
				if err != nil {
					log.Warnf("Error while sending to leaf %s: %v",
						node.Name(), err)
				}
			}(node)
		}
	}

	responses := make(ResponseMap)
	for _, c := range p.Children() {
		_, index := searchPublicKey(p.TreeNodeInstance, c.ServerIdentity)
		if index != -1 {
			// Accept response for those identities only
			responses[index] = nil
		}
	}

	own, err := p.makeResponse()
	if ok := p.verificationFn(p.Msg, p.Data); ok {
		log.Lvlf3("Subleader %v signed", p.ServerIdentity())
		_, index := searchPublicKey(p.TreeNodeInstance, p.ServerIdentity())
		if index != -1 {
			responses[index] = own
		}
	}

	// we need to timeout the children faster than the root timeout to let it
	// know the subleader is alive, but some children are failing
	timeout := time.After(p.Timeout / 2)
	done := 0
	for done < len(p.Children()) {
		select {
		case <-p.closeChan:
			return nil
		case reply := <-p.ChannelResponse:
			public, pubIndex := searchPublicKey(p.TreeNodeInstance, reply.ServerIdentity)
			if public != nil {
				r, ok := responses[pubIndex]
				if !ok {
					log.Warnf("Got a message from an unknown node %v", reply.ServerIdentity.ID)
				} else if r == nil {
					if err := p.Verify(p.suite, public, p.Msg, reply.Signature); err == nil {
						responses[pubIndex] = &reply.Response
						done++
					}
				} else {
					log.Warnf("Duplicate message from %v", reply.ServerIdentity)
				}
			} else {
				log.Warnf("Received unknown server identity %v", reply.ServerIdentity)
			}
		case reply := <-p.ChannelRefusal:
			public, pubIndex := searchPublicKey(p.TreeNodeInstance, reply.ServerIdentity)
			r, ok := responses[pubIndex]

			if !ok {
				log.Warnf("Got a message from an unknown node %v", reply.ServerIdentity.ID)
			} else if r == nil {
				if err := p.Verify(p.suite, public, a.Nonce, reply.Signature); err == nil {
					// The child gives an empty signature as a mark of refusal
					responses[pubIndex] = &Response{}
					done++
				} else {
					log.Warnf("Tentative to send a unsigned refusal from %v", reply.ServerIdentity.ID)
				}
			} else {
				log.Warnf("Duplicate refusal from %v", reply.ServerIdentity)
			}
		case <-timeout:
			log.Lvlf3("Subleader reached timeout waiting for children"+
				" responses: %v", p.ServerIdentity())
			// Use whatever we received until then to try to finish
			// the protocol
			done = len(p.Children())
		}
	}

	r, err := p.makeSubLeaderResponse(responses)
	if err != nil {
		log.Error(err)
		return err
	}

	log.Lvlf3("Subleader %v sent its reply with mask %b", p.ServerIdentity(), r.Mask)
	return p.SendToParent(r)
}

// dispatchLeaf prepares the signature and send it to the subleader
func (p *SubBlsCosi) dispatchLeaf() error {
	a := p.waitAnnouncement(p.Root().Children[0])
	if a == nil {
		return nil
	}

	res := make(chan bool)
	go p.makeVerification(res)

	// give a chance to avoid sending the response if a stop
	// has been requested
	select {
	case <-p.closeChan:
		// ...but still wait for the response so that we don't leak the goroutine
		<-res
		return nil
	case ok := <-res:
		var r interface{}
		var err error
		if ok {
			log.Lvlf3("Leaf %v signed", p.ServerIdentity())
			r, err = p.makeResponse()
			if err != nil {
				return err
			}
		} else {
			log.Lvlf3("Leaf %v refused to sign", p.ServerIdentity())
			r, err = p.makeRefusal(a.Nonce)
			if err != nil {
				return err
			}
		}

		return p.SendToParent(r)
	}
}

// Sign the message and pack it with the mask as a response
func (p *SubBlsCosi) makeResponse() (*Response, error) {
	mask, err := sign.NewMask(p.suite, p.Publics(), p.Public())
	if err != nil {
		log.Error(err)
		return nil, err
	}

	sig, err := p.Sign(p.suite, p.Private(), p.Msg)
	if err != nil {
		return nil, err
	}

	return &Response{
		Mask:      mask.Mask(),
		Signature: sig,
	}, nil
}

// makeRefusal will sign a random nonce so that we can check
// that the refusal is not forged
func (p *SubBlsCosi) makeRefusal(nonce []byte) (*Refusal, error) {
	sig, err := p.Sign(p.suite, p.Private(), nonce)

	return &Refusal{Signature: sig}, err
}

// makeVerification executes the verification function provided and
// returns the result in the given channel
func (p *SubBlsCosi) makeVerification(out chan bool) {
	out <- p.verificationFn(p.Msg, p.Data)
}

// makeSubLeaderResponse aggregates its own signature with the children's and it also
// creates the final mask for this aggregation
func (p *SubBlsCosi) makeSubLeaderResponse(responses ResponseMap) (*Response, error) {
	pubs := p.Publics()
	mask, err := sign.NewMask(p.suite, pubs, nil)
	if err != nil {
		return nil, err
	}

	sigs := [][]byte{}
	for idx, res := range responses {
		if res == nil || len(res.Signature) == 0 {
			continue
		}

		err = mask.Merge(res.Mask)
		if err != nil {
			return nil, err
		}

		i := mask.NthEnabledAtIndex(idx)
		sigs = append(sigs[:i], append([][]byte{res.Signature}, sigs[i:]...)...)
	}

	agg, err := p.Aggregate(p.suite, mask, sigs)

	return &Response{Signature: agg, Mask: mask.Mask()}, err
}

// checkIntegrity checks that the subprotocol can start with the current
// parameters
func (p *SubBlsCosi) checkIntegrity() error {
	if p.Msg == nil {
		return errors.New("subprotocol does not have a proposal msg")
	}
	if p.verificationFn == nil {
		return errors.New("subprotocol has an empty verification fn")
	}
	if p.Timeout < 10*time.Nanosecond {
		return errors.New("unrealistic timeout")
	}
	if p.Threshold > p.Tree().Size() {
		return errors.New("threshold bigger than number of nodes in subtree")
	}
	if p.Threshold < 1 {
		return fmt.Errorf("threshold of %d smaller than one node", p.Threshold)
	}

	return nil
}
