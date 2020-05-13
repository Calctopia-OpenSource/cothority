// Package viewchange implements the view-change algorithm found in the PBFT
// paper (OSDI99). The implementation is specific to our use-case, meaning that
// our views are represented by skipblocks. However, it is possible to create
// an interface that abstracts the underlying data-structure of a view.
//
// The key component is the Controller. It acts as a finite state machine (FSM)
// that reacts to incoming messages. Under normal operation, the FSM waits for
// 2f+1 valid InitReq messages (also known as view-change messages in the
// paper) and then starts a timer. If the timer expires before the view-change
// is completed, then the FSM goes back to the initial state. Please see the
// paper to see how it handles other scenarios.
package viewchange

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"math"
	"time"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// maxTimeout is an upper bound for the view change timeout as it is increasing
// exponentially.
const maxTimeout = 1 * time.Minute

// View assume that the context are the same.
type View struct {
	ID          skipchain.SkipBlockID
	Gen         skipchain.SkipBlockID
	LeaderIndex int
}

// Equal checks whether the receiver equals to other.
func (v View) Equal(other View) bool {
	return v.ID.Equal(other.ID) && v.Gen.Equal(other.Gen) && v.LeaderIndex == other.LeaderIndex
}

func (v View) String() string {
	return fmt.Sprintf("ID: %x, Gen: %x, Leader: %d", v.ID, v.Gen, v.LeaderIndex)
}

// Hash computes the of the view.
func (v View) Hash() []byte {
	h := sha256.New()
	h.Write(v.ID)
	h.Write(v.Gen)

	idxBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(idxBuf, uint32(v.LeaderIndex))
	h.Write(idxBuf)

	return h.Sum(nil)
}

// SendInitReqFunc is a callback that must be registered in Controller. It is
// called when the Controller decides to multicast a view-change message.
type SendInitReqFunc func(view View) error

// SendNewViewReqFunc is a callback that must be registered in Controller. It
// is called when the Controller decides to propose itself as the new leader.
// The function should not block. The successful execution of this function
// should send a signal back to the Controller by calling Done.
type SendNewViewReqFunc func(proof []InitReq) error

// IsLeaderFunc is a callback that must be registered in Controller. It should
// say whether the node itself is the leader in the given view.
type IsLeaderFunc func(view View) bool

// Controller accepts three types of messages from the outside - (1) a
// view-change message from another node, (2) an anomaly message from myself
// and (3) a notification of the completion of a view-change. There are three
// states in the controller, (1) the initial state, (2) the sent request state
// and (3) the started timer state. Depending on the messages that the
// controller receives, the state might be moved forward or reset.
// The caller of the controller is expected to behave correctly. That is, it
// should not send views from a different context (i.e., from a different
// skipchain) to the controller.
type Controller struct {
	reqChan          chan InitReq
	doneChan         chan View
	waiting          chan chan bool
	closeMonitorChan chan bool
	sendInitReq      SendInitReqFunc
	sendNewViewReq   SendNewViewReqFunc
	isLeader         IsLeaderFunc

	// The following channels are for testing the internal state.
	expireTimerChan chan int
	startTimerChan  chan int
	stopTimerChan   chan int
}

// NewController creates a new Controller. Upon creation, the controller is not
// active, Start must be called to activate it.
func NewController(sendInitReq SendInitReqFunc, sendNewView SendNewViewReqFunc, isLeader IsLeaderFunc) Controller {
	return Controller{
		reqChan:          make(chan InitReq, 1),
		doneChan:         make(chan View, 1),
		waiting:          make(chan chan bool, 1),
		closeMonitorChan: make(chan bool),
		sendInitReq:      sendInitReq,
		sendNewViewReq:   sendNewView,
		isLeader:         isLeader,

		// Make non-blocking channels, to remove races between starting/stopping and
		// the expiration of the viewchange.
		expireTimerChan: make(chan int, 1),
		startTimerChan:  make(chan int, 1),
		stopTimerChan:   make(chan int, 1),
	}
}

// Stop should only be called from the test, it blocks until the controller is
// closed.
func (c *Controller) Stop() {
	c.closeMonitorChan <- true
}

// Start begins a blocking process that processes incoming view-requests.
func (c *Controller) Start(myID network.ServerIdentityID,
	genesis skipchain.SkipBlockID, initialDuration time.Duration,
	threshold int) {
	meta := newStateLogs()
	// Timer is only valid for the current ctr. It starts in the stopped
	// state, we can't set it to nil because it gets de-referenced in
	// select.
	timer := time.NewTimer(time.Second)
	if !timer.Stop() {
		<-timer.C
	}
	var ctr int
	// The loop below implements the view-change state machine. It can be
	// in one of three states (defined in state) and four transitions
	// (close is not a transition) defined in the case statements below.
	for {
		select {
		case req := <-c.reqChan:
			// Transition: received a view-change request, start
			// the timer and move the state if there are 'threshold' valid
			// requests.
			if myID.Equal(req.SignerID) {
				log.Lvl4("adding anomaly:", req.View.LeaderIndex,
					req.SignerID.String())
				meta.add(req)
				ctr = c.processAnomaly(req, &meta, ctr)
			} else {
				log.Lvl4("adding req:", req.View.LeaderIndex,
					req.SignerID.String())
				meta.add(req)
				// Previously the node started to propagate view-changes
				// already if enough other nodes sent a view-change.
				// But this means that a node would participate in a view
				// -change, even if it thinks it's not correct.
				// So this code has been removed.
				// But it might be breaking stuff :(
			}
			log.Lvlf2("counter: %d, thr: %d, meta[ctr] (#/state): %d/%d, "+
				"req: %+v", ctr, threshold, meta.countOf(ctr), meta.stateOf(ctr), req)
			if meta.countOf(ctr) >= threshold && meta.stateOf(
				ctr) < startedTimerState && meta.acceptOf(ctr) {
				// To avoid starting the next view-change too
				// soon, start view-change timer after
				// receiving 2*f+1 view-change messages.
				timeout := maxTimeout
				backoff := float64(ctr)

				// Do some maths to make sure that it will not calculate a value
				// bigger than maxTimeout.
				//   maxTimeout = 2**backoff * initialDuration
				//   maxTimeout / initialDuration = 2**backoff
				//   log2(maxtimeout / initialDuration) = backoff
				// So as long as backoff is smaller than this log, all is fine.
				if backoff < math.Log2(float64(maxTimeout)/
					float64(initialDuration)) {
					timeout = time.Duration(math.Pow(2, backoff)) *
						initialDuration
				}
				log.Lvlf2("backoff = %f - timeout: %s", backoff,
					timeout.String())

				timer.Reset(timeout)
				meta.nextStateFor(ctr)
				select {
				case c.startTimerChan <- ctr:
				default:
				}

				// If I am the leader, send the new-view message,
				// which means starting ftcosi.
				if c.isLeader(meta.currOf(ctr)) {
					if err := c.sendNewViewReq(meta.getProof(ctr)); err != nil {
						log.Errorf("couldn't send view-change request: %+v",
							err)
					}
				}
			}
		case view := <-c.doneChan:
			// Transition: view-change completed successfully, go
			// back to the initial state.
			if meta.empty() {
				log.Warn("doing nothing because the controller is in an empty state for view:", view)
				continue
			}
			if view.Equal(meta.currOf(ctr)) {
				log.Lvl1("view-change completed successfully for view: ", view)
			} else {
				// Usually this should not happen, if it does,
				// that means the controller decided to move on
				// to a later view too soon. But if this
				// section of the code is execute, that means
				// the majority of the nodes agreed, so we'll
				// accept the view.
				log.Warn("view-change completed an earlier view: ", view, "the current view is: ", meta.currOf(ctr))
			}
			ctr = 0
			stopTimer(timer, c.stopTimerChan, ctr)
			meta = newStateLogs()
		case <-timer.C:
			select {
			case c.expireTimerChan <- ctr:
			default:
			}
			// Transition: timer expired, view-change did not
			// complete, so increase the timer multiplier.
			view := View{
				ID:          meta.currOf(ctr).ID,
				Gen:         genesis,
				LeaderIndex: ctr + 1,
			}
			log.Lvl1("view-change timer expired, creating new view:", view)
			req := InitReq{
				View:     view,
				SignerID: myID,
			}
			meta.add(req)
			ctr = c.processAnomaly(req, &meta, ctr)
			meta.clean(ctr)
		case ch := <-c.waiting:
			if meta.stateOf(ctr) == startedTimerState {
				ch <- true
			} else {
				ch <- false
			}
		case <-c.closeMonitorChan:
			stopTimer(timer, c.stopTimerChan, ctr)
			return
		}
	}
}

func (c *Controller) processAnomaly(req InitReq, meta *stateLogs, ctr int) int {
	if req.View.LeaderIndex > ctr {
		// We detected a new anomaly, so send a new
		// view-change message.
		ctr = req.View.LeaderIndex
		if meta.stateOf(ctr) < sentReqState {
			if err := c.sendInitReq(meta.currOf(ctr)); err != nil {
				log.Error("failed to send request", err)
			} else {
				meta.nextStateFor(ctr)
				meta.accept(ctr)
			}
		}
	} else {
		// We blackhole the anomaly if the leader index
		// is less or equal to the counter. This
		// situation only happens if we detect an
		// anomaly for an earlier view. But the
		// controller has already moved on and it will
		// only wait for relevant messages for its
		// current or later view.
		log.Lvlf4("Controller is not accepting anomalies for earlier views"+
			": %d <= %d", req.View.LeaderIndex, ctr)
	}
	return ctr
}

// AddReq adds the request to the log. It assumes the caller is correct and
// does not add bogus requests. We first check that the current view is the
// same as the one in our request. If it is, then we need to update the current
// view in the receiver. Finally, we add the request.
func (c *Controller) AddReq(req InitReq) {
	c.reqChan <- req
}

// Done should be called when a view-change is completed.
func (c *Controller) Done(view View) {
	c.doneChan <- view
}

// Waiting returns true if the controller is waiting for the view-change
// procedure to complete.
func (c *Controller) Waiting() bool {
	ch := make(chan bool, 1)
	c.waiting <- ch
	return <-ch
}

// InitReq is the request that is sent by SendInitReqFunc. It is the
// "view-change" message from the PBFT paper.
type InitReq struct {
	// SignerID is the ID of the request sender.
	View      View
	SignerID  network.ServerIdentityID
	Signature []byte
}

// Hash computes the digest of the request.
func (req InitReq) Hash() []byte {
	h := sha256.New()
	h.Write(req.SignerID[:])
	h.Write(req.View.ID)

	idxBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(idxBuf, uint32(req.View.LeaderIndex))
	h.Write(idxBuf)
	return h.Sum(nil)
}

// Sign signs the request.
func (req *InitReq) Sign(sk kyber.Scalar) error {
	sig, err := schnorr.Sign(cothority.Suite, sk, req.Hash())
	if err != nil {
		return err
	}
	req.Signature = sig
	return nil
}

// NewViewReq is the message that is created and sent out by SendNewViewReqFunc.
type NewViewReq struct {
	Roster onet.Roster
	Proof  []InitReq
}

// NewNewViewReq creates a new view request given the current roster and a
// set of proofs.
// It verifies that all proofs are unique,
// point to the same view, and that the signatures are correct.
func NewNewViewReq(old *onet.Roster, proofs []InitReq) (*NewViewReq, error) {
	newRoster := rotateRoster(old, proofs[0].View.LeaderIndex)
	nvr := &NewViewReq{
		Roster: *newRoster,
		Proof:  proofs,
	}
	if err := nvr.VerifySignatures(old); err != nil {
		return nil, err
	}
	if err := nvr.VerifyUniqueness(); err != nil {
		return nil, err
	}
	return nvr, nil
}

// Hash computes the digest of the request.
func (req NewViewReq) Hash() []byte {
	h := sha256.New()
	h.Write(req.Roster.ID[:])
	for _, p := range req.Proof {
		h.Write(p.Hash())
	}
	return h.Sum(nil)
}

// GetGen gets the first genesis block in the list, if the list is empty it
// returns nil. It assumes all the genesis blocks are the same.
func (req NewViewReq) GetGen() []byte {
	for _, p := range req.Proof {
		return p.View.Gen
	}
	return nil
}

// GetView gets the first view in the list, if the list is empty it returns
// nil. It assumes all the views are the same.
func (req NewViewReq) GetView() *View {
	for _, p := range req.Proof {
		return &p.View
	}
	return nil
}

// Verify that the view request is correct.
// The skipblock passed must be the latest skipblock available.
func (req NewViewReq) Verify(sb *skipchain.SkipBlock) error {
	if !sb.Hash.Equal(req.GetView().ID) {
		return errors.New("wrong block id")
	}

	// Check that we know about the view and the new roster in the request
	// matches the view-change proofs.
	newRoster := rotateRoster(sb.Roster, req.GetView().LeaderIndex)
	equal, err := newRoster.Equal(&req.Roster)
	if err != nil {
		return fmt.Errorf("while comparing rosters: %v", err)
	}
	if !equal {
		return errors.New("invalid roster in request")
	}

	if err := req.VerifyUniqueness(); err != nil {
		return fmt.Errorf("proofs are not unique: %v", err)
	}
	threshold := protocol.DefaultThreshold(len(sb.Roster.List))
	uniqueSigners := len(req.Proof)
	if uniqueSigners < threshold {
		return fmt.Errorf("not enough proofs: %d < %d", uniqueSigners,
			threshold)
	}

	defer log.Lvl2("view-change verification OK")
	return req.VerifySignatures(sb.Roster)
}

// VerifyUniqueness makes sure that all requests are unique and point to the
// same view.
func (req NewViewReq) VerifyUniqueness() error {
	ids := make(map[network.ServerIdentityID]bool)
	for _, p := range req.Proof {
		ids[p.SignerID] = true
		if !req.Proof[0].View.Equal(p.View) {
			return errors.New("have different view")
		}
	}

	if len(ids) != len(req.Proof) {
		return errors.New("got one or more signer twice or more")
	}

	return nil
}

// VerifySignatures verifies that all individual signatures of the proofs are
// correct.
func (req NewViewReq) VerifySignatures(r *onet.Roster) error {
	for _, p := range req.Proof {
		_, sid := r.Search(p.SignerID)
		if sid == nil {
			return errors.New("the signer is not in the roster")
		}
		// Check that the signature is correct.
		if err := schnorr.Verify(cothority.Suite, sid.Public, p.Hash(), p.Signature); err != nil {
			return fmt.Errorf("proof signature failed: %v", err)
		}
	}
	return nil
}

func rotateRoster(roster *onet.Roster, i int) *onet.Roster {
	// handle catastrophic situations where a round of the roster
	// is not enough to find a new leader
	i = i % len(roster.List)

	return onet.NewRoster(append(roster.List[i:], roster.List[:i]...))
}

type state int

const (
	initialState state = iota
	sentReqState
	startedTimerState
)

type stateLog struct {
	curr     View
	received map[network.ServerIdentityID]InitReq
	state    state
	accept   bool // set to true if we received a message for ourself
}

func newStateLog() stateLog {
	return stateLog{
		received: make(map[network.ServerIdentityID]InitReq),
	}
}

func (m *stateLog) add(req InitReq) {
	// Invariant: requests must have the same view
	for _, v := range m.received {
		if !v.View.Equal(req.View) {
			// This happens when the conode is out of sync with respect with the view change and it didn't
			// received yet the new blocks so the state are not reset
			log.Lvlf1("a request has been ignored because it does not match previously received views: %s", req.View.String())
			return
		}
	}
	m.curr = req.View
	m.received[req.SignerID] = req
}

func (m *stateLog) nextState() {
	switch m.state {
	case initialState:
		m.state = sentReqState
	case sentReqState:
		m.state = startedTimerState
	default:
		panic("there is no more next state")
	}
}

func (m stateLog) count() int {
	return len(m.received)
}

type stateLogs struct {
	m map[int]stateLog
}

func newStateLogs() stateLogs {
	return stateLogs{
		m: make(map[int]stateLog),
	}
}

func (m *stateLogs) add(req InitReq) {
	if _, ok := m.m[req.View.LeaderIndex]; !ok {
		m.m[req.View.LeaderIndex] = newStateLog()
	}
	tmp := m.m[req.View.LeaderIndex]
	tmp.add(req)
	m.m[req.View.LeaderIndex] = tmp
}

func (m *stateLogs) accept(i int) {
	tmp := m.m[i]
	tmp.accept = true
	m.m[i] = tmp
}

func (m stateLogs) highest() int {
	i := -1
	for k := range m.m {
		if k > i {
			i = k
		}
	}
	return i
}

func (m *stateLogs) nextStateFor(i int) {
	tmp := m.m[i]
	tmp.nextState()
	m.m[i] = tmp
}

func (m stateLogs) countOf(i int) int {
	return m.m[i].count()
}

func (m stateLogs) stateOf(i int) state {
	return m.m[i].state
}

func (m stateLogs) currOf(i int) View {
	return m.m[i].curr
}

func (m stateLogs) acceptOf(i int) bool {
	return m.m[i].accept
}

func (m stateLogs) getProof(viewIdx int) []InitReq {
	reqs := make([]InitReq, len(m.m[viewIdx].received))
	var i int
	for _, req := range m.m[viewIdx].received {
		reqs[i] = req
		i++
	}
	return reqs
}

func (m stateLogs) empty() bool {
	return len(m.m) == 0
}

func (m *stateLogs) clean(i int) {
	for k := range m.m {
		if k < i {
			delete(m.m, k)
		}
	}
}

func stopTimer(timer *time.Timer, c chan int, i int) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	select {
	case c <- i:
	default:
	}
}
