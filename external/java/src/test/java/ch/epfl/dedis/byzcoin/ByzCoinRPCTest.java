package ch.epfl.dedis.byzcoin;

import ch.epfl.dedis.byzcoin.contracts.ChainConfigData;
import ch.epfl.dedis.byzcoin.contracts.ChainConfigInstance;
import ch.epfl.dedis.byzcoin.transaction.*;
import ch.epfl.dedis.integration.TestServerController;
import ch.epfl.dedis.integration.TestServerInit;
import ch.epfl.dedis.lib.SkipBlock;
import ch.epfl.dedis.lib.SkipblockId;
import ch.epfl.dedis.lib.darc.Darc;
import ch.epfl.dedis.lib.darc.Signer;
import ch.epfl.dedis.lib.darc.SignerEd25519;
import ch.epfl.dedis.lib.exception.CothorityCommunicationException;
import ch.epfl.dedis.lib.exception.CothorityCryptoException;
import ch.epfl.dedis.lib.exception.CothorityException;
import ch.epfl.dedis.lib.exception.CothorityPermissionException;
import ch.epfl.dedis.lib.network.Roster;
import ch.epfl.dedis.lib.network.ServerIdentity;
import ch.epfl.dedis.lib.proto.ByzCoinProto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static java.time.temporal.ChronoUnit.MILLIS;
import static org.junit.jupiter.api.Assertions.*;

public class ByzCoinRPCTest {
    public final static Duration BLOCK_INTERVAL = Duration.of(1000, MILLIS);

    private ByzCoinRPC bc;
    private Signer admin;
    private final static Logger logger = LoggerFactory.getLogger(ByzCoinRPCTest.class);
    private TestServerController testInstanceController;

    @BeforeEach
    void initAll() throws Exception {
        testInstanceController = TestServerInit.getInstance();
        admin = new SignerEd25519();
        Darc genesisDarc = ByzCoinRPC.makeGenesisDarc(admin, testInstanceController.getRoster());

        bc = new ByzCoinRPC(testInstanceController.getRoster(), genesisDarc, BLOCK_INTERVAL);
        if (!bc.checkLiveness()) {
            throw new CothorityCommunicationException("liveness check failed");
        }
    }

    @Test
    void ping() {
        assertTrue(bc.checkLiveness());
    }

    @Test
    void getBlocks() throws Exception {
        // First get the genesis block
        SkipBlock candidate = bc.getSkipchain().getSkipblock(this.bc.getGenesisBlock().getId());
        assertEquals(candidate.getId(), this.bc.getGenesisBlock().getId());

        // Update should give us the genesis block
        assertEquals(bc.getLatestBlock().getId(), this.bc.getGenesisBlock().getId());

        // Then make a transaction, and we should see a new block, here it's just a darc evolution
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head()+1, 10);

        // Update again should give us a different block
        assertNotEquals(bc.getLatestBlock().getId(), this.bc.getGenesisBlock().getId());

        // Getting the block should work
        SkipBlock latest = bc.getSkipchain().getSkipblock(bc.getLatestBlock().getId());
        assertEquals(latest.getId(), bc.getLatestBlock().getId());

        // Get the genesis block again and it should have at least one forward links
        SkipBlock newGenesis = bc.getSkipchain().getSkipblock(this.bc.getGenesisBlock().getId());
        assertTrue(newGenesis.getForwardLinks().size() > 0);
    }

    @Test
    void getProof() throws Exception {
        // Then make a transaction so we can do something with the proof.
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head()+1, 10);

        // Get one Proof.
        InstanceId inst = bc.getGenesisDarcInstance().getInstance().getId();
        Proof p = bc.getProof(inst);
        assertTrue(p.exists(inst.getId()));
        assertEquals(2, p.toProto().getLinksList().size());

        bc.update();
        p = bc.getProofFromLatest(inst);
        assertTrue(p.exists(inst.getId()));
        assertEquals(1, p.toProto().getLinksList().size());
    }

    /**
     * We only give the client the roster and the genesis ID. It should be able to find the configuration, latest block
     * and the genesis darc.
     */
    @Test
    void reconnect() throws Exception {
        ByzCoinRPC bcCopy = ByzCoinRPC.fromByzCoin(bc.getRoster(), bc.getGenesisBlock().getSkipchainId());
        assertEquals(bc.getConfig().getBlockInterval(), bcCopy.getConfig().getBlockInterval());
        // check that getMaxBlockSize returned what we expect (from defaultMaxBlockSize in Go).
        assertEquals(4000000, bcCopy.getConfig().getMaxBlockSize());
        assertEquals(bc.getLatestBlock().getTimestampNano(), bcCopy.getLatestBlock().getTimestampNano());
        assertEquals(bc.getGenesisDarc().getBaseId(), bcCopy.getGenesisDarc().getBaseId());
    }

    class TestReceiver implements Subscription.SkipBlockReceiver {
        private int ctr;
        private String error;

        private TestReceiver() {
            ctr = 0;
        }

        @Override
        public void receive(SkipBlock block) {
            if (isOk()) {
                ctr++;
            }
        }

        @Override
        public void error(String s) {
            if (isOk()) {
                error = s;
            }
        }

        private int getCtr() {
            return ctr;
        }

        private boolean isOk() {
            return error == null;
        }
    }

    /**
     * Subscribes to new blocks and verifies it gets them.
     */
    @Test
    void subscribeSkipBlocks() throws Exception {
        logger.info("Subscribing blocks");
        TestReceiver receiver = new TestReceiver();
        assertTrue(bc.getSubscription().isClosed());
        bc.subscribeSkipBlock(receiver);
        assertFalse(bc.getSubscription().isClosed());
        // Wait for two block intervals, we should see 0 blocks because we haven't done anything
        Thread.sleep(4 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(0, receiver.getCtr());

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        // Update the darc and thus create one block
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin,counters.head()+1, 10);
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        assertNotEquals(0, receiver.getCtr());
        bc.unsubscribeBlock(receiver);
    }

    /**
     * Subscribe to new blocks using a stream
     */
    @Test
    void subscribeSkipBlockStream() throws Exception {
        Stream<SkipBlock> stream = bc.subscribeSkipBlock();

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        // create one block
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head()+1, 0);

        // no need to wait as it will hang until one block is accepted
        assertEquals(1, stream.limit(1).count());

        stream.close();
    }

    @Test
    void multipleSubscribeSkipBlocks() throws Exception {
        logger.info("Subscribing blocks");
        List<TestReceiver> receivers = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            TestReceiver receiver = new TestReceiver();
            bc.subscribeSkipBlock(receiver);
            receivers.add(receiver);
        }
        assertFalse(bc.getSubscription().isClosed());

        // Wait for two block intervals, we should see 0 blocks because we haven't done anything
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        for (TestReceiver receiver : receivers) {
            assertEquals(0, receiver.getCtr());
        }

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        // Update the darc and thus create some blocks
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head()+1, 10);
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        for (TestReceiver receiver : receivers) {
            assertNotEquals(0, receiver.getCtr());
        }

        // Remove all, then the connection should close.
        for (TestReceiver receiver : receivers) {
            bc.unsubscribeBlock(receiver);
        }
    }


    class TestTxReceiver implements Subscription.SkipBlockReceiver {
        private List<ClientTransaction> allCtxs;
        private String error;

        private TestTxReceiver() {
            super();
            allCtxs = new ArrayList<>();
        }

        @Override
        public void receive(SkipBlock block) {
            logger.info("got SkipBlock {}", block);
            try {
                Block b = new Block(block);
                allCtxs.addAll(b.getAcceptedClientTransactions());
            } catch (CothorityCryptoException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void error(String s) {
            if (error == null) {
                error = s;
            }
        }

        private List<ClientTransaction> getAllCtxs() {
            return allCtxs;
        }
    }

    /**
     * Subscribes to new blocks and verifies it gets them.
     */
    @Test
    void subscribeClientTransactions() throws Exception {
        // Create a second subscription that will receive multiple blocks at once.
        TestReceiver receiver = new TestReceiver();
        Subscription sub2 = new Subscription(bc);
        sub2.subscribeSkipBlock(receiver);
        TestTxReceiver txReceiver = new TestTxReceiver();
        bc.subscribeSkipBlock(txReceiver);

        // Wait for two possible blocks and make sure we don't get any transactions
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(0, receiver.getCtr());
        assertEquals(0, txReceiver.getAllCtxs().size());

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        // Update the darc and thus create at least one block with at least the interesting clientTransaction
        ClientTransactionId ctxid = bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head() + 1, 10);

        Thread.sleep(10 * bc.getConfig().getBlockInterval().toMillis());
        assertNotEquals(0, txReceiver.getAllCtxs().size());
        assertEquals(1, txReceiver.getAllCtxs().stream().filter(ctx ->
                ctx.getId().equals(ctxid)).count());

        // Update the darc again - even if it's the same darc
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head() + 2, 10);

        Thread.sleep(3 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(2, receiver.getCtr());
    }

    @Test
    void streamClientTransaction() throws Exception {
        TestReceiver receiver = new TestReceiver();
        ServerIdentity.StreamingConn conn = bc.streamTransactions(receiver);

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        // Generate a block by updating the darc.
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head() + 1, 10);
        Thread.sleep(bc.getConfig().getBlockInterval().toMillis());
        assertTrue(receiver.isOk());
        assertNotEquals(0, receiver.getCtr());

        conn.close();
    }

    @Test
    void updateInterval() throws Exception {
        logger.info("test-start: updateInterval");
		
        // Get the counter for the admin and increment it
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));
        counters.increment();

        List<Signer> admins = Collections.singletonList(admin);
        assertThrows(CothorityPermissionException.class,
                () -> bc.setBlockInterval(Duration.ofMillis(4999), admins, counters.getCounters(), 10)
        );
        logger.info("Setting interval to 5 seconds");
        Duration newInterval = Duration.ofMillis(5000);
        bc.setBlockInterval(newInterval, admins, counters.getCounters(), 10);

        // we need to make one dummy transaction before timing the block interval because there is a delay
        // for the new block interval to take effect
        counters.increment();
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head(), 10);

        Instant now = Instant.now();
        counters.increment();
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head(), 10);
        // check if the interval has changed - as there is no method to update the configuration, create a new RPC...
        ByzCoinRPC newBC = ByzCoinRPC.fromByzCoin(testInstanceController.getRoster(), bc.getGenesisBlock().getSkipchainId());
        assertEquals(newBC.getConfig().getBlockInterval(), newInterval);


        // Need to set the blockInterval back manually, else it will complain.
        logger.info("Setting interval back to default");
        // The value is in nanoseconds.
        ByzCoinProto.ChainConfig.Builder newCCD = ChainConfigInstance.fromByzcoin(bc).getChainConfig().toProto().toBuilder();
        newCCD.setBlockinterval(BLOCK_INTERVAL.toNanos());

        counters.increment();
        ChainConfigInstance.fromByzcoin(bc).evolveConfigAndWait(new ChainConfigData(newCCD.build()), admins, counters.getCounters(), 10);
    }

    @Test
    void updateMaxBlockSize() throws Exception {
        List<Signer> admins = Collections.singletonList(admin);

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));
        Long ctr = counters.head();

        for (int invalidSize : Arrays.asList(ChainConfigData.blocksizeMin - 1, ChainConfigData.blocksizeMax + 1)) {
            final Long c = ctr + 1;
            assertThrows(CothorityException.class, () ->
                    bc.setMaxBlockSize(invalidSize, admins, Collections.singletonList(c), 10)
            );
        }
        for (int validSize : Arrays.asList(ChainConfigData.blocksizeMin, (ChainConfigData.blocksizeMin + ChainConfigData.blocksizeMax) / 2, ChainConfigData.blocksizeMax)) {
            try {
                ctr++;
                bc.setMaxBlockSize(validSize, admins, Collections.singletonList(ctr), 10);
            } catch (CothorityException e) {
                fail("should accept this size");
            }
        }
    }

    /**
     * Checks that you can request for the instance versions and that you can verify
     * that it has not been tempered.
     */
    @Test
    void getInstanceVersion() throws Exception {
        final int n = 5;

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));

        for (int i = 0; i < n-1; i++) {
            bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, counters.head()+1+i,10);
        }

        StateChange sc = bc.getInstanceVersion(bc.getGenesisDarcInstance().getInstance().getId(), 1);

        assertNotNull(sc);
        assertEquals(1, sc.getVersion());

        sc = bc.getLastInstanceVersion(bc.getGenesisDarcInstance().getInstance().getId());

        assertNotNull(sc);
        assertEquals(n-1, sc.getVersion());

        List<StateChange> scs;
        scs = bc.getAllInstanceVersion(bc.getGenesisDarcInstance().getInstance().getId());

        assertEquals(n, scs.size());
        assertEquals(n-1, scs.get(n-1).getVersion());
        assertEquals("darc", scs.get(0).getContractId());
        assertEquals(bc.getGenesisDarcInstance().getInstance().getId(), scs.get(0).getInstanceId());
        assertEquals(scs.get(0).getDarcBaseID(), scs.get(1).getDarcBaseID());

        boolean isValid = bc.checkStateChangeValidity(sc);
        assertTrue(isValid);
    }

    @Test
    void updateRoster() throws Exception {
        List<Signer> admins = new ArrayList<>();
        admins.add(admin);

        // Get the counter for the admin
        SignerCounters counters = bc.getSignerCounters(Collections.singletonList(admin.getIdentity().toString()));
        counters.increment();

        // First make sure we correctly refuse invalid new rosters.
        // Too few nodes
        final Roster newRoster1 = new Roster(testInstanceController.getIdentities().subList(0, 2));
        assertThrows(CothorityCommunicationException.class, () -> bc.setRoster(newRoster1, admins, counters.getCounters(), 10));

        // Too many new nodes
        List<ServerIdentity> newList = bc.getRoster().getNodes();
        newList.addAll(testInstanceController.getIdentities().subList(4, 6));
        final Roster newRoster2 = new Roster(newList);
        assertThrows(CothorityCommunicationException.class, () -> bc.setRoster(newRoster2, admins, counters.getCounters(), 10));

        // Too many changes
        newList.subList(0, 3).addAll(testInstanceController.getIdentities().subList(4, 6));
        logger.info(newList.toString());
        final Roster newRoster3 = new Roster(newList);
        assertThrows(CothorityCommunicationException.class, () -> bc.setRoster(newRoster3, admins, counters.getCounters(), 10));

        // And finally some real update of the roster
        // First start conode5, conode6, conode7 (these are sleeper conodes)
        try {
            testInstanceController.startConode(5);
            testInstanceController.startConode(6);
            testInstanceController.startConode(7);

            logger.info("updating real roster");
            Roster newRoster = new Roster(testInstanceController.getIdentities().subList(0, 5));

            bc.setRoster(newRoster, admins, counters.getCounters(), 10);
            counters.increment();
            newRoster = new Roster(testInstanceController.getIdentities().subList(0, 6));
            bc.setRoster(newRoster, admins, counters.getCounters(), 10);
            counters.increment();
            newRoster = new Roster(testInstanceController.getIdentities().subList(0, 7));
            bc.setRoster(newRoster, admins, counters.getCounters(), 10);
            counters.increment();

            // Need to send in at least two blocks before the new node is active
            bc.setMaxBlockSize(1000 * 1000, admins, counters.getCounters(), 20);
            counters.increment();
            bc.setMaxBlockSize(1000 * 1000, admins, counters.getCounters(), 20);
            counters.increment();

            List<SkipBlock> updates = bc.getSkipchain().getUpdateChain();
            int latest = updates.get(updates.size() - 1).getIndex();
            logger.info("shutting down two nodes and it should still run");
            try {
                // here we kill only the 4th conode to avoid killing a subleader because we use a
                // small interval in the tests
                testInstanceController.killConode(4);
                bc.setMaxBlockSize(1000 * 1000, admins, counters.getCounters(), 12);
                counters.increment();
            } finally {
                // Start node again
                logger.info("Starting conodes to make sure everything's OK for next tests");
                testInstanceController.startConode(4);
            }

            assertEquals(7, bc.getRoster().getNodes().size());

            // Check that we can update to the latest block using the skipchain API after roster change.
            updates = bc.getSkipchain().getUpdateChain();
            assertEquals(1, updates.get(updates.size() - 1).getIndex() - latest);

        } finally {
            logger.info("stopping conode for next tests");
            testInstanceController.killConode(5);
            testInstanceController.killConode(6);
            testInstanceController.killConode(7);
        }
    }

    @Test
    void getByzCoinIDs() throws Exception {
        List<SkipblockId> ids = ByzCoinRPC.getAllByzCoinIDs(bc.getRoster());
        // The number of ids is unknown because the tests creates a lot of byzcoins,
        // so we check that it's more than 0 and the one we know about is in it.
        assertTrue(ids.size() > 0);
        assertTrue(ids.contains(bc.getSkipchain().getID()));
    }
}
