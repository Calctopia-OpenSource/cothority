import { Log } from "../../src";
import ByzCoinRPC from "../../src/byzcoin/byzcoin-rpc";
import { PaginateRequest, PaginateResponse } from "../../src/byzcoin/proto/stream";
import { WebSocketConnection } from "../../src/network";
import { BLOCK_INTERVAL, ROSTER, SIGNER, startConodes } from "../support/conondes";

describe("Stream Tests", () => {
    const roster = ROSTER.slice(0, 4);
    let originalTimeout: number;

    beforeAll(async () => {
        await startConodes();
        originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 2000;
    });

    it("should send a PaginateRequest and receive a PaginateResponse", async (done) => {
        const darc = ByzCoinRPC.makeGenesisDarc([SIGNER], roster);
        const rpc = await ByzCoinRPC.newByzCoinRPC(roster, darc, BLOCK_INTERVAL);

        const conn = new WebSocketConnection(roster.list[0].getWebSocketAddress(), ByzCoinRPC.serviceName);

        const msg = new PaginateRequest({startid: rpc.genesisID, pagesize: 1, numpages: 1,  backward: false});

        conn.sendStream<PaginateResponse>(msg, PaginateResponse).subscribe({
            complete: () => {
                done();
            },
            error: (err: Error) => {
                fail("onError should not be called: " + err.message);
                done();
            },
            next: ([message, ws]) => {
                expect(message.blocks.length).toEqual(1);
                expect(message.blocks[0].hash).toEqual(rpc.genesisID);
                expect(message.backward).toBe(false);
                expect(message.errorcode.toString()).toEqual("0");
                expect(message.errortext.length).toEqual(0);
                expect(message.pagenumber.toString()).toEqual("0");
                ws.close(1000);
            },
        });
    });

    afterAll( () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });
});
