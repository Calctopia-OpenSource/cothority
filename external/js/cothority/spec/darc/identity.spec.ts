import IdentityDarc from "../../src/darc/identity-darc";
import IdentityEd25519 from "../../src/darc/identity-ed25519";
import IdentityDid from "../../src/darc/identity-did";
import IdentityWrapper from "../../src/darc/identity-wrapper";
import { SIGNER } from "../support/conondes";

describe("Identity Tests", () => {
    it("should create a darc identity", () => {
        const id = new IdentityDarc({ id: Buffer.from("deadbeef", "hex") });

        expect(id.verify(Buffer.from([]), Buffer.from([]))).toBeFalsy();
        expect(IdentityWrapper.fromIdentity(id).darc).toBeDefined();
        expect(id.toBytes()).toEqual(Buffer.from("deadbeef", "hex"));
        expect(id.toString()).toBe("darc:deadbeef");
    });

    it("should create a ed25519 identity", () => {
        const id = new IdentityEd25519({ point: SIGNER.point });

        const msg = Buffer.from("deadbeef", "hex");
        const sig = SIGNER.sign(msg);
        expect(id.verify(msg, sig)).toBeTruthy();
        expect(IdentityWrapper.fromIdentity(id).ed25519).toBeDefined();
        expect(id.toBytes()).toEqual(SIGNER.point);
        expect(id.toString()).toBe(`ed25519:${SIGNER.public.toString()}`);
    });

    it("should create a did identity", () => {
        const id = new IdentityDid({ method: Buffer.from("sov"), did: Buffer.from("xxx") });
        expect(IdentityWrapper.fromIdentity(id).did).toBeDefined();
        expect(id.toString()).toBe("did:sov:xxx");
    });

    it("should return the string representation", () => {
        const id = new IdentityEd25519({ point: SIGNER.point });
        const wrapper = new IdentityWrapper({ ed25519: id });
        expect(id.toString()).toBe(wrapper.toString());

        const did = new IdentityDid({ method: Buffer.from("sov"), did: Buffer.from("xxx") });
        const wrapper2 = new IdentityWrapper({ did });
        expect(did.toString()).toBe(wrapper2.toString());
    });
});
