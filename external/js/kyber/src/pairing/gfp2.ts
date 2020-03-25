import BN from "bn.js";
import { p } from "./constants";
import GfP from "./gfp";

type BNType = Buffer | string | number | BN;

/**
 * Group field of size p^2
 * This object acts as an immutable and then any modification will instantiate
 * a new object.
 */
export default class GfP2 {

    static zero(): GfP2 {
        return GfP2.ZERO;
    }

    static one(): GfP2 {
        return GfP2.ONE;
    }
    private static ZERO = new GfP2(0, 0);
    private static ONE = new GfP2(0, 1);

    private x: GfP;
    private y: GfP;

    constructor(x: BNType | GfP, y: BNType | GfP) {
        this.x = x instanceof GfP ? x : new GfP(x || 0);
        this.y = y instanceof GfP ? y : new GfP(y || 0);
    }

    /**
     * Get the x value of this element
     * @returns the x element
     */
    getX(): GfP {
        return this.x;
    }

    /**
     * Get the y value of this element
     * @returns the y element
     */
    getY(): GfP {
        return this.y;
    }

    /**
     * Check if the value is zero
     * @returns true when zero, false otherwise
     */
    isZero(): boolean {
        return this.x.getValue().eqn(0) && this.y.getValue().eqn(0);
    }

    /**
     * Check if the value is one
     * @returns true when one, false otherwise
     */
    isOne(): boolean {
        return this.x.getValue().eqn(0) && this.y.getValue().eqn(1);
    }

    /**
     * Get the conjugate of the element
     * @return the conjugate
     */
    conjugate(): GfP2 {
        return new GfP2(this.x.negate(), this.y);
    }

    /**
     * Get the negative of the element
     * @returns the negative
     */
    negative(): GfP2 {
        return new GfP2(this.x.negate(), this.y.negate());
    }

    /**
     * Add a to the current element
     * @param a the other element to add
     * @returns the new element
     */
    add(a: GfP2): GfP2 {
        const x = this.x.add(a.x).mod(p);
        const y = this.y.add(a.y).mod(p);
        return new GfP2(x, y);
    }

    /**
     * Subtract a to the current element
     * @param a the other element to subtract
     * @returns the new element
     */
    sub(a: GfP2): GfP2 {
        const x = this.x.sub(a.x).mod(p);
        const y = this.y.sub(a.y).mod(p);
        return new GfP2(x, y);
    }

    /**
     * Multiply a to the current element
     * @param a the other element to multiply
     * @returns the new element
     */
    mul(a: GfP2): GfP2 {
        let tx = this.x.mul(a.y);
        let t = a.x.mul(this.y);
        tx = tx.add(t).mod(p);

        let ty = this.y.mul(a.y).mod(p);
        t = this.x.mul(a.x).mod(p);
        ty = ty.sub(t).mod(p);

        return new GfP2(tx, ty);
    }

    /**
     * Multiply the current element by the scalar k
     * @param k the scalar to multiply with
     * @returns the new element
     */
    mulScalar(k: GfP): GfP2 {
        const x = this.x.mul(k);
        const y = this.y.mul(k);

        return new GfP2(x, y);
    }

    /**
     * Set e=ξa where ξ=i+3 and return the new element
     * @returns the new element
     */
    mulXi(): GfP2 {
        let tx = this.x.add(this.x);
        tx = tx.add(this.x);
        tx = tx.add(this.y);

        let ty = this.y.add(this.y);
        ty = ty.add(this.y);
        ty = ty.sub(this.x);

        return new GfP2(tx, ty);
    }

    /**
     * Get the square value of the element
     * @returns the new element
     */
    square(): GfP2 {
        const t1 = this.y.sub(this.x);
        const t2 = this.x.add(this.y);

        const ty = t1.mul(t2).mod(p);
        // intermediate modulo is due to a missing implementation
        // in the library that is actually using the unsigned left
        // shift any time
        const tx = this.x.mul(this.y).mod(p).shiftLeft(1).mod(p);

        return new GfP2(tx, ty);
    }

    /**
     * Get the inverse of the element
     * @returns the new element
     */
    invert(): GfP2 {
        let t = this.y.mul(this.y);
        const t2 = this.x.mul(this.x);
        t = t.add(t2);

        const inv = t.invmod(p);
        const tx = this.x.negate().mul(inv).mod(p);
        const ty = this.y.mul(inv).mod(p);

        return new GfP2(tx, ty);
    }

    /**
     * Check the equality of the elements
     * @param o the object to compare
     * @returns true when both are equal, false otherwise
     */
    equals(o: any): o is GfP2 {
        return this.x.equals(o.x) && this.y.equals(o.y);
    }

    /**
     * Get the string representation of the element
     * @returns the string representation
     */
    toString(): string {
        return `(${this.x.toHex()},${this.y.toHex()})`;
    }
}

export const xiToPMinus1Over6 = new GfP2("8669379979083712429711189836753509758585994370025260553045152614783263110636",
    "19998038925833620163537568958541907098007303196759855091367510456613536016040");
export const xiToPMinus1Over3 =
    new GfP2("26098034838977895781559542626833399156321265654106457577426020397262786167059",
        "15931493369629630809226283458085260090334794394361662678240713231519278691715");
export const xiToPMinus1Over2 =
    new GfP2("50997318142241922852281555961173165965672272825141804376761836765206060036244",
        "38665955945962842195025998234511023902832543644254935982879660597356748036009");
export const xiToPSquaredMinus1Over3 = new BN("65000549695646603727810655408050771481677621702948236658134783353303381437752");
export const xiTo2PSquaredMinus2Over3 = new BN("4985783334309134261147736404674766913742361673560802634030");
export const xiToPSquaredMinus1Over6 = new BN("65000549695646603727810655408050771481677621702948236658134783353303381437753");
export const xiTo2PMinus2Over3 = new GfP2("19885131339612776214803633203834694332692106372356013117629940868870585019582",
    "21645619881471562101905880913352894726728173167203616652430647841922248593627");
