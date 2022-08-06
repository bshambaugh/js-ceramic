import * as u8a from 'uint8arrays';
import * as bigintModArith from './bigint-mod-arith.js';
import * as nist_weierstrass_common from './nist-weierstrass-common.js';
export function ECPointDecompress(comp) {
    if (!nist_weierstrass_common.testUint8Array(comp)) {
        throw new TypeError('input must be a Uint8Array');
    }
    const two = BigInt(2);
    const prime = (two ** 384n) - (two ** 128n) - (two ** 96n) + (two ** 32n) - 1n;
    const b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575n;
    const pIdent = (prime + 1n) / 4n;
    const signY = BigInt(comp[0] - 2);
    const x = comp.subarray(1);
    const xBig = BigInt(u8a.toString(x, 'base10'));
    const a = xBig ** 3n - xBig * 3n + b;
    let yBig = bigintModArith.modPow(a, pIdent, prime);
    if (yBig % 2n !== signY) {
        yBig = prime - yBig;
    }
    return {
        x: xBig,
        y: yBig
    };
}
//# sourceMappingURL=secp384r1.js.map