import * as u8a from 'uint8arrays'
import multicodec from 'multicodec'
import  multibase from'multibase'

/**
 * Constructs the document based on the method key
 */
export function keyToDidDoc (pubKeyBytes: Uint8Array, fingerprint: string): any {
  const did = `did:key:${fingerprint}`
  const keyId = `${did}#${fingerprint}`
  const key = fingerprintToXY(fingerprint);
  return {
    id: did,
    verificationMethod: [{
      id: keyId,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwK: {
               kty: "EC",
	       crv: "P-256",
	       x: key.xm,
	       y: key.ym,
      }, 
    }],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    capabilityInvocation: [keyId],
  }
  }

function fingerprintToHex(fingerprint) {
 const buf = multibase.decode(fingerprint)
 const bufnoPrefix = multicodec.rmPrefix(buf)
 const bbf = u8a.toString(bufnoPrefix,'base16')
 return bbf;
}

function publicKeyToXY(publicKeyHex) {
 const xHex = publicKeyHex.slice(0,publicKeyHex.length/2);
 const yHex = publicKeyHex.slice(publicKeyHex.length/2,publicKeyHex.length);
 const xOctet = u8a.fromString(xHex,'base16');
 const yOctet = u8a.fromString(yHex,'base16');
 const xm = u8a.toString(multibase.encode('base64url',xOctet));
 const ym = u8a.toString(multibase.encode('base64url',yOctet));
 return { xm, ym };
}

function fingerprintToXY(fingerprint) {
 const publicKeyHex = fingerprintToHex(fingerprint);
 const XYpairObject = publicKeyToXY(publicKeyHex);
 return XYpairObject;
}
