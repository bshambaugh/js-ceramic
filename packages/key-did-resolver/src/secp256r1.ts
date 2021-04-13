import * as u8a from 'uint8arrays'
import multicodec from 'multicodec'
import  multibase from'multibase'

/**
 * Constructs the document based on the method key
 */
export function keyToDidDoc (pubKeyBytes: Uint8Array, fingerprint: string): any {
  const did = `did:key:${fingerprint}`
  const keyId = `${did}#${fingerprint}`
  const key = pubKeyBytesToXY(pubKeyBytes);
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

function pubKeyBytesToHex(pubKeyBytes: Uint8Array) {
 const bbf = u8a.toString(pubKeyBytes,'base16')
 return bbf;
}

function publicKeyToXY(publicKeyHex: string) {
 const xHex = publicKeyHex.slice(0,publicKeyHex.length/2);
 const yHex = publicKeyHex.slice(publicKeyHex.length/2,publicKeyHex.length);
 const xOctet = u8a.fromString(xHex,'base16');
 const yOctet = u8a.fromString(yHex,'base16');
 const xm = u8a.toString(multibase.encode('base64url',xOctet));
 const ym = u8a.toString(multibase.encode('base64url',yOctet));
 return { xm, ym };
}

function pubKeyBytesToXY(pubKeyBytes: Uint8Array) {
 const publicKeyHex = pubKeyBytesToHex(pubKeyBytes);
 const XYpairObject = publicKeyToXY(publicKeyHex);
 return XYpairObject;
}
