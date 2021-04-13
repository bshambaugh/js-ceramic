import varint from "varint"
import multibase from "multibase"
import * as mapper from "../secp256r1"

describe('Secp256r1 mapper', () => {

    it('successfully resolves the document from did', async () => {
        const id = "zruuPojWkzGPb8sVc42f2YxcTXKUTpAUbdrzVovaTBmGGNyK6cGFaA4Kp7SSLKecrxYz8Sc9d77Rss7rayYt1oFCaNJ"

        const multicodecPubKey = multibase.decode(id)
        varint.decode(multicodecPubKey) // decode is changing param multicodecPubKey as well
        const pubKeyBytes = multicodecPubKey.slice(varint.decode.bytes)
        const doc = await mapper.keyToDidDoc(pubKeyBytes, id)
        expect(doc).toMatchSnapshot()
    })

})

console.log(JSON.stringify({"test": {}}))
