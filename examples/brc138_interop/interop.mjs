/**
 * BRC-138 cross-implementation interop driver (TypeScript side).
 *
 * Verifies proofs created by the Python implementation and creates proofs
 * the Python implementation verifies, using the reference @bsv/auth library
 * and @bsv/sdk ProtoWallet. This proves the Python module is byte-compatible
 * with the canonical TypeScript implementation.
 *
 * Usage:
 *   node interop.mjs verifyPy <vector.json>   # verify a Python-made proof
 *   node interop.mjs create <clientPrivHex> <serverPrivHex> <action> <payloadB64?>
 *
 * verifyPy input JSON: { clientPrivHex, serverPrivHex, action, proof, payloadB64? }
 * Output: JSON { valid, identityKey?, error? }
 */
import { PrivateKey, ProtoWallet } from '@bsv/sdk'
import { verifyAuthProof, createAuthProof } from '@bsv/auth'

const mode = process.argv[2]

function hexSig(sig) {
  // Accept byte array (Python wire form) or hex string; return hex.
  if (typeof sig === 'string') return sig
  if (Array.isArray(sig)) return Buffer.from(sig).toString('hex')
  throw new Error('unknown signature form')
}


if (mode === 'verifyPy') {
  const fs = await import('node:fs')
  const data = JSON.parse(fs.readFileSync(process.argv[3], "utf8"))
  const serverWallet = new ProtoWallet(PrivateKey.fromHex(data.serverPrivHex))
  const proof = {
    data: data.proof.data,
    signature: data.proof.signature // spec wire form: array of byte values
  }
  const consumeNonce = async () => true // single-use is exercised on the Python side
  const result = await verifyAuthProof({
    wallet: serverWallet,
    proof,
    action: data.action,
    consumeNonce,
    body: data.payloadB64 !== undefined ? Buffer.from(data.payloadB64, 'base64') : undefined
  })
  console.log(JSON.stringify(result))
} else if (mode === 'create') {
  const clientPrivHex = process.argv[3]
  const serverPrivHex = process.argv[4]
  const action = process.argv[5]
  const payloadB64 = process.argv[6] !== undefined ? process.argv[6] : undefined
  const clientWallet = new ProtoWallet(PrivateKey.fromHex(clientPrivHex))
  const serverPubHex = PrivateKey.fromHex(serverPrivHex).toPublicKey().toString()
  const body = payloadB64 !== undefined ? Buffer.from(payloadB64, 'base64') : undefined
  const proof = await createAuthProof({ wallet: clientWallet, counterparty: serverPubHex, action, body })
  console.log(JSON.stringify({ ...proof, identityKey: (await clientWallet.getPublicKey({ identityKey: true })).publicKey }))
} else {
  console.error('unknown mode')
  process.exit(1)
}
