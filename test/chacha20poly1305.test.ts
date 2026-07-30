/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  chacha20poly1305.test.ts — Correctitud de ChaCha20-Poly1305 (RFC 8439 §A.5)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Valida el AEAD ChaCha20-Poly1305 (nonce 12 B) contra los vectores oficiales
 * de `test/vectors/vectors_chacha20poly1305.ts` (campos en HEX):
 *   • key / nonce / aad / msg  → entradas (msg = plaintext)
 *   • result                   → salida esperada = ciphertext ‖ tag (combined)
 *
 * Por cada vector se comprueban TRES direcciones (cobertura máxima):
 *   1) ENCRYPT  : encrypt(key,nonce,msg,aad)        == result
 *   2) DECRYPT  : decrypt(key,nonce,result,aad)     == msg   (round-trip)
 *   3) TAMPER   : decrypt con 1 bit flip en result  == null  (autenticación)
 *
 * Fuera del bucle, propiedades adicionales con el vector #1:
 *   • detached ≡ combined  (encryptDetached/decryptDetached)
 *   • AAD mismatch → null  (autenticación de los datos asociados)
 *   • STREAMING encrypt por chunks ≡ one-shot
 *   • STREAMING decrypt ok  y  con tag malo → false
 *
 * Corre con:  bun test test/chacha20poly1305.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import {
  AeadWasm,
  ChaCha20Poly1305,
  hexToBytes,
  bytesToHex,
  concatBytes,
  KEY_BYTES,
  NONCE_BYTES,
  TAG_BYTES
} from "../src"
import { chacha20poly1305_vectors } from "./vectors/vectors_chacha20poly1305"

/** Parte `buf` en trozos de `n` bytes (el último puede ser menor). */
function chunksOf(buf: Uint8Array, n: number): Uint8Array[] {
  const out: Uint8Array[] = []
  for (let i = 0; i < buf.length; i += n) out.push(buf.subarray(i, Math.min(i + n, buf.length)))
  return out
}

describe("ChaCha20-Poly1305 — correctitud (test vectors)", () => {
  beforeAll(async () => {
    const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
    await AeadWasm.fromBuffer(readFileSync(wasmPath))
  })

  test("WASM cargado", () => {
    expect(AeadWasm.getInstance()).toBeDefined()
  })

  // ── BUCLE DE VECTORES: encrypt + decrypt + tamper por cada entrada ────────
  for (let i = 0; i < chacha20poly1305_vectors.length; i++) {
    const v = chacha20poly1305_vectors[i]
    const ptHex = v.msg.length ? v.msg : v.input // plaintext (msg por defecto)
    const aadHex = v.aad
    let expHex = v.result // combined esperado = ct ‖ tag
    if (!expHex.length) expHex = v.output + v.tag // fallback: ct y tag separados
    expHex = expHex.toLowerCase()
    if (!expHex.length) continue // vector sin salida esperada → no validable

    const ptBytes = ptHex.length >> 1
    const label = `vector #${i + 1}  (pt ${ptBytes} B · aad ${aadHex.length >> 1} B · ${expHex.slice(0, 12)}…)`

    test(label, () => {
      const key = hexToBytes(v.key)
      const nonce = hexToBytes(v.nonce)
      const aad = hexToBytes(aadHex)
      const pt = hexToBytes(ptHex)

      expect(key.length).toBe(KEY_BYTES) // 32
      expect(nonce.length).toBe(NONCE_BYTES) // 12

      // 1) ENCRYPT → debe coincidir con el combined oficial
      const combined = ChaCha20Poly1305.encrypt(key, nonce, pt, aad)
      expect(combined.length).toBe(pt.length + TAG_BYTES) // ct ‖ tag
      expect(bytesToHex(combined)).toBe(expHex)

      // 2) DECRYPT round-trip → debe devolver el plaintext original
      const dec = ChaCha20Poly1305.decrypt(key, nonce, combined, aad)
      expect(dec).not.toBeNull()
      expect(bytesToHex(dec as Uint8Array)).toBe(bytesToHex(pt))

      // 3) TAMPER → 1 bit flip en el combined debe invalidar el tag
      const tampered = new Uint8Array(combined)
      tampered[0] ^= 0x01
      expect(ChaCha20Poly1305.decrypt(key, nonce, tampered, aad)).toBeNull()
    })
  }

  // ── Propiedades adicionales (sobre el vector #1) ──────────────────────────

  test("detached ≡ combined (encrypt + decrypt)", () => {
    const v = chacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = hexToBytes(v.result)

    const { ciphertext, tag } = ChaCha20Poly1305.encryptDetached(key, nonce, pt, aad)
    expect(bytesToHex(concatBytes(ciphertext, tag))).toBe(bytesToHex(combined))

    const dec = ChaCha20Poly1305.decryptDetached(key, nonce, ciphertext, tag, aad)
    expect(dec).not.toBeNull()
    expect(bytesToHex(dec as Uint8Array)).toBe(bytesToHex(pt))
  })

  test("AAD mismatch → decrypt retorna null", () => {
    const v = chacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = ChaCha20Poly1305.encrypt(key, nonce, pt, aad)

    const wrongAad = new Uint8Array(aad.length ? aad.length : 1)
    if (aad.length) wrongAad.set(aad)
    wrongAad[0] ^= 0x01
    expect(ChaCha20Poly1305.decrypt(key, nonce, combined, wrongAad)).toBeNull()
  })

  test("STREAMING encrypt por chunks ≡ one-shot", () => {
    const v = chacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const expected = v.result.toLowerCase()

    const enc = ChaCha20Poly1305.createEncryptStream(key, nonce, aad)
    const parts: Uint8Array[] = []
    for (const chunk of chunksOf(pt, 7)) parts.push(enc.update(chunk))
    parts.push(enc.final()) // tag
    expect(bytesToHex(concatBytes(...parts))).toBe(expected)
  })

  test("STREAMING decrypt ok y con tag malo → false", () => {
    const v = chacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = hexToBytes(v.result)
    const ct = combined.subarray(0, combined.length - TAG_BYTES)
    const tag = combined.subarray(combined.length - TAG_BYTES)

    // Descifrado correcto por chunks
    const dec = ChaCha20Poly1305.createDecryptStream(key, nonce, aad)
    const ptParts: Uint8Array[] = []
    for (const chunk of chunksOf(ct, 7)) ptParts.push(dec.update(chunk))
    expect(dec.final(tag)).toBe(true)
    expect(bytesToHex(concatBytes(...ptParts))).toBe(bytesToHex(pt))

    // Tag alterado → final retorna false (plaintext debe descartarse)
    const dec2 = ChaCha20Poly1305.createDecryptStream(key, nonce, aad)
    for (const chunk of chunksOf(ct, 7)) dec2.update(chunk)
    const badTag = new Uint8Array(tag)
    badTag[0] ^= 0x01
    expect(dec2.final(badTag)).toBe(false)
  })

  test("fail-fast: longitudes inválidas lanzan", () => {
    const v = chacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const pt = new Uint8Array(8)
    expect(() => ChaCha20Poly1305.encrypt(new Uint8Array(31), nonce, pt)).toThrow() // key ≠ 32
    expect(() => ChaCha20Poly1305.encrypt(key, new Uint8Array(11), pt)).toThrow() // nonce ≠ 12
  })
})