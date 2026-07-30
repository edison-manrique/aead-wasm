/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  xchacha20poly1305.test.ts — Correctitud de XChaCha20-Poly1305
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Valida el AEAD XChaCha20-Poly1305 (nonce extendido de 24 B) contra los
 * vectores de `test/vectors/vectors_xchacha20poly1305.ts` (campos en HEX):
 *   • key / nonce(24B) / aad / msg  → entradas (msg = plaintext)
 *   • result                        → salida esperada = ciphertext ‖ tag
 *
 * Misma estructura de validación que ChaCha20-Poly1305 (encrypt + decrypt +
 * tamper por vector, más detached / AAD-mismatch / streaming), pero con la
 * clase XChaCha20Poly1305 y nonce de 24 bytes (HChaCha20 internamente).
 *
 * Corre con:  bun test test/xchacha20poly1305.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import {
  AeadWasm,
  XChaCha20Poly1305,
  hexToBytes,
  bytesToHex,
  concatBytes,
  KEY_BYTES,
  XNONCE_BYTES,
  TAG_BYTES
} from "../src"
import { xchacha20poly1305_vectors } from "./vectors/vectors_xchacha20poly1305"

/** Parte `buf` en trozos de `n` bytes (el último puede ser menor). */
function chunksOf(buf: Uint8Array, n: number): Uint8Array[] {
  const out: Uint8Array[] = []
  for (let i = 0; i < buf.length; i += n) out.push(buf.subarray(i, Math.min(i + n, buf.length)))
  return out
}

describe("XChaCha20-Poly1305 — correctitud (test vectors)", () => {
  beforeAll(async () => {
    const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
    await AeadWasm.fromBuffer(readFileSync(wasmPath))
  })

  test("WASM cargado", () => {
    expect(AeadWasm.getInstance()).toBeDefined()
  })

  // ── BUCLE DE VECTORES: encrypt + decrypt + tamper por cada entrada ────────
  for (let i = 0; i < xchacha20poly1305_vectors.length; i++) {
    const v = xchacha20poly1305_vectors[i]
    const ptHex = v.msg.length ? v.msg : v.input
    const aadHex = v.aad
    let expHex = v.result
    if (!expHex.length) expHex = v.output + v.tag
    expHex = expHex.toLowerCase()
    if (!expHex.length) continue

    const ptBytes = ptHex.length >> 1
    const label = `vector #${i + 1}  (pt ${ptBytes} B · aad ${aadHex.length >> 1} B · ${expHex.slice(0, 12)}…)`

    test(label, () => {
      const key = hexToBytes(v.key)
      const nonce = hexToBytes(v.nonce)
      const aad = hexToBytes(aadHex)
      const pt = hexToBytes(ptHex)

      expect(key.length).toBe(KEY_BYTES) // 32
      expect(nonce.length).toBe(XNONCE_BYTES) // 24

      // 1) ENCRYPT
      const combined = XChaCha20Poly1305.encrypt(key, nonce, pt, aad)
      expect(combined.length).toBe(pt.length + TAG_BYTES)
      expect(bytesToHex(combined)).toBe(expHex)

      // 2) DECRYPT round-trip
      const dec = XChaCha20Poly1305.decrypt(key, nonce, combined, aad)
      expect(dec).not.toBeNull()
      expect(bytesToHex(dec as Uint8Array)).toBe(bytesToHex(pt))

      // 3) TAMPER
      const tampered = new Uint8Array(combined)
      tampered[0] ^= 0x01
      expect(XChaCha20Poly1305.decrypt(key, nonce, tampered, aad)).toBeNull()
    })
  }

  // ── Propiedades adicionales (sobre el vector #1) ──────────────────────────

  test("detached ≡ combined (encrypt + decrypt)", () => {
    const v = xchacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = hexToBytes(v.result)

    const { ciphertext, tag } = XChaCha20Poly1305.encryptDetached(key, nonce, pt, aad)
    expect(bytesToHex(concatBytes(ciphertext, tag))).toBe(bytesToHex(combined))

    const dec = XChaCha20Poly1305.decryptDetached(key, nonce, ciphertext, tag, aad)
    expect(dec).not.toBeNull()
    expect(bytesToHex(dec as Uint8Array)).toBe(bytesToHex(pt))
  })

  test("AAD mismatch → decrypt retorna null", () => {
    const v = xchacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = XChaCha20Poly1305.encrypt(key, nonce, pt, aad)

    const wrongAad = new Uint8Array(aad.length ? aad.length : 1)
    if (aad.length) wrongAad.set(aad)
    wrongAad[0] ^= 0x01
    expect(XChaCha20Poly1305.decrypt(key, nonce, combined, wrongAad)).toBeNull()
  })

  test("STREAMING encrypt por chunks ≡ one-shot", () => {
    const v = xchacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const expected = v.result.toLowerCase()

    const enc = XChaCha20Poly1305.createEncryptStream(key, nonce, aad)
    const parts: Uint8Array[] = []
    for (const chunk of chunksOf(pt, 7)) parts.push(enc.update(chunk))
    parts.push(enc.final())
    expect(bytesToHex(concatBytes(...parts))).toBe(expected)
  })

  test("STREAMING decrypt ok y con tag malo → false", () => {
    const v = xchacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const pt = hexToBytes(v.msg)
    const combined = hexToBytes(v.result)
    const ct = combined.subarray(0, combined.length - TAG_BYTES)
    const tag = combined.subarray(combined.length - TAG_BYTES)

    const dec = XChaCha20Poly1305.createDecryptStream(key, nonce, aad)
    const ptParts: Uint8Array[] = []
    for (const chunk of chunksOf(ct, 7)) ptParts.push(dec.update(chunk))
    expect(dec.final(tag)).toBe(true)
    expect(bytesToHex(concatBytes(...ptParts))).toBe(bytesToHex(pt))

    const dec2 = XChaCha20Poly1305.createDecryptStream(key, nonce, aad)
    for (const chunk of chunksOf(ct, 7)) dec2.update(chunk)
    const badTag = new Uint8Array(tag)
    badTag[0] ^= 0x01
    expect(dec2.final(badTag)).toBe(false)
  })

  test("fail-fast: longitudes inválidas lanzan", () => {
    const v = xchacha20poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const pt = new Uint8Array(8)
    expect(() => XChaCha20Poly1305.encrypt(new Uint8Array(31), nonce, pt)).toThrow() // key ≠ 32
    expect(() => XChaCha20Poly1305.encrypt(key, new Uint8Array(23), pt)).toThrow() // nonce ≠ 24
  })
})