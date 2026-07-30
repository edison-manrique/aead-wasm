/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  chacha20.test.ts — Test de CORRECTITUD de ChaCha20 (solo validación)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Verifica el CORE de ChaCha20 contra los vectores de `vectors_chacha20.ts`
 * (campos `key` / `nonce` / `stream` en HEXADECIMAL).
 *
 * ── IMPORTANTE: dos variantes históricas del algoritmo ────────────────────
 * Los vectores de noble-js / del paper original de Bernstein usan un NONCE
 * DE 8 BYTES (variante "Bernstein": counter 64b + nonce 64b). Nuestra
 * implementación es la variante IETF / RFC 8439: NONCE DE 12 BYTES
 * (counter 32b + nonce 96b), que es la que exige ChaCha20-Poly1305.
 *
 * Como los vectores de keystream del paper usan COUNTER = 0, ambas variantes
 * coinciden si reinterpretamos el nonce de 8 bytes `N` como el nonce IETF de
 * 12 bytes `00000000 ‖ N` (4 ceros + N): el estado (x12..x15) queda idéntico.
 * Por eso `toIetfNonce()` prefija 4 ceros a los nonces de 8 B y deja los de
 * 12 B intactos. Esto valida el CORE sin añadir la variante deprecada de 8 B
 * al producto. (El layout IETF completo se valida luego con el AEAD §A.5.)
 *
 * Relación keystream ↔ cifrado:
 *   stream == ChaCha20.encrypt(key, nonceIetf, 0x00…00, counter = 0)
 * (cifrar ceros devuelve el keystream puro: 0 ⊕ ks == ks).
 *
 * Estrategia:
 *  1. `beforeAll` carga el WASM una sola vez (singleton AeadWasm).
 *  2. Un BUCLE recorre `chacha20_vectors` → un `test` por vector (reporte
 *     granular; si uno falla, se ve exactamente cuál).
 *  3. Propiedades de correctitud con nonces IETF de 12 B (determinismo,
 *     involución, sensibilidad a key/nonce, counter, fail-fast).
 *
 * Corre con:  bun test test/chacha20.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import { AeadWasm, ChaCha20, hexToBytes, bytesToHex, KEY_BYTES, NONCE_BYTES } from "../src"
import { chacha20_vectors } from "./vectors/vectors_chacha20"

/**
 * Normaliza un nonce de vector a 12 bytes (formato IETF de nuestro núcleo).
 *  • 12 bytes → IETF nativo, se devuelve tal cual.
 *  •  8 bytes → Bernstein con counter=0: se prefijan 4 ceros (equivalencia de
 *               layouts; ver cabecera). Solo válido porque estos vectores usan
 *               counter = 0.
 *  • otro     → lanza (vector no soportado por este test).
 */
function toIetfNonce(nonce: Uint8Array): Uint8Array {
  if (nonce.length === NONCE_BYTES) return nonce // 12 → IETF
  if (nonce.length === 8) {
    const n = new Uint8Array(NONCE_BYTES) // 12 ceros
    n.set(nonce, 4) // últimos 8 bytes = nonce Bernstein
    return n
  }
  throw new Error(`toIetfNonce: nonce de ${nonce.length} bytes no soportado (esperados 8 o 12).`)
}

describe("ChaCha20 — correctitud (test vectors)", () => {
  // ── Carga del WASM (una sola vez para toda la suite) ──────────────────────
  beforeAll(async () => {
    // Ajusta el nombre/ruta si tu build emite el binario en otro sitio.
    const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
    const wasmBuffer = readFileSync(wasmPath)
    await AeadWasm.fromBuffer(wasmBuffer)
  })

  test("WASM cargado y ChaCha20 accesible", () => {
    expect(AeadWasm.getInstance()).toBeDefined()
  })

  // ── BUCLE DE VECTORES: un test por cada entrada oficial ───────────────────
  // Cifra `stream.length/2` ceros con (key, nonceIetf, counter=0) y comprueba
  // que el resultado coincide byte a byte con el keystream esperado (`stream`).
  for (let i = 0; i < chacha20_vectors.length; i++) {
    const v = chacha20_vectors[i]
    const streamBytes = v.stream.length >> 1 // hex → bytes
    const label = `vector #${i + 1}  (stream ${streamBytes} B · ${v.stream.slice(0, 12)}…)`

    test(label, () => {
      const key = hexToBytes(v.key)
      const nonceRaw = hexToBytes(v.nonce) // 8 B (Bernstein) o 12 B (IETF)
      const nonce = toIetfNonce(nonceRaw) // siempre 12 B para el núcleo
      const expected = v.stream.toLowerCase()

      expect(key.length).toBe(KEY_BYTES) // 32
      expect(nonce.length).toBe(NONCE_BYTES) // 12 (tras normalizar)

      // Cifrar ceros con counter 0 == keystream puro.
      const zeros = new Uint8Array(streamBytes)
      const out = ChaCha20.encrypt(key, nonce, zeros, 0)

      expect(out.length).toBe(streamBytes) // longitud preservada
      expect(bytesToHex(out)).toBe(expected) // coincidencia exacta
    })
  }

  // ── Propiedades de correctitud (nonces IETF de 12 B, sin depender del formato) ──

  test("determinismo: mismo (key, nonce, counter, data) → mismo stream", () => {
    const v = chacha20_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = toIetfNonce(hexToBytes(v.nonce))
    const zeros = new Uint8Array(v.stream.length >> 1)
    expect(bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 0))).toBe(bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 0)))
  })

  test("involución: cifrar el keystream con el mismo (key,nonce,counter) → ceros", () => {
    // encrypt(encrypt(0)) == 0 ⇒ confirma encrypt == decrypt (simetría del flujo).
    const v = chacha20_vectors[0]
    const key = hexToBytes(v.key)
    const nonce = toIetfNonce(hexToBytes(v.nonce))
    const stream = hexToBytes(v.stream)
    const back = ChaCha20.encrypt(key, nonce, stream, 0)
    expect(bytesToHex(back)).toBe(bytesToHex(new Uint8Array(stream.length)))
  })

  test("sensibilidad a la clave: 1 bit flip en key cambia el stream", () => {
    const key = hexToBytes(chacha20_vectors[0].key)
    const nonce = new Uint8Array(NONCE_BYTES) // 12 ceros
    const zeros = new Uint8Array(64)

    const original = bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 0))
    const mutatedKey = new Uint8Array(key)
    mutatedKey[0] ^= 0x01
    const after = bytesToHex(ChaCha20.encrypt(mutatedKey, nonce, zeros, 0))

    expect(after).not.toBe(original)
  })

  test("sensibilidad al nonce: 1 bit flip en nonce cambia el stream", () => {
    const key = hexToBytes(chacha20_vectors[0].key)
    const nonce = new Uint8Array(NONCE_BYTES) // 12 ceros
    const zeros = new Uint8Array(64)

    const original = bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 0))
    const mutatedNonce = new Uint8Array(nonce)
    mutatedNonce[0] ^= 0x01
    const after = bytesToHex(ChaCha20.encrypt(key, mutatedNonce, zeros, 0))

    expect(after).not.toBe(original)
  })

  test("el counter desplaza el keystream: counter 0 ≠ counter 1", () => {
    const key = hexToBytes(chacha20_vectors[0].key)
    const nonce = new Uint8Array(NONCE_BYTES)
    const zeros = new Uint8Array(64)
    expect(bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 0))).not.toBe(
      bytesToHex(ChaCha20.encrypt(key, nonce, zeros, 1))
    )
  })

  test("fail-fast: longitudes inválidas de key/nonce lanzan", () => {
    const key = hexToBytes(chacha20_vectors[0].key)
    const nonce = new Uint8Array(NONCE_BYTES)
    const data = new Uint8Array(16)
    expect(() => ChaCha20.encrypt(new Uint8Array(31), nonce, data)).toThrow() // key ≠ 32
    expect(() => ChaCha20.encrypt(key, new Uint8Array(11), data)).toThrow() // nonce ≠ 12
  })
})
