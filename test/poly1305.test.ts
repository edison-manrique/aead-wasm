/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  poly1305.test.ts — Test de CORRECTITUD de Poly1305 (solo validación)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Verifica que la implementación WASM de Poly1305 produce exactamente los
 * tags (MAC de 16 bytes) esperados por los vectores oficiales de test
 * (`test/vectors/vectors_poly1305.ts`), cuyos campos `key` / `data` / `mac`
 * están codificados en HEXADECIMAL.
 *
 * Estrategia:
 *  1. `beforeAll` carga el binario WASM UNA sola vez (singleton AeadWasm).
 *  2. Un BUCLE recorre `poly1305_vectors` y genera un `test` por vector,
 *     decodificando key/data/mac de hex y comparando `bytesToHex(Poly1305.mac)`
 *     con el mac esperado. Así cada vector aparece por separado en el reporte
 *     (fácil de depurar si uno falla).
 *  3. Dos propiedades de correctitud refuerzan la validación sin depender de
 *     vectores: determinismo (mismo input → mismo tag) y sensibilidad
 *     (cambiar 1 bit del mensaje cambia el tag).
 *
 * Corre con:  bun test test/poly1305.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import { AeadWasm, Poly1305, hexToBytes, bytesToHex } from "../src"
import { poly1305_vectors } from "./vectors/vectors_poly1305"

describe("Poly1305 — correctitud (test vectors)", () => {
  // ── Carga del WASM (una sola vez para toda la suite) ──────────────────────
  beforeAll(async () => {
    // Ajusta el nombre/ruta si tu build emite el binario en otro sitio.
    const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
    const wasmBuffer = readFileSync(wasmPath)
    await AeadWasm.fromBuffer(wasmBuffer)
  })

  test("WASM cargado y Poly1305 accesible", () => {
    expect(AeadWasm.getInstance()).toBeDefined()
    expect(Poly1305.tagLength).toBe(16)
  })

  // ── BUCLE DE VECTORES: un test por cada entrada oficial ───────────────────
  // Decodifica key/data/mac de hex y comprueba que el tag calculado coincide
  // byte a byte con el esperado. La comparación en hex minúsculo es exacta.
  for (let i = 0; i < poly1305_vectors.length; i++) {
    const v = poly1305_vectors[i]
    const label = `vector #${i + 1}  (mac ${v.mac.slice(0, 12)}… · data ${v.data.length >> 1} B)`

    test(label, () => {
      const key = hexToBytes(v.key)
      const data = hexToBytes(v.data)
      const expected = v.mac.toLowerCase()

      // Longitud de la clave: los vectores oficiales usan 32 bytes.
      expect(key.length).toBe(32)

      const tag = Poly1305.mac(key, data)

      // El tag SIEMPRE son 16 bytes.
      expect(tag.length).toBe(16)
      // Coincidencia exacta con el vector oficial.
      expect(bytesToHex(tag)).toBe(expected)
    })
  }

  // ── Propiedades de correctitud (independientes de vectores) ───────────────

  test("determinismo: mismo (key, data) → mismo tag", () => {
    const v = poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const data = hexToBytes(v.data)
    expect(bytesToHex(Poly1305.mac(key, data))).toBe(bytesToHex(Poly1305.mac(key, data)))
  })

  test("sensibilidad: 1 bit flip en el mensaje cambia el tag", () => {
    const v = poly1305_vectors[0]
    const key = hexToBytes(v.key)
    const data = hexToBytes(v.data)
    if (data.length === 0) return // nada que mutar en un mensaje vacío

    const original = bytesToHex(Poly1305.mac(key, data))
    const mutated = new Uint8Array(data)
    mutated[0] ^= 0x01 // flip de 1 bit
    const after = bytesToHex(Poly1305.mac(key, mutated))

    expect(after).not.toBe(original)
  })

  test("fail-fast: clave de longitud inválida lanza", () => {
    const badKey = new Uint8Array(31) // ≠ 32
    expect(() => Poly1305.mac(badKey, new Uint8Array(8))).toThrow()
  })
})