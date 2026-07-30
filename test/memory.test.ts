/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  memory.test.ts — Estrés ZERO-ALLOC (heap JS + memoria lineal WASM)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Verifica que NINGUNA operación reserva memoria bajo carga, para los 5
 * elementos del paquete:
 *   1. Poly1305           (mac one-shot)
 *   2. ChaCha20           (encrypt one-shot)
 *   3. XChaCha20          (encrypt one-shot)
 *   4. ChaCha20-Poly1305  (encrypt + decrypt one-shot)
 *   5. XChaCha20-Poly1305 (encrypt + decrypt one-shot)
 *
 * Por elemento y por ronda (10K / 50K / 100K / 500K ops) se mide:
 *   • Heap JS      → process.memoryUsage().heapUsed (antes/después, con GC).
 *   • Memoria WASM → AeadWasm.getAllocator().getHeap().buffer.byteLength
 *                    (tamaño de la memoria lineal; si no crece = zero-alloc).
 *   • Throughput   → ops/s.
 *
 * Aserciones por ronda:
 *   • WASM Δ 0 B        → la memoria lineal NUNCA crece (arena bump + save/restore).
 *   • heap JS estable   → crecimiento < 10 MB (solo el Uint8Array de salida por op).
 *   • Integridad        → tras el estrés, un vector conocido sigue siendo correcto.
 *
 * ⚠️ IMPORTANTE (por qué los esperados se calculan en beforeAll):
 *   Las constantes PURAS (KEY, NONCE, MSG, ROUNDS…) pueden ir en el top-level
 *   porque no tocan el WASM. Pero los 5 vectores esperados SÍ llaman a la API
 *   del WASM (Poly1305.mac, ChaCha20.encrypt…), así que NO pueden calcularse al
 *   evaluar el archivo (ahí el WASM aún no está cargado y getInstance() lanza).
 *   Por eso se declaran vacíos aquí y se rellenan dentro de beforeAll, DESPUÉS
 *   de fromBuffer. Los tests anidados los ven por closure.
 *
 * Corre con:  bun test test/memory.test.ts
 */
import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import {
  AeadWasm,
  Poly1305,
  ChaCha20,
  XChaCha20,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  hexToBytes,
  bytesToHex
} from "../src"

// ── Utilidades de medición ──────────────────────────────────────────────────

/** Fuerza GC (si está disponible: bun --smol / node --expose-gc) y espera un poco. */
async function gc(): Promise<void> {
  if (typeof globalThis.gc === "function") globalThis.gc()
  await new Promise((r) => setTimeout(r, 30))
}

/** Tamaño actual de la memoria lineal del WASM (bytes). */
function wasmMemoryBytes(): number {
  return AeadWasm.getInstance().getAllocator().getHeap().buffer.byteLength
}

/** Heap JS usado (bytes). */
function jsHeapBytes(): number {
  return process.memoryUsage().heapUsed
}

/** Convierte bytes a MB con 2 decimales. */
function toMB(bytes: number): number {
  return bytes / (1024 * 1024)
}

// ── Datos de prueba PUROS (fijos, reusados; NO tocan el WASM → top-level OK) ─

const KEY = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
const NONCE12 = hexToBytes("070000004041424344454647")
const NONCE24 = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657")
const AAD = hexToBytes("50515253c0c1c2c3c4c5c6c7")
const MSG = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: sunscreen would be it.") // 64 B

// ── Vectores esperados (se calculan en beforeAll, NO aquí) ──────────────────
// Declarados vacíos; se rellenan tras cargar el WASM. Los tests los leen por closure.
let POLY_MAC_EXPECTED = ""
let CHACHA_CT_EXPECTED = ""
let XCHACHA_CT_EXPECTED = ""
let AEAD_CT_EXPECTED = ""
let XAEAD_CT_EXPECTED = ""

// Rondas de estrés (ops por ronda)
const ROUNDS = [10_000, 50_000, 100_000, 500_000]

// Umbral de crecimiento aceptable del heap JS por ronda (MB)
const HEAP_DELTA_LIMIT_MB = 10

describe("aead-wasm — Estrés zero-alloc (heap JS + memoria WASM)", () => {
  beforeAll(async () => {
    // 1) Cargar el WASM primero (sin esto, cualquier llamada a la API lanza).
    const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
    await AeadWasm.fromBuffer(readFileSync(wasmPath))

    // 2) AHORA sí: calcular los esperados una sola vez (el WASM ya está listo).
    POLY_MAC_EXPECTED = bytesToHex(Poly1305.mac(KEY, MSG))
    CHACHA_CT_EXPECTED = bytesToHex(ChaCha20.encrypt(KEY, NONCE12, MSG))
    XCHACHA_CT_EXPECTED = bytesToHex(XChaCha20.encrypt(KEY, NONCE24, MSG))
    AEAD_CT_EXPECTED = bytesToHex(ChaCha20Poly1305.encrypt(KEY, NONCE12, MSG, AAD))
    XAEAD_CT_EXPECTED = bytesToHex(XChaCha20Poly1305.encrypt(KEY, NONCE24, MSG, AAD))
  })

  test("WASM cargado", () => {
    expect(AeadWasm.getInstance()).toBeDefined()
  })

  // ── 1. Poly1305 ───────────────────────────────────────────────────────────
  describe("Poly1305 (mac)", () => {
    test("sanity check (vector antes del estrés)", () => {
      expect(bytesToHex(Poly1305.mac(KEY, MSG))).toBe(POLY_MAC_EXPECTED)
    })

    for (const count of ROUNDS) {
      test(`ronda ${count.toLocaleString()} ops`, async () => {
        await gc()
        const wasmBefore = wasmMemoryBytes()
        const heapBefore = jsHeapBytes()
        const t0 = performance.now()

        for (let i = 0; i < count; i++) Poly1305.mac(KEY, MSG)

        const elapsed = performance.now() - t0
        await gc()
        const wasmDelta = wasmMemoryBytes() - wasmBefore
        const heapDeltaMB = toMB(jsHeapBytes() - heapBefore)
        const opsPerSec = Math.round((count / elapsed) * 1000).toLocaleString()

        console.log(
          `    Poly1305 ${count.toLocaleString()} ops en ${elapsed.toFixed(0)} ms ` +
            `(${opsPerSec} ops/s) · heap Δ ${heapDeltaMB.toFixed(2)} MB · WASM Δ ${wasmDelta} B`
        )

        expect(wasmDelta).toBe(0) // zero-alloc: la memoria lineal no crece
        expect(heapDeltaMB).toBeLessThan(HEAP_DELTA_LIMIT_MB)
        expect(bytesToHex(Poly1305.mac(KEY, MSG))).toBe(POLY_MAC_EXPECTED) // integridad
      }, 30_000)
    }
  })

  // ── 2. ChaCha20 ───────────────────────────────────────────────────────────
  describe("ChaCha20 (encrypt)", () => {
    test("sanity check (vector antes del estrés)", () => {
      expect(bytesToHex(ChaCha20.encrypt(KEY, NONCE12, MSG))).toBe(CHACHA_CT_EXPECTED)
    })

    for (const count of ROUNDS) {
      test(`ronda ${count.toLocaleString()} ops`, async () => {
        await gc()
        const wasmBefore = wasmMemoryBytes()
        const heapBefore = jsHeapBytes()
        const t0 = performance.now()

        for (let i = 0; i < count; i++) ChaCha20.encrypt(KEY, NONCE12, MSG)

        const elapsed = performance.now() - t0
        await gc()
        const wasmDelta = wasmMemoryBytes() - wasmBefore
        const heapDeltaMB = toMB(jsHeapBytes() - heapBefore)
        const opsPerSec = Math.round((count / elapsed) * 1000).toLocaleString()

        console.log(
          `    ChaCha20 ${count.toLocaleString()} ops en ${elapsed.toFixed(0)} ms ` +
            `(${opsPerSec} ops/s) · heap Δ ${heapDeltaMB.toFixed(2)} MB · WASM Δ ${wasmDelta} B`
        )

        expect(wasmDelta).toBe(0)
        expect(heapDeltaMB).toBeLessThan(HEAP_DELTA_LIMIT_MB)
        expect(bytesToHex(ChaCha20.encrypt(KEY, NONCE12, MSG))).toBe(CHACHA_CT_EXPECTED)
      }, 30_000)
    }
  })

  // ── 3. XChaCha20 ──────────────────────────────────────────────────────────
  describe("XChaCha20 (encrypt)", () => {
    test("sanity check (vector antes del estrés)", () => {
      expect(bytesToHex(XChaCha20.encrypt(KEY, NONCE24, MSG))).toBe(XCHACHA_CT_EXPECTED)
    })

    for (const count of ROUNDS) {
      test(`ronda ${count.toLocaleString()} ops`, async () => {
        await gc()
        const wasmBefore = wasmMemoryBytes()
        const heapBefore = jsHeapBytes()
        const t0 = performance.now()

        for (let i = 0; i < count; i++) XChaCha20.encrypt(KEY, NONCE24, MSG)

        const elapsed = performance.now() - t0
        await gc()
        const wasmDelta = wasmMemoryBytes() - wasmBefore
        const heapDeltaMB = toMB(jsHeapBytes() - heapBefore)
        const opsPerSec = Math.round((count / elapsed) * 1000).toLocaleString()

        console.log(
          `    XChaCha20 ${count.toLocaleString()} ops en ${elapsed.toFixed(0)} ms ` +
            `(${opsPerSec} ops/s) · heap Δ ${heapDeltaMB.toFixed(2)} MB · WASM Δ ${wasmDelta} B`
        )

        expect(wasmDelta).toBe(0)
        expect(heapDeltaMB).toBeLessThan(HEAP_DELTA_LIMIT_MB)
        expect(bytesToHex(XChaCha20.encrypt(KEY, NONCE24, MSG))).toBe(XCHACHA_CT_EXPECTED)
      }, 30_000)
    }
  })

  // ── 4. ChaCha20-Poly1305 ──────────────────────────────────────────────────
  describe("ChaCha20-Poly1305 (encrypt + decrypt)", () => {
    test("sanity check (vector antes del estrés)", () => {
      expect(bytesToHex(ChaCha20Poly1305.encrypt(KEY, NONCE12, MSG, AAD))).toBe(AEAD_CT_EXPECTED)
    })

    for (const count of ROUNDS) {
      test(`ronda ${count.toLocaleString()} ops`, async () => {
        await gc()
        const wasmBefore = wasmMemoryBytes()
        const heapBefore = jsHeapBytes()
        const t0 = performance.now()

        for (let i = 0; i < count; i++) {
          const ct = ChaCha20Poly1305.encrypt(KEY, NONCE12, MSG, AAD)
          ChaCha20Poly1305.decrypt(KEY, NONCE12, ct, AAD)
        }

        const elapsed = performance.now() - t0
        await gc()
        const wasmDelta = wasmMemoryBytes() - wasmBefore
        const heapDeltaMB = toMB(jsHeapBytes() - heapBefore)
        const opsPerSec = Math.round((count / elapsed) * 1000).toLocaleString()

        console.log(
          `    ChaCha20-Poly1305 ${count.toLocaleString()} ops en ${elapsed.toFixed(0)} ms ` +
            `(${opsPerSec} ops/s) · heap Δ ${heapDeltaMB.toFixed(2)} MB · WASM Δ ${wasmDelta} B`
        )

        expect(wasmDelta).toBe(0)
        expect(heapDeltaMB).toBeLessThan(HEAP_DELTA_LIMIT_MB)
        expect(bytesToHex(ChaCha20Poly1305.encrypt(KEY, NONCE12, MSG, AAD))).toBe(AEAD_CT_EXPECTED)
      }, 30_000)
    }
  })

  // ── 5. XChaCha20-Poly1305 ─────────────────────────────────────────────────
  describe("XChaCha20-Poly1305 (encrypt + decrypt)", () => {
    test("sanity check (vector antes del estrés)", () => {
      expect(bytesToHex(XChaCha20Poly1305.encrypt(KEY, NONCE24, MSG, AAD))).toBe(XAEAD_CT_EXPECTED)
    })

    for (const count of ROUNDS) {
      test(`ronda ${count.toLocaleString()} ops`, async () => {
        await gc()
        const wasmBefore = wasmMemoryBytes()
        const heapBefore = jsHeapBytes()
        const t0 = performance.now()

        for (let i = 0; i < count; i++) {
          const ct = XChaCha20Poly1305.encrypt(KEY, NONCE24, MSG, AAD)
          XChaCha20Poly1305.decrypt(KEY, NONCE24, ct, AAD)
        }

        const elapsed = performance.now() - t0
        await gc()
        const wasmDelta = wasmMemoryBytes() - wasmBefore
        const heapDeltaMB = toMB(jsHeapBytes() - heapBefore)
        const opsPerSec = Math.round((count / elapsed) * 1000).toLocaleString()

        console.log(
          `    XChaCha20-Poly1305 ${count.toLocaleString()} ops en ${elapsed.toFixed(0)} ms ` +
            `(${opsPerSec} ops/s) · heap Δ ${heapDeltaMB.toFixed(2)} MB · WASM Δ ${wasmDelta} B`
        )

        expect(wasmDelta).toBe(0)
        expect(heapDeltaMB).toBeLessThan(HEAP_DELTA_LIMIT_MB)
        expect(bytesToHex(XChaCha20Poly1305.encrypt(KEY, NONCE24, MSG, AAD))).toBe(XAEAD_CT_EXPECTED)
      }, 30_000)
    }
  })
})
