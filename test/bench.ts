/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bench.ts — Benchmark de RENDIMIENTO de aead-wasm (sin aserciones)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A diferencia de memory.test.ts (que es un TEST: aserciona WASM Δ 0 B y heap
 * estable con un solo tamaño), este es un BENCHMARK: mide throughput real
 * (ops/s y MB/s) en varios tamaños de mensaje e imprime tablas. NO tiene
 * `expect`; se ejecuta como script.
 *
 * Mide, por cada tamaño (64 B / 1 KB / 16 KB / 256 KB):
 *   • Poly1305.mac
 *   • ChaCha20.encrypt / XChaCha20.encrypt
 *   • ChaCha20-Poly1305.encrypt / .decrypt
 *   • XChaCha20-Poly1305.encrypt / .decrypt
 * Más dos secciones extra:
 *   • STREAMING (archivos): AEAD encrypt a 1 MB y 4 MB (MB/s).
 *   • vs node:crypto: ChaCha20-Poly1305.encrypt contra el chacha20-poly1305
 *     nativo de Node (speedup).
 *
 * Metodología: warmup (~25 % del tiempo, mín. 5 iters) + medida a tiempo fijo
 * por tamaño (1000/700/500 ms). Se mide el camino PÚBLICO completo, incluida
 * la copia de salida del wrapper (coste real que paga el usuario). Los buffers
 * de ENTRADA se pre-asignan una vez por tamaño (no se mide su alloc); el de
 * salida lo crea el wrapper cada iter (inevitable, y es parte del coste real).
 *
 * Corre con:  bun test/bench.ts     (o añade "bench": "bun test/bench.ts")
 *             NO se ejecuta con `bun test` (no coincide con *.test.ts).
 */
import { readFileSync, statSync } from "node:fs"
import path from "node:path"
import { createCipheriv } from "node:crypto"
import {
  AeadWasm,
  Poly1305,
  ChaCha20,
  XChaCha20,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  hexToBytes
} from "../src"

// ── Constantes de prueba (pre-asignadas, reusadas) ──────────────────────────
const KEY = hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
const NONCE12 = hexToBytes("070000004041424344454647")
const NONCE24 = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657")
const AAD = hexToBytes("50515253c0c1c2c3c4c5c6c7")

// Tamaños de la tabla one-shot (todos caben en el one-shot de cada operación).
const SIZES: Array<{ label: string; n: number }> = [
  { label: "64 B", n: 64 },
  { label: "1 KB", n: 1024 },
  { label: "16 KB", n: 16384 },
  { label: "256 KB", n: 262144 }
]
// Tamaños de la sección streaming (fuerzan el path de chunks internos del AEAD).
const STREAM_SIZES: Array<{ label: string; n: number }> = [
  { label: "1 MB", n: 1 << 20 },
  { label: "4 MB", n: 4 << 20 }
]

// Buffers de ENTRADA pre-asignados por tamaño (no se mide su alloc).
const bufs = new Map<number, Uint8Array>()
function buf(n: number): Uint8Array {
  let b = bufs.get(n)
  if (!b) {
    b = new Uint8Array(n)
    b.fill(0x42)
    bufs.set(n, b)
  }
  return b
}

// ── Motor de medición ───────────────────────────────────────────────────────

/** Tiempo de medida (ms) según el tamaño: menos iters cuanto más grande. */
function msFor(n: number): number {
  return n <= 1024 ? 1000 : n <= 16384 ? 700 : 500
}

/** Warmup + medida a tiempo fijo. Devuelve ops/s y MB/s (throughput de datos). */
function measure(fn: () => unknown, bytesPerOp: number, ms: number): { ops: number; mbps: number } {
  // Warmup: JIT caliente, caches llenos (mín. 5 iters o ~25 % del tiempo).
  const wEnd = performance.now() + Math.min(ms * 0.25, 250)
  let wi = 0
  while (performance.now() < wEnd || wi < 5) {
    fn()
    wi++
  }
  // Medida: cuenta iteraciones hasta agotar el tiempo.
  let iters = 0
  const t0 = performance.now()
  const mEnd = t0 + ms
  while (performance.now() < mEnd) {
    fn()
    iters++
  }
  const secs = (performance.now() - t0) / 1000
  return { ops: iters / secs, mbps: (iters * bytesPerOp) / secs / 1e6 }
}

// ── Formato de tablas ───────────────────────────────────────────────────────

const fmt = (n: number): string => Math.round(n).toLocaleString("en-US")
const COL = { size: 8, ops: 13, mbps: 9, speed: 9 }

function header3(): string {
  return `${"Size".padEnd(COL.size)} ${"ops/s".padStart(COL.ops)} ${"MB/s".padStart(COL.mbps)}`
}
function row3(label: string, ops: number, mbps: number): string {
  return `${label.padEnd(COL.size)} ${fmt(ops).padStart(COL.ops)} ${mbps.toFixed(1).padStart(COL.mbps)}`
}
function header4(): string {
  return `${"Size".padEnd(COL.size)} ${"wasm ops/s".padStart(COL.ops)} ${"node ops/s".padStart(COL.ops)} ${"speedup".padStart(COL.speed)}`
}
function row4(label: string, wOps: number, nOps: number): string {
  const x = nOps > 0 ? (wOps / nOps).toFixed(2) + "x" : "n/a"
  return `${label.padEnd(COL.size)} ${fmt(wOps).padStart(COL.ops)} ${fmt(nOps).padStart(COL.ops)} ${x.padStart(COL.speed)}`
}
function section(title: string): void {
  console.log(`\n── ${title} ${"─".repeat(Math.max(2, 64 - title.length))}`)
}

// ── Casos WASM (one-shot) ───────────────────────────────────────────────────
// `run(n)` devuelve el closure a medir para un tamaño n; precomputa lo caro
// (p. ej. el combined del decrypt) UNA vez, fuera del loop.
interface BenchCase {
  name: string
  run: (n: number) => () => unknown
}
const CASES: BenchCase[] = [
  { name: "Poly1305 (mac)", run: (n) => () => Poly1305.mac(KEY, buf(n)) },
  { name: "ChaCha20 (encrypt)", run: (n) => () => ChaCha20.encrypt(KEY, NONCE12, buf(n)) },
  { name: "XChaCha20 (encrypt)", run: (n) => () => XChaCha20.encrypt(KEY, NONCE24, buf(n)) },
  { name: "ChaCha20-Poly1305 (encrypt)", run: (n) => () => ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(n), AAD) },
  {
    name: "ChaCha20-Poly1305 (decrypt)",
    run: (n) => {
      const c = ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(n), AAD)
      return () => ChaCha20Poly1305.decrypt(KEY, NONCE12, c, AAD)
    }
  },
  { name: "XChaCha20-Poly1305 (encrypt)", run: (n) => () => XChaCha20Poly1305.encrypt(KEY, NONCE24, buf(n), AAD) },
  {
    name: "XChaCha20-Poly1305 (decrypt)",
    run: (n) => {
      const c = XChaCha20Poly1305.encrypt(KEY, NONCE24, buf(n), AAD)
      return () => XChaCha20Poly1305.decrypt(KEY, NONCE24, c, AAD)
    }
  }
]

// ── node:crypto (chacha20-poly1305 nativo) para la comparativa ──────────────
function nodeChachaPolyEnc(n: number): () => unknown {
  const m = buf(n)
  return () => {
    const c = createCipheriv("chacha20-poly1305", KEY, NONCE12, { authTagLength: 16 })
    c.setAAD(AAD, { plaintextLength: m.length })
    c.update(m)
    c.final()
    c.getAuthTag()
  }
}
function nodeAvailable(): boolean {
  try {
    createCipheriv("chacha20-poly1305", KEY, NONCE12, { authTagLength: 16 })
    return true
  } catch {
    return false
  }
}

// ── main ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const wasmPath = path.join(import.meta.dir, "../dist/aead.wasm")
  await AeadWasm.fromBuffer(readFileSync(wasmPath))

  // Banner
  const runtime = (process.versions as Record<string, string>).bun
    ? `Bun ${(process.versions as Record<string, string>).bun}`
    : `Node ${process.version}`
  console.log("\n🔐 aead-wasm — benchmark de rendimiento")
  console.log(`   runtime  : ${runtime}`)
  console.log(`   binary   : ${(statSync(wasmPath).size / 1024).toFixed(1)} KB`)
  console.log(`   platform : ${process.platform} ${process.arch}`)
  console.log(`   (medida a tiempo fijo por tamaño; se mide el camino público completo)`)

  // 1) Tabla one-shot por operación
  section("One-shot (ops/s · MB/s de datos)")
  for (const c of CASES) {
    console.log(`\n  • ${c.name}`)
    console.log("    " + header3())
    for (const s of SIZES) {
      const r = measure(c.run(s.n), s.n, msFor(s.n))
      console.log("    " + row3(s.label, r.ops, r.mbps))
    }
  }

  // 2) Streaming de archivos (AEAD encrypt a 1–4 MB)
  section("Streaming de archivos — AEAD encrypt (MB/s)")
  const streamCases: BenchCase[] = [
    { name: "ChaCha20-Poly1305", run: (n) => () => ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(n), AAD) },
    { name: "XChaCha20-Poly1305", run: (n) => () => XChaCha20Poly1305.encrypt(KEY, NONCE24, buf(n), AAD) }
  ]
  for (const c of streamCases) {
    console.log(`\n  • ${c.name}`)
    console.log("    " + header3())
    for (const s of STREAM_SIZES) {
      const r = measure(c.run(s.n), s.n, s.n >= 4 << 20 ? 400 : 500)
      console.log("    " + row3(s.label, r.ops, r.mbps))
    }
  }

  // 3) Comparativa vs node:crypto (chacha20-poly1305 nativo)
  if (nodeAvailable()) {
    section("vs node:crypto — ChaCha20-Poly1305 encrypt (speedup)")
    console.log("    " + header4())
    for (const s of SIZES) {
      const w = measure(() => ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(s.n), AAD), s.n, msFor(s.n))
      const n = measure(nodeChachaPolyEnc(s.n), s.n, msFor(s.n))
      console.log("    " + row4(s.label, w.ops, n.ops))
    }
    console.log("    (node crea un objeto cipher por llamada; wasm reusa la arena estática)")
  } else {
    section("vs node:crypto — omitido (chacha20-poly1305 no disponible en este Node)")
  }

  console.log("\n✅ benchmark completado\n")
}

await main()