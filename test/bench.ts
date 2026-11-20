/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  bench.ts — Benchmark de RENDIMIENTO: Single-Thread vs Multithread
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Mide throughput real (ops/s y MB/s) para AMBAS compilaciones del módulo:
 *   1. Single-Thread (dist/aead.wasm)
 *   2. Multithread   (dist/aead.mt.wasm con SharedArrayBuffer + locks atómicos)
 *   3. Concurrencia con Worker Threads (N workers compartiendo WebAssembly.Memory)
 *   4. Comparativa vs node:crypto nativo
 *
 * Corre con:  npm run bench   (o: npx tsx test/bench.ts)
 */
import { readFileSync, statSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { createCipheriv } from "node:crypto"
import { fileURLToPath } from "node:url"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads"
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

const SIZES: Array<{ label: string; n: number }> = [
  { label: "64 B", n: 64 },
  { label: "1 KB", n: 1024 },
  { label: "16 KB", n: 16384 },
  { label: "256 KB", n: 262144 }
]

const STREAM_SIZES: Array<{ label: string; n: number }> = [
  { label: "1 MB", n: 1 << 20 },
  { label: "4 MB", n: 4 << 20 }
]

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

function msFor(n: number): number {
  return n <= 1024 ? 700 : n <= 16384 ? 500 : 400
}

function measure(fn: () => unknown, bytesPerOp: number, ms: number): { ops: number; mbps: number } {
  const wEnd = performance.now() + Math.min(ms * 0.25, 180)
  let wi = 0
  while (performance.now() < wEnd || wi < 5) {
    fn()
    wi++
  }
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

const fmt = (n: number): string => Math.round(n).toLocaleString("en-US")
const COL = { size: 8, ops: 13, mbps: 9, speed: 9 }

function header3(): string {
  return `${"Size".padEnd(COL.size)} ${"ops/s".padStart(COL.ops)} ${"MB/s".padStart(COL.mbps)}`
}
function row3(label: string, ops: number, mbps: number): string {
  return `${label.padEnd(COL.size)} ${fmt(ops).padStart(COL.ops)} ${mbps.toFixed(1).padStart(COL.mbps)}`
}
function headerCompare(): string {
  return `${"Size".padEnd(COL.size)} ${"ST ops/s".padStart(COL.ops)} ${"MT ops/s".padStart(COL.ops)} ${"ST MB/s".padStart(COL.mbps)} ${"MT MB/s".padStart(COL.mbps)}`
}
function rowCompare(label: string, stOps: number, mtOps: number, stMbps: number, mtMbps: number): string {
  return `${label.padEnd(COL.size)} ${fmt(stOps).padStart(COL.ops)} ${fmt(mtOps).padStart(COL.ops)} ${stMbps.toFixed(1).padStart(COL.mbps)} ${mtMbps.toFixed(1).padStart(COL.mbps)}`
}
function header4(): string {
  return `${"Size".padEnd(COL.size)} ${"wasm ops/s".padStart(COL.ops)} ${"node ops/s".padStart(COL.ops)} ${"speedup".padStart(COL.speed)}`
}
function row4(label: string, wOps: number, nOps: number): string {
  const x = nOps > 0 ? (wOps / nOps).toFixed(2) + "x" : "n/a"
  return `${label.padEnd(COL.size)} ${fmt(wOps).padStart(COL.ops)} ${fmt(nOps).padStart(COL.ops)} ${x.padStart(COL.speed)}`
}
function section(title: string): void {
  console.log(`\n── ${title} ${"─".repeat(Math.max(2, 68 - title.length))}`)
}

interface BenchCase {
  name: string
  run: (n: number) => () => unknown
}

function buildCases(): BenchCase[] {
  return [
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
}

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

interface WorkerBenchJob {
  wasmModule: WebAssembly.Module
  sharedMemory: WebAssembly.Memory
  caseName: string
  payloadSize: number
  durationMs: number
}

function runWorkerOp(caseName: string, payload: Uint8Array, ct?: Uint8Array): void {
  switch (caseName) {
    case "Poly1305 (mac)":
      Poly1305.mac(KEY, payload)
      break
    case "ChaCha20 (encrypt)":
      ChaCha20.encrypt(KEY, NONCE12, payload)
      break
    case "XChaCha20 (encrypt)":
      XChaCha20.encrypt(KEY, NONCE24, payload)
      break
    case "ChaCha20-Poly1305 (encrypt)":
      ChaCha20Poly1305.encrypt(KEY, NONCE12, payload, AAD)
      break
    case "ChaCha20-Poly1305 (decrypt)":
      ChaCha20Poly1305.decrypt(KEY, NONCE12, ct!, AAD)
      break
    case "XChaCha20-Poly1305 (encrypt)":
      XChaCha20Poly1305.encrypt(KEY, NONCE24, payload, AAD)
      break
    case "XChaCha20-Poly1305 (decrypt)":
      XChaCha20Poly1305.decrypt(KEY, NONCE24, ct!, AAD)
      break
  }
}

async function benchWorkersShared(
  wasmModule: WebAssembly.Module,
  sharedMemory: WebAssembly.Memory,
  workerCount: number,
  caseName: string,
  payloadSize: number,
  durationMs: number
): Promise<{ ops: number; mbps: number }> {
  const promises = Array.from({ length: workerCount }, () => {
    return new Promise<{ iters: number; elapsedMs: number }>((resolve, reject) => {
      const w = new Worker(fileURLToPath(import.meta.url), {
        workerData: {
          wasmModule,
          sharedMemory,
          caseName,
          payloadSize,
          durationMs
        } satisfies WorkerBenchJob
      })
      w.on("error", reject)
      w.on("message", async (msg: { iters: number; elapsedMs: number }) => {
        await w.terminate()
        resolve(msg)
      })
    })
  })
  const results = await Promise.all(promises)
  const totalIters = results.reduce((acc, r) => acc + r.iters, 0)
  const wallSecs = Math.max(...results.map((r) => r.elapsedMs)) / 1000
  return {
    ops: totalIters / wallSecs,
    mbps: (totalIters * payloadSize) / wallSecs / 1e6
  }
}

if (!isMainThread) {
  const job = workerData as WorkerBenchJob
  await AeadWasm.fromModule(job.wasmModule, { env: { memory: job.sharedMemory } })
  const payload = buf(job.payloadSize)
  let ct: Uint8Array | undefined
  if (job.caseName === "ChaCha20-Poly1305 (decrypt)") {
    ct = ChaCha20Poly1305.encrypt(KEY, NONCE12, payload, AAD)
  } else if (job.caseName === "XChaCha20-Poly1305 (decrypt)") {
    ct = XChaCha20Poly1305.encrypt(KEY, NONCE24, payload, AAD)
  }

  // Warmup corto
  for (let i = 0; i < 20; i++) runWorkerOp(job.caseName, payload, ct)

  let iters = 0
  const t0 = performance.now()
  const end = t0 + job.durationMs
  while (performance.now() < end) {
    runWorkerOp(job.caseName, payload, ct)
    iters++
  }
  const elapsedMs = performance.now() - t0
  parentPort!.postMessage({ iters, elapsedMs })
} else {
  const __dirname = path.dirname(fileURLToPath(import.meta.url))
  const stPath = path.resolve(__dirname, "../dist/aead.wasm")
  const mtPath = path.resolve(__dirname, "../dist/aead.mt.wasm")

  const runtime = (process.versions as Record<string, string>).bun
    ? `Bun ${(process.versions as Record<string, string>).bun}`
    : `Node ${process.version}`
  const workerCount = Math.min(4, Math.max(2, os.cpus().length))

  console.log("\n🔐 aead-wasm — Benchmark Single-Thread vs Multithread")
  console.log(`   runtime    : ${runtime}`)
  console.log(`   platform   : ${process.platform} ${process.arch} (${os.cpus().length} vCPUs)`)
  console.log(`   ST binary  : ${(statSync(stPath).size / 1024).toFixed(1)} KB (dist/aead.wasm)`)
  console.log(`   MT binary  : ${(statSync(mtPath).size / 1024).toFixed(1)} KB (dist/aead.mt.wasm)`)

  const cases = buildCases()
  const stOneShot = new Map<string, Map<string, { ops: number; mbps: number }>>()
  const mtOneShot = new Map<string, Map<string, { ops: number; mbps: number }>>()

  // ── 1) Single-Thread (dist/aead.wasm) ────────────────────────────────────
  await AeadWasm.fromBuffer(readFileSync(stPath))
  for (const c of cases) {
    const map = new Map<string, { ops: number; mbps: number }>()
    for (const s of SIZES) {
      map.set(s.label, measure(c.run(s.n), s.n, msFor(s.n)))
    }
    stOneShot.set(c.name, map)
  }

  const streamCases: BenchCase[] = [
    { name: "ChaCha20-Poly1305", run: (n) => () => ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(n), AAD) },
    { name: "XChaCha20-Poly1305", run: (n) => () => XChaCha20Poly1305.encrypt(KEY, NONCE24, buf(n), AAD) }
  ]
  const stStream = new Map<string, Map<string, { ops: number; mbps: number }>>()
  for (const c of streamCases) {
    const map = new Map<string, { ops: number; mbps: number }>()
    for (const s of STREAM_SIZES) {
      map.set(s.label, measure(c.run(s.n), s.n, s.n >= 4 << 20 ? 350 : 450))
    }
    stStream.set(c.name, map)
  }

  // ── 2) Multithread (dist/aead.mt.wasm) ───────────────────────────────────
  const mtWasm = await AeadWasm.fromBuffer(readFileSync(mtPath))
  for (const c of cases) {
    const map = new Map<string, { ops: number; mbps: number }>()
    for (const s of SIZES) {
      map.set(s.label, measure(c.run(s.n), s.n, msFor(s.n)))
    }
    mtOneShot.set(c.name, map)
  }

  const mtStream = new Map<string, Map<string, { ops: number; mbps: number }>>()
  for (const c of streamCases) {
    const map = new Map<string, { ops: number; mbps: number }>()
    for (const s of STREAM_SIZES) {
      map.set(s.label, measure(c.run(s.n), s.n, s.n >= 4 << 20 ? 350 : 450))
    }
    mtStream.set(c.name, map)
  }

  // ── Imprimir comparativa One-Shot ST vs MT ───────────────────────────────
  section("One-shot: Single-Thread (ST) vs Multithread (MT, lock atómico)")
  for (const c of cases) {
    console.log(`\n  • ${c.name}`)
    console.log("    " + headerCompare())
    for (const s of SIZES) {
      const st = stOneShot.get(c.name)!.get(s.label)!
      const mt = mtOneShot.get(c.name)!.get(s.label)!
      console.log("    " + rowCompare(s.label, st.ops, mt.ops, st.mbps, mt.mbps))
    }
  }

  // ── Imprimir comparativa Streaming ST vs MT ──────────────────────────────
  section("Streaming de archivos — AEAD encrypt (1 MB y 4 MB)")
  for (const c of streamCases) {
    console.log(`\n  • ${c.name}`)
    console.log("    " + headerCompare())
    for (const s of STREAM_SIZES) {
      const st = stStream.get(c.name)!.get(s.label)!
      const mt = mtStream.get(c.name)!.get(s.label)!
      console.log("    " + rowCompare(s.label, st.ops, mt.ops, st.mbps, mt.mbps))
    }
  }

  // ── 3) Concurrencia MT con Worker Threads (memoria compartida) ───────────
  section(`MT Concurrente — ${workerCount} Worker Threads compartiendo SharedArrayBuffer`)
  const mtMod = mtWasm.getModule()!
  const mtMem = mtWasm.getMemory()
  console.log("\n  • Payload 16 KB (contención controlada por arena_lock)")
  console.log("    " + `${"Primitiva".padEnd(30)} ${"ops/s agreg.".padStart(13)} ${"MB/s agreg.".padStart(12)}`)
  for (const c of cases) {
    const r = await benchWorkersShared(mtMod, mtMem, workerCount, c.name, 16384, 600)
    console.log("    " + `${c.name.padEnd(30)} ${fmt(r.ops).padStart(13)} ${r.mbps.toFixed(1).padStart(12)}`)
  }

  // ── 4) Comparativa vs node:crypto ────────────────────────────────────────
  await AeadWasm.fromBuffer(readFileSync(stPath))
  if (nodeAvailable()) {
    section("vs node:crypto — ChaCha20-Poly1305 encrypt (ST)")
    console.log("    " + header4())
    for (const s of SIZES) {
      const w = measure(() => ChaCha20Poly1305.encrypt(KEY, NONCE12, buf(s.n), AAD), s.n, msFor(s.n))
      const n = measure(nodeChachaPolyEnc(s.n), s.n, msFor(s.n))
      console.log("    " + row4(s.label, w.ops, n.ops))
    }
  }

  console.log("\n✅ benchmark completado\n")
}