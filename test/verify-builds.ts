import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import path from "node:path"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads"
import { fileURLToPath } from "node:url"
import {
  AeadWasm,
  ChaCha20,
  XChaCha20,
  Poly1305,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  hexToBytes,
  bytesToHex,
  NONCE_BYTES,
  TAG_BYTES
} from "../src"
import { poly1305_vectors } from "./vectors/vectors_poly1305"
import { chacha20_vectors } from "./vectors/vectors_chacha20"
import { chacha20poly1305_vectors } from "./vectors/vectors_chacha20poly1305"
import { xchacha20poly1305_vectors } from "./vectors/vectors_xchacha20poly1305"

function toIetfNonce(nonce: Uint8Array): Uint8Array {
  if (nonce.length === NONCE_BYTES) return nonce
  const n = new Uint8Array(NONCE_BYTES)
  n.set(nonce, 4)
  return n
}

function runVectorSuite(label: string): void {
  // 1. Poly1305
  for (let i = 0; i < poly1305_vectors.length; i++) {
    const v = poly1305_vectors[i]
    const out = Poly1305.mac(hexToBytes(v.key), hexToBytes(v.data))
    assert.equal(bytesToHex(out), v.mac.toLowerCase(), `[${label}] Poly1305 vector #${i + 1}`)
  }

  // 2. ChaCha20
  for (let i = 0; i < chacha20_vectors.length; i++) {
    const v = chacha20_vectors[i]
    const len = v.stream.length >> 1
    const out = ChaCha20.encrypt(hexToBytes(v.key), toIetfNonce(hexToBytes(v.nonce)), new Uint8Array(len), 0)
    assert.equal(bytesToHex(out), v.stream.toLowerCase(), `[${label}] ChaCha20 vector #${i + 1}`)
  }

  // 3. ChaCha20-Poly1305 (one-shot + streaming + tamper rejection)
  for (let i = 0; i < chacha20poly1305_vectors.length; i++) {
    const v = chacha20poly1305_vectors[i]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const msg = hexToBytes(v.msg)
    const combined = ChaCha20Poly1305.encrypt(key, nonce, msg, aad)
    assert.equal(bytesToHex(combined), v.result.toLowerCase(), `[${label}] ChaCha20-Poly1305 vector #${i + 1}`)

    const decrypted = ChaCha20Poly1305.decrypt(key, nonce, combined, aad)
    assert.ok(decrypted !== null, `[${label}] ChaCha20-Poly1305 decrypt #${i + 1}`)
    assert.equal(bytesToHex(decrypted), bytesToHex(msg))

    // Tamper tag -> must reject
    const tampered = new Uint8Array(combined)
    tampered[tampered.length - 1] ^= 0xff
    assert.equal(ChaCha20Poly1305.decrypt(key, nonce, tampered, aad), null)
  }

  // 4. XChaCha20-Poly1305 (RFC + streaming chunks + >1MB transparent streaming)
  for (let i = 0; i < xchacha20poly1305_vectors.length; i++) {
    const v = xchacha20poly1305_vectors[i]
    const key = hexToBytes(v.key)
    const nonce = hexToBytes(v.nonce)
    const aad = hexToBytes(v.aad)
    const msg = hexToBytes(v.msg)
    const combined = XChaCha20Poly1305.encrypt(key, nonce, msg, aad)
    assert.equal(bytesToHex(combined), v.result.toLowerCase(), `[${label}] XChaCha20-Poly1305 vector #${i + 1}`)

    // Streaming chunk-by-chunk mismatch sizes
    const enc = XChaCha20Poly1305.createEncryptStream(key, nonce, aad)
    const ctParts: Uint8Array[] = []
    for (let off = 0; off < msg.length; off += 17) {
      ctParts.push(enc.update(msg.subarray(off, Math.min(off + 17, msg.length))))
    }
    const tag = enc.final()
    const streamOut = new Uint8Array(msg.length + TAG_BYTES)
    let p = 0
    for (const part of ctParts) {
      streamOut.set(part, p)
      p += part.length
    }
    streamOut.set(tag, p)
    assert.equal(bytesToHex(streamOut), v.result.toLowerCase(), `[${label}] XChaCha20-Poly1305 streaming`)

    const dec = XChaCha20Poly1305.createDecryptStream(key, nonce, aad)
    const pt = dec.update(streamOut.subarray(0, msg.length))
    assert.equal(dec.final(tag), true)
    assert.equal(bytesToHex(pt), bytesToHex(msg))
  }

  // 5. Large payload > 1 MB (exercises streamed path + Arena)
  const bigKey = new Uint8Array(32).fill(0x42)
  const bigNonce = new Uint8Array(24).fill(0x24)
  const bigMsg = new Uint8Array(1_250_000)
  for (let i = 0; i < bigMsg.length; i++) bigMsg[i] = (i * 31) & 0xff
  const bigCombined = XChaCha20Poly1305.encrypt(bigKey, bigNonce, bigMsg, "big-aad")
  const bigDec = XChaCha20Poly1305.decrypt(bigKey, bigNonce, bigCombined, "big-aad")
  assert.ok(bigDec !== null)
  assert.equal(bytesToHex(bigDec), bytesToHex(bigMsg))

  // 6. XChaCha20 direct round-trip
  const xct = XChaCha20.encrypt(bigKey, bigNonce, "xchacha-test-payload")
  assert.equal(new TextDecoder().decode(XChaCha20.decrypt(bigKey, bigNonce, xct)), "xchacha-test-payload")

  const stats = AeadWasm.getInstance().getArenaStats()
  assert.equal(stats.used, 0, `[${label}] Arena leaked bytes: ${stats.used}`)
  assert.equal(stats.locked, false, `[${label}] Lock left engaged`)
}

interface WorkerJob {
  mode: "contention" | "hammer"
  workerId: number
  wasmModule: WebAssembly.Module
  sharedMemory: WebAssembly.Memory
  iterations?: number
}

if (!isMainThread) {
  const job = workerData as WorkerJob
  const wasm = await AeadWasm.fromModule(job.wasmModule, { env: { memory: job.sharedMemory } })
  assert.equal(wasm.isThreaded(), true)

  if (job.mode === "contention") {
    // Main thread holds the lock at launch; tryLock must report busy immediately
    const sawBusy = !wasm.tryLock()
    if (!sawBusy) wasm.unlock()
    parentPort!.postMessage({ phase: "ready", sawBusy })

    // Now call encrypt(), which must spin-wait on arena_lock until main thread unlocks
    const key = new Uint8Array(32).fill(job.workerId + 1)
    const nonce = new Uint8Array(12).fill(0xaa)
    const pt = new TextEncoder().encode("concurrent-lock-protected-message")
    const combined = ChaCha20Poly1305.encrypt(key, nonce, pt, "lock-aad")
    const dec = ChaCha20Poly1305.decrypt(key, nonce, combined, "lock-aad")
    assert.ok(dec !== null)
    assert.equal(new TextDecoder().decode(dec), "concurrent-lock-protected-message")
    parentPort!.postMessage({ phase: "done", ok: true })
  } else {
    const iters = job.iterations ?? 100
    for (let i = 0; i < iters; i++) {
      const key = new Uint8Array(32)
      key.fill((job.workerId * 37 + i) & 0xff)
      const nonce12 = new Uint8Array(12)
      nonce12.fill((job.workerId + i) & 0xff)
      const nonce24 = new Uint8Array(24)
      nonce24.fill((job.workerId * 13 + i) & 0xff)

      const payload = new Uint8Array(256 + ((i * 19) % 1024))
      for (let b = 0; b < payload.length; b++) payload[b] = (b + i + job.workerId) & 0xff

      const c1 = ChaCha20Poly1305.encrypt(key, nonce12, payload, `w-${job.workerId}-${i}`)
      const d1 = ChaCha20Poly1305.decrypt(key, nonce12, c1, `w-${job.workerId}-${i}`)
      assert.ok(d1 !== null)
      assert.equal(bytesToHex(d1), bytesToHex(payload))

      const c2 = XChaCha20Poly1305.encrypt(key, nonce24, payload)
      const d2 = XChaCha20Poly1305.decrypt(key, nonce24, c2)
      assert.ok(d2 !== null)
      assert.equal(bytesToHex(d2), bytesToHex(payload))

      const s1 = ChaCha20.encrypt(key, nonce12, payload, i)
      assert.equal(bytesToHex(ChaCha20.decrypt(key, nonce12, s1, i)), bytesToHex(payload))

      const mac = Poly1305.mac(key, payload)
      assert.equal(mac.length, TAG_BYTES)
    }
    parentPort!.postMessage({ phase: "done", ok: true })
  }
} else {
  const __dirname = path.dirname(fileURLToPath(import.meta.url))
  const stPath = path.resolve(__dirname, "../dist/aead.wasm")
  const mtPath = path.resolve(__dirname, "../dist/aead.mt.wasm")

  // ── 1. Verify Single-Thread build ──────────────────────────────────────────
  console.log("1) Verificando dist/aead.wasm (Single-Thread)...")
  const stWasm = await AeadWasm.fromBuffer(readFileSync(stPath))
  assert.equal(stWasm.isThreaded(), false)
  assert.equal(stWasm.getMemory().buffer instanceof ArrayBuffer, true)
  runVectorSuite("ST")

  // Single-thread Lock test: protect PARAM_IN against overwrite while locked
  assert.equal(stWasm.tryLock(), true)
  assert.equal(stWasm.tryLock(), false)
  assert.equal(stWasm.isLocked(), true)
  const sentinel = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe])
  stWasm.getAllocator().writeInput(sentinel, 0)
  assert.throws(() => ChaCha20Poly1305.encrypt(new Uint8Array(32), new Uint8Array(12), "blocked"), /bloqueada/)
  assert.throws(() => ChaCha20.encrypt(new Uint8Array(32), new Uint8Array(12), "blocked"), /bloqueada/)
  assert.throws(() => Poly1305.mac(new Uint8Array(32), "blocked"), /bloqueada/)
  // Sentinel in PARAM_IN must still be completely untouched
  assert.equal(bytesToHex(stWasm.getAllocator().readBytes(stWasm.getAllocator().inPtr, sentinel.length)), bytesToHex(sentinel))
  stWasm.unlock()
  assert.equal(stWasm.isLocked(), false)
  console.log("   ✓ Vectores ST (Poly1305, ChaCha20, XChaCha20, AEAD, streaming >1MB) + Lock ST OK")

  // ── 2. Verify Multithread build ───────────────────────────────────────────
  console.log("2) Verificando dist/aead.mt.wasm (Multithread + SharedArrayBuffer)...")
  const mtWasm = await AeadWasm.fromBuffer(readFileSync(mtPath))
  assert.equal(mtWasm.isThreaded(), true)
  assert.equal(typeof SharedArrayBuffer !== "undefined" && mtWasm.getMemory().buffer instanceof SharedArrayBuffer, true)
  runVectorSuite("MT")
  console.log("   ✓ Vectores MT (Poly1305, ChaCha20, XChaCha20, AEAD, streaming >1MB) OK")

  const wasmModule = mtWasm.getModule()!
  const sharedMemory = mtWasm.getMemory()

  // ── 3. Verify Multi-Slot isolation + Full-Pool Lock contention across Worker ──
  console.log("3) Verificando aislamiento Multi-Slot y Lock atómico en Worker Thread...")
  assert.equal(mtWasm.getSlotCount(), 8, "MT debe exponer 8 slots paralelos")

  // 3a. Lock Slot 0 + write sentinel: Worker encrypting concurrently picks Slot 1 and leaves Slot 0 intact
  mtWasm.lockSlot(0)
  const mtSentinel = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44])
  mtWasm.getAllocator().writeInput(mtSentinel, 0)

  // Lock remaining slots 1..7 so Worker must wait until unlocked
  for (let s = 1; s < mtWasm.getSlotCount(); s++) {
    mtWasm.lockSlot(s)
  }

  await new Promise<void>((resolve, reject) => {
    const worker = new Worker(fileURLToPath(import.meta.url), {
      workerData: {
        mode: "contention",
        workerId: 1,
        wasmModule,
        sharedMemory
      } satisfies WorkerJob
    })

    worker.on("error", reject)
    worker.on("message", async (msg: { phase: string; sawBusy?: boolean; ok?: boolean }) => {
      if (msg.phase === "ready") {
        assert.equal(msg.sawBusy, true, "El worker debe detectar que el lock del Slot 0 está ocupado")
        // Give the worker time to enter spin-wait because all 8 slots are locked
        await new Promise((r) => setTimeout(r, 40))
        // Sentinel in Slot 0 PARAM_IN must STILL be intact!
        const readBackBefore = mtWasm.getAllocator().readBytes(mtWasm.getAllocator().inPtr, mtSentinel.length)
        assert.equal(bytesToHex(readBackBefore), bytesToHex(mtSentinel), "Worker sobrescribió PARAM_IN mientras todos los slots estaban bloqueados!")
        // Unlock ONLY slots 1..7 while keeping Slot 0 locked -> Worker runs on another slot without touching Slot 0
        for (let s = 1; s < mtWasm.getSlotCount(); s++) {
          mtWasm.unlockSlot(s)
        }
      } else if (msg.phase === "done") {
        assert.equal(msg.ok, true)
        // Slot 0 sentinel must STILL be intact even AFTER worker encrypted on Slot 1!
        const readBackAfter = mtWasm.getAllocator().readBytes(mtWasm.getAllocator().inPtr, mtSentinel.length)
        assert.equal(bytesToHex(readBackAfter), bytesToHex(mtSentinel), "Worker tocó Slot 0 aunque operó en otro slot!")
        mtWasm.unlockSlot(0)
        await worker.terminate()
        resolve()
      }
    })
  })
  console.log("   ✓ Lock atómico + aislamiento Multi-Slot (8 slots) verificados")

  // ── 4. Verify 4 concurrent workers hammering shared WASM memory ───────────
  console.log("4) Verificando 4 workers concurrentes sobre la misma SharedArrayBuffer...")
  const workers = Array.from({ length: 4 }, (_, idx) => {
    return new Promise<void>((resolve, reject) => {
      const w = new Worker(fileURLToPath(import.meta.url), {
        workerData: {
          mode: "hammer",
          workerId: idx + 1,
          wasmModule,
          sharedMemory,
          iterations: 75
        } satisfies WorkerJob
      })
      w.on("error", reject)
      w.on("message", async (msg: { phase: string; ok?: boolean }) => {
        if (msg.phase === "done") {
          assert.equal(msg.ok, true)
          await w.terminate()
          resolve()
        }
      })
    })
  })
  await Promise.all(workers)
  const finalStats = mtWasm.getArenaStats()
  assert.equal(finalStats.used, 0)
  assert.equal(finalStats.locked, false)
  console.log("   ✓ 4 workers × 75 rondas (1,200 ops concurrentes) sin colisiones ni corrupción")
  console.log("✅ TODAS LAS VERIFICACIONES ST + MT + ARENA LOCK PASARON CORRECTAMENTE")
}
