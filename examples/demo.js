/**
 * ==============================================================================
 * 🧪 ChaChaPolyWasm — Demo & Validación Exhaustiva
 * ==============================================================================
 * Ejecutar: node examples/demo.js
 * ==============================================================================
 */

import { readFileSync } from "node:fs"
import { fileURLToPath, pathToFileURL } from "node:url"
import { dirname, join } from "node:path"
import { randomBytes } from "node:crypto"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// ── Cargar WASM ────────────────────────────────────────────────────────────

const wasmPath = join(__dirname, "..", "dist", "aead.wasm")
const wasmBuffer = readFileSync(wasmPath)

// Importar el wrapper compilado (usamos pathToFileURL para compatibilidad Windows ESM)
const modulePath = join(__dirname, "..", "dist", "index.js")
const { default: ChaChaPolyWasm } = await import(pathToFileURL(modulePath).href)

const crypto = await ChaChaPolyWasm.fromBuffer(wasmBuffer)

// ── Helpers ────────────────────────────────────────────────────────────────

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("")
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

let passed = 0
let failed = 0

function assert(condition, name) {
  if (condition) {
    console.log(`  ✅ ${name}`)
    passed++
  } else {
    console.error(`  ❌ ${name}`)
    failed++
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. ChaCha20 — Cifrador de Flujo
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  🔓 TEST: ChaCha20 (Cifrador de Flujo, Nonce 12B)")
console.log("══════════════════════════════════════════════════════")

{
  const key = randomBytes(32)
  const nonce = randomBytes(12)
  const plaintext = new TextEncoder().encode("ChaCha20 funciona correctamente en WASM! 🔥")

  const ciphertext = crypto.chacha20Encrypt(new Uint8Array(key), new Uint8Array(nonce), plaintext)
  assert(ciphertext.length === plaintext.length, "Longitud del ciphertext == longitud del plaintext")
  assert(!arraysEqual(ciphertext, plaintext), "Ciphertext es diferente del plaintext")

  const decrypted = crypto.chacha20Decrypt(new Uint8Array(key), new Uint8Array(nonce), ciphertext)
  assert(arraysEqual(decrypted, plaintext), "Descifrado coincide con plaintext original")

  console.log(`  📦 Plaintext:  "${new TextDecoder().decode(plaintext)}"`)
  console.log(`  🔐 Ciphertext: ${toHex(ciphertext).slice(0, 64)}...`)
  console.log(`  🔓 Decrypted:  "${new TextDecoder().decode(decrypted)}"`)
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. XChaCha20 — Cifrador de Flujo Extendido
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  🔓 TEST: XChaCha20 (Cifrador de Flujo, Nonce 24B)")
console.log("══════════════════════════════════════════════════════")

{
  const key = randomBytes(32)
  const nonce = randomBytes(24)
  const plaintext = new TextEncoder().encode("XChaCha20 con nonce extendido de 192 bits 🚀")

  const ciphertext = crypto.xchacha20Encrypt(new Uint8Array(key), new Uint8Array(nonce), plaintext)
  assert(ciphertext.length === plaintext.length, "Longitud del ciphertext == longitud del plaintext")
  assert(!arraysEqual(ciphertext, plaintext), "Ciphertext es diferente del plaintext")

  const decrypted = crypto.xchacha20Decrypt(new Uint8Array(key), new Uint8Array(nonce), ciphertext)
  assert(arraysEqual(decrypted, plaintext), "Descifrado coincide con plaintext original")

  console.log(`  📦 Plaintext:  "${new TextDecoder().decode(plaintext)}"`)
  console.log(`  🔐 Ciphertext: ${toHex(ciphertext).slice(0, 64)}...`)
  console.log(`  🔓 Decrypted:  "${new TextDecoder().decode(decrypted)}"`)
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Poly1305 — MAC de Un Solo Uso
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  🏷️  TEST: Poly1305 (MAC de Un Solo Uso)")
console.log("══════════════════════════════════════════════════════")

{
  const key = randomBytes(32)
  const message = new TextEncoder().encode("Mensaje autenticado con Poly1305 MAC")

  const tag = crypto.poly1305Mac(message, new Uint8Array(key))
  assert(tag.length === 16, "Tag tiene exactamente 16 bytes (128 bits)")

  // Mismo mensaje + misma clave = mismo tag (determinístico)
  const tag2 = crypto.poly1305Mac(message, new Uint8Array(key))
  assert(arraysEqual(tag, tag2), "Mismo mensaje y clave produce mismo tag (determinístico)")

  // Mensaje diferente = tag diferente
  const otherMsg = new TextEncoder().encode("Mensaje DIFERENTE")
  const tag3 = crypto.poly1305Mac(otherMsg, new Uint8Array(key))
  assert(!arraysEqual(tag, tag3), "Mensaje diferente produce tag diferente")

  console.log(`  📦 Message: "${new TextDecoder().decode(message)}"`)
  console.log(`  🏷️  Tag:     ${toHex(tag)}`)
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. ChaCha20-Poly1305 AEAD (RFC 8439)
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  🔐 TEST: ChaCha20-Poly1305 AEAD (RFC 8439)")
console.log("══════════════════════════════════════════════════════")

{
  const key = randomBytes(32)
  const nonce = randomBytes(12)
  const aad = new TextEncoder().encode("datos adicionales autenticados")
  const plaintext = new TextEncoder().encode("Cifrado autenticado AEAD con ChaCha20-Poly1305!")

  // ── Cifrado ──
  const sealed = crypto.chacha20Poly1305Encrypt(
    new Uint8Array(key), new Uint8Array(nonce), plaintext, aad
  )
  assert(sealed.length === plaintext.length + 16, "Sealed = plaintext + 16 bytes de tag")

  // ── Descifrado válido ──
  const opened = crypto.chacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), sealed, aad
  )
  assert(opened !== null, "Descifrado exitoso (tag válido)")
  assert(opened !== null && arraysEqual(opened, plaintext), "Plaintext recuperado correctamente")

  // ── Tampering: modificar 1 byte del ciphertext ──
  const tampered = new Uint8Array(sealed)
  tampered[0] ^= 0xFF  // Flip bits del primer byte
  const failedDecrypt = crypto.chacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), tampered, aad
  )
  assert(failedDecrypt === null, "Detección de tampering: ciphertext alterado → null")

  // ── AAD incorrecto ──
  const wrongAad = new TextEncoder().encode("datos FALSOS")
  const failedAad = crypto.chacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), sealed, wrongAad
  )
  assert(failedAad === null, "Detección de tampering: AAD incorrecto → null")

  // ── Sin AAD ──
  const sealedNoAad = crypto.chacha20Poly1305Encrypt(
    new Uint8Array(key), new Uint8Array(nonce), plaintext, null
  )
  const openedNoAad = crypto.chacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), sealedNoAad, null
  )
  assert(openedNoAad !== null && arraysEqual(openedNoAad, plaintext), "AEAD sin AAD funciona correctamente")

  console.log(`  📦 Plaintext: "${new TextDecoder().decode(plaintext)}"`)
  console.log(`  🔐 Sealed:    ${toHex(sealed).slice(0, 64)}...`)
  console.log(`  🏷️  Tag:       ${toHex(sealed.slice(-16))}`)
  if (opened) {
    console.log(`  🔓 Opened:    "${new TextDecoder().decode(opened)}"`)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. XChaCha20-Poly1305 AEAD (Nonce Extendido 24B)
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  🔐 TEST: XChaCha20-Poly1305 AEAD (Nonce 24B)")
console.log("══════════════════════════════════════════════════════")

{
  const key = randomBytes(32)
  const nonce = randomBytes(24)
  const aad = new TextEncoder().encode("metadata v2.0")
  const plaintext = new TextEncoder().encode("XChaCha20-Poly1305: nonce seguro para generación aleatoria 🔒")

  const sealed = crypto.xchacha20Poly1305Encrypt(
    new Uint8Array(key), new Uint8Array(nonce), plaintext, aad
  )
  assert(sealed.length === plaintext.length + 16, "Sealed = plaintext + 16 bytes de tag")

  const opened = crypto.xchacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), sealed, aad
  )
  assert(opened !== null, "Descifrado exitoso (tag válido)")
  assert(opened !== null && arraysEqual(opened, plaintext), "Plaintext recuperado correctamente")

  // ── Tampering ──
  const tampered = new Uint8Array(sealed)
  tampered[tampered.length - 1] ^= 0x01
  const failedDecrypt = crypto.xchacha20Poly1305Decrypt(
    new Uint8Array(key), new Uint8Array(nonce), tampered, aad
  )
  assert(failedDecrypt === null, "Detección de tampering: tag alterado → null")

  console.log(`  📦 Plaintext: "${new TextDecoder().decode(plaintext)}"`)
  console.log(`  🔐 Sealed:    ${toHex(sealed).slice(0, 64)}...`)
  console.log(`  🏷️  Tag:       ${toHex(sealed.slice(-16))}`)
  if (opened) {
    console.log(`  🔓 Opened:    "${new TextDecoder().decode(opened)}"`)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Benchmark de Rendimiento
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
console.log("  ⚡ BENCHMARK: Rendimiento AEAD (1KB, 64KB)")
console.log("══════════════════════════════════════════════════════")

{
  const benchKey = new Uint8Array(32)
  const benchNonce12 = new Uint8Array(12)
  const benchNonce24 = new Uint8Array(24)
  randomBytes(32).copy(benchKey)
  randomBytes(12).copy(benchNonce12)
  randomBytes(24).copy(benchNonce24)

  for (const size of [1024, 65536]) {
    const data = new Uint8Array(randomBytes(size))
    const label = size >= 1024 ? `${size / 1024}KB` : `${size}B`

    // ── ChaCha20-Poly1305 ──
    const warmup1 = 50
    for (let i = 0; i < warmup1; i++) {
      crypto.chacha20Poly1305Encrypt(benchKey, benchNonce12, data, null)
    }
    const iters1 = 2000
    const t1 = performance.now()
    for (let i = 0; i < iters1; i++) {
      crypto.chacha20Poly1305Encrypt(benchKey, benchNonce12, data, null)
    }
    const dt1 = performance.now() - t1
    const ops1 = Math.round(iters1 / (dt1 / 1000))
    const mbps1 = ((iters1 * size) / (dt1 / 1000) / 1e6).toFixed(1)
    console.log(`  ChaCha20-Poly1305  (${label}): ${ops1.toLocaleString()} ops/s | ${mbps1} MB/s`)

    // ── XChaCha20-Poly1305 ──
    for (let i = 0; i < warmup1; i++) {
      crypto.xchacha20Poly1305Encrypt(benchKey, benchNonce24, data, null)
    }
    const t2 = performance.now()
    for (let i = 0; i < iters1; i++) {
      crypto.xchacha20Poly1305Encrypt(benchKey, benchNonce24, data, null)
    }
    const dt2 = performance.now() - t2
    const ops2 = Math.round(iters1 / (dt2 / 1000))
    const mbps2 = ((iters1 * size) / (dt2 / 1000) / 1e6).toFixed(1)
    console.log(`  XChaCha20-Poly1305 (${label}): ${ops2.toLocaleString()} ops/s | ${mbps2} MB/s`)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Resumen Final
// ═══════════════════════════════════════════════════════════════════════════

console.log("\n══════════════════════════════════════════════════════")
if (failed === 0) {
  console.log(`  🎉 TODOS LOS TESTS PASARON: ${passed}/${passed + failed}`)
} else {
  console.log(`  ⚠️  TESTS FALLIDOS: ${failed}/${passed + failed}`)
}
console.log("══════════════════════════════════════════════════════\n")

process.exit(failed > 0 ? 1 : 0)
