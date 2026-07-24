// bun builder.ts aead -fm 323 -b (20,672 kb)

import { ChaCha20Poly1305, XChaCha20Poly1305 } from "../chacha_polyV2"
// Asumimos que la clase Memory sigue existiendo para el contexto y objetos pequeños.
import { Memory } from "../../lib/Memory"

// =========================================================================
// ESTRATEGIA DE MEMORIA DE DOS BUFFERS (20MB)
// =========================================================================
// Reservamos el espacio para los dos buffers de datos más grandes que deben
// coexistir. El tercer buffer se mapeará sobre uno de estos dos.
const MAX_BENCHMARK_SIZE: u32 = 10 * 1024 * 1024
const TAG_SIZE: u32 = 16

// Buffer A: Contendrá 'plaintext' o 'decryptedOutput'
const DATA_BUFFER_A = new ArrayBuffer(MAX_BENCHMARK_SIZE)
// Buffer B: Contendrá 'ciphertext'
const DATA_BUFFER_B = new ArrayBuffer(MAX_BENCHMARK_SIZE + TAG_SIZE)

// Buffers pequeños y estáticos para datos que no cambian de tamaño
const KEY_BUFFER = new ArrayBuffer(32)
const NONCE_BUFFER = new ArrayBuffer(24) // Máximo tamaño para XChaCha
const AAD_BUFFER = new ArrayBuffer(16)

/**
 * Benchmark ultra-optimizado con reutilización de buffers. Cero 'new' en runtime.
 */
// @ts-ignore: decorator
@inline
function runBenchmark(plaintext_size: u32, iterations: i32, isXChaCha: bool, isDecrypt: bool): void {
  // Guardamos el estado del Arena. Aquí solo vivirá el objeto 'context'.
  const marker = Memory.save()

  // --- Creamos Vistas "Zero-Copy" ---
  // Estas vistas son objetos ligeros que viven en el Arena y apuntan a los buffers estáticos.
  const key = Uint8Array.wrap(KEY_BUFFER, 0, 32)
  const nonce = Uint8Array.wrap(NONCE_BUFFER, 0, isXChaCha ? 24 : 12)
  const aad = Uint8Array.wrap(AAD_BUFFER, 0, 16)

  // Buffer A se usa para el texto plano inicial
  const plaintext = Uint8Array.wrap(DATA_BUFFER_A, 0, plaintext_size)
  // Buffer B siempre es para el texto cifrado
  const ciphertext = Uint8Array.wrap(DATA_BUFFER_B, 0, plaintext_size + TAG_SIZE)
  // ¡REUTILIZACIÓN! El buffer A se usará para la salida descifrada.
  const decryptedOutput = Uint8Array.wrap(DATA_BUFFER_A, 0, plaintext_size)

  if (isXChaCha) {
    const context = XChaCha20Poly1305.create(key, nonce, aad)

    if (isDecrypt) {
      // 1. Preparamos los datos cifrados. plaintext (A) -> ciphertext (B)
      context.encrypt(plaintext, ciphertext)
      // En este punto, el contenido de DATA_BUFFER_A (plaintext) es irrelevante.

      // 2. Ejecutamos el benchmark de descifrado.
      //    ciphertext (B) -> decryptedOutput (que apunta a A)
      for (let i = 0; i < iterations; i++) {
        context.decrypt(ciphertext, decryptedOutput)
      }
    } else {
      // Benchmark de cifrado: plaintext (A) -> ciphertext (B)
      for (let i = 0; i < iterations; i++) {
        context.encrypt(plaintext, ciphertext)
      }
    }
  } else {
    // ChaCha20 (misma lógica)
    const context = ChaCha20Poly1305.create(key, nonce, aad)

    if (isDecrypt) {
      context.encrypt(plaintext, ciphertext)
      for (let i = 0; i < iterations; i++) {
        context.decrypt(ciphertext, decryptedOutput)
      }
    } else {
      for (let i = 0; i < iterations; i++) {
        context.encrypt(plaintext, ciphertext)
      }
    }
  }

  // Aniquilamos el objeto 'context' del Arena. Los buffers estáticos permanecen.
  Memory.restore(marker)
}

// --- Benchmarks de ENCRYPT ---

export function benchmark_chacha20poly1305_encrypt_128k(iterations: i32): void {
  runBenchmark(128 * 1024, iterations, false, false)
}
export function benchmark_chacha20poly1305_encrypt_1mb(iterations: i32): void {
  runBenchmark(1024 * 1024, iterations, false, false)
}
export function benchmark_chacha20poly1305_encrypt_10mb(iterations: i32): void {
  runBenchmark(10 * 1024 * 1024, iterations, false, false)
}
export function benchmark_xchacha20poly1305_encrypt_128k(iterations: i32): void {
  runBenchmark(128 * 1024, iterations, true, false)
}
export function benchmark_xchacha20poly1305_encrypt_1mb(iterations: i32): void {
  runBenchmark(1024 * 1024, iterations, true, false)
}
export function benchmark_xchacha20poly1305_encrypt_10mb(iterations: i32): void {
  runBenchmark(10 * 1024 * 1024, iterations, true, false)
}

// --- Benchmarks de DECRYPT (NUEVO) ---

export function benchmark_chacha20poly1305_decrypt_128k(iterations: i32): void {
  runBenchmark(128 * 1024, iterations, false, true)
}
export function benchmark_chacha20poly1305_decrypt_1mb(iterations: i32): void {
  runBenchmark(1024 * 1024, iterations, false, true)
}
export function benchmark_chacha20poly1305_decrypt_10mb(iterations: i32): void {
  runBenchmark(10 * 1024 * 1024, iterations, false, true)
}
export function benchmark_xchacha20poly1305_decrypt_128k(iterations: i32): void {
  runBenchmark(128 * 1024, iterations, true, true)
}
export function benchmark_xchacha20poly1305_decrypt_1mb(iterations: i32): void {
  runBenchmark(1024 * 1024, iterations, true, true)
}
export function benchmark_xchacha20poly1305_decrypt_10mb(iterations: i32): void {
  runBenchmark(10 * 1024 * 1024, iterations, true, true)
}
