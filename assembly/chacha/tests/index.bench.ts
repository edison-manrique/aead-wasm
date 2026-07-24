// bun builder.ts chacha -fm 322 -b

import { ChaCha20, XChaCha20 } from ".."

// =========================================================================
// ARQUITECTURA DE MEMORIA ESTÁTICA PARA ChaCha20 (BARE-METAL)
// =========================================================================
// Requisito máximo para ChaCha20: 10MB (buffer A) + 10MB (buffer B) = ~20MB
// Reservamos esta memoria UNA SOLA VEZ al cargar el módulo Wasm
// No habrá más asignaciones en el heap principal durante la ejecución
// =========================================================================
const MAX_DATA_SIZE: u32 = 10 * 1024 * 1024

// Buffer A: Contendrá el 'plaintext' para cifrar o el destino del descifrado
const DATA_BUFFER_A = new ArrayBuffer(MAX_DATA_SIZE)
// Buffer B: Contendrá la salida del cifrado o el 'ciphertext' para descifrar
const DATA_BUFFER_B = new ArrayBuffer(MAX_DATA_SIZE)

// Buffers pequeños estáticos
const KEY_BUFFER = new ArrayBuffer(32)
const NONCE_BUFFER = new ArrayBuffer(24)

/**
 * Función de benchmark interna ultra-optimizada y unificada
 * Utiliza buffers estáticos para los datos y el Arena para el objeto de contexto
 * Complejidad de memoria en tiempo de ejecución: O(1)
 */
// @ts-ignore: decorator
@inline
function runBenchmark1(size: u32, iterations: i32, isDecrypt: bool): void {

  // 2. Creamos Vistas "Zero-Copy" sobre los buffers estáticos
  const key = Uint8Array.wrap(KEY_BUFFER, 0, 32)
  const nonce = Uint8Array.wrap(NONCE_BUFFER, 0, 12)
  const bufferA = Uint8Array.wrap(DATA_BUFFER_A, 0, size)
  const bufferB = Uint8Array.wrap(DATA_BUFFER_B, 0, size)

  // 3. El objeto de contexto 'chacha' también se aloja en el Arena
  // const chacha = ChaCha20.create(key, nonce, 1)

  // 4. Ejecución del benchmark
  if (isDecrypt) {
    // Para medir el descifrado, primero necesitamos datos cifrados
    // Pre-ciframos A -> B una vez
    ChaCha20.encrypt(key, nonce, bufferA, bufferB)

    // Ahora medimos el descifrado de B -> A
    for (let i = 0; i < iterations; i++) {
      ChaCha20.encrypt(key, nonce, bufferB, bufferA)
    }
  } else {
    // Medimos el cifrado de A -> B
    for (let i = 0; i < iterations; i++) {
      ChaCha20.encrypt(key, nonce, bufferA, bufferB)
    }
  }

}
function runBenchmark2(size: u32, iterations: i32, isDecrypt: bool): void {

  // 2. Creamos Vistas "Zero-Copy" sobre los buffers estáticos
  const key = Uint8Array.wrap(KEY_BUFFER, 0, 32)
  const nonce = Uint8Array.wrap(NONCE_BUFFER, 0, 24)
  const bufferA = Uint8Array.wrap(DATA_BUFFER_A, 0, size)
  const bufferB = Uint8Array.wrap(DATA_BUFFER_B, 0, size)


  // 4. Ejecución del benchmark
  if (isDecrypt) {
    // Para medir el descifrado, primero necesitamos datos cifrados
    // Pre-ciframos A -> B una vez
    XChaCha20.encrypt(key, nonce, bufferA, bufferB)

    // Ahora medimos el descifrado de B -> A
    for (let i = 0; i < iterations; i++) {
      XChaCha20.encrypt(key, nonce, bufferB, bufferA)
    }
  } else {
    // Medimos el cifrado de A -> B
    for (let i = 0; i < iterations; i++) {
      XChaCha20.encrypt(key, nonce, bufferA, bufferB)
    }
  }
}

// =========================================================================
// >> EXPORTS DE BENCHMARKS DE ENCRYPT
// =========================================================================

export function benchmark_chacha20_encrypt_64k(iterations: i32): void {
  runBenchmark1(64 * 1024, iterations, false)
}

export function benchmark_chacha20_encrypt_1mb(iterations: i32): void {
  runBenchmark1(1024 * 1024, iterations, false)
}

export function benchmark_chacha20_encrypt_10mb(iterations: i32): void {
  runBenchmark1(10 * 1024 * 1024, iterations, false)
}

export function benchmark_xchacha20_encrypt_64k(iterations: i32): void {
  runBenchmark2(64 * 1024, iterations, false)
}

export function benchmark_xchacha20_encrypt_1mb(iterations: i32): void {
  runBenchmark2(1024 * 1024, iterations, false)
}

export function benchmark_xchacha20_encrypt_10mb(iterations: i32): void {
  runBenchmark2(10 * 1024 * 1024, iterations, false)
}

// =========================================================================
// >> EXPORTS DE BENCHMARKS DE DECRYPT (NUEVO)
// =========================================================================

export function benchmark_chacha20_decrypt_64k(iterations: i32): void {
  runBenchmark1(64 * 1024, iterations, true)
}

export function benchmark_chacha20_decrypt_1mb(iterations: i32): void {
  runBenchmark1(1024 * 1024, iterations, true)
}

export function benchmark_chacha20_decrypt_10mb(iterations: i32): void {
  runBenchmark1(10 * 1024 * 1024, iterations, true)
}

export function benchmark_xchacha20_decrypt_64k(iterations: i32): void {
  runBenchmark2(64 * 1024, iterations, true)
}

export function benchmark_xchacha20_decrypt_1mb(iterations: i32): void {
  runBenchmark2(1024 * 1024, iterations, true)
}

export function benchmark_xchacha20_decrypt_10mb(iterations: i32): void {
  runBenchmark2(10 * 1024 * 1024, iterations, true)
}

