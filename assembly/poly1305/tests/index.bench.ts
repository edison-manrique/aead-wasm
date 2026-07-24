// bun builder.ts poly1305 -b -fm 170

import { Poly1305 } from ".."

// =========================================================================
// >> IMPORTS DEL HOST (JAVASCRIPT)
// =========================================================================
// Declaramos una función "log" que esperamos que el host (JS) nos proporcione
// al instanciar el módulo Wasm. La usaremos para reportar la memoria.
// @ts-ignore
@external("env", "log")
declare function log(message: string): void

// =========================================================================
// ARQUITECTURA DE MEMORIA ESTÁTICA PARA Poly1305 (BARE-METAL)
// =========================================================================
// Requisito máximo: 10MB para el mensaje. La clave (32b) y la salida (16b) son despreciables
const MAX_DATA_SIZE: u32 = 10 * 1024 * 1024

const MESSAGE_BUFFER = new ArrayBuffer(MAX_DATA_SIZE)
const KEY_BUFFER = new ArrayBuffer(32)
const OUT_BUFFER = new ArrayBuffer(16)

// =========================================================================
// INICIALIZACIÓN DE DATOS (UNA SOLA VEZ)
// =========================================================================
// Para un benchmark justo, pre-llenamos los buffers con datos una única vez
// cuando el módulo Wasm se carga. Esto evita que el coste de inicialización
// contamine la medición del rendimiento del algoritmo.
function initializeStaticBuffers(): void {
  const keyView = Uint8Array.wrap(KEY_BUFFER, 0, 32)
  for (let i: u32 = 0; i < 32; i++) {
    keyView[i] = <u8>i
  }

  const messageView = Uint8Array.wrap(MESSAGE_BUFFER, 0, MAX_DATA_SIZE)
  for (let i: u32 = 0; i < MAX_DATA_SIZE; i++) {
    messageView[i] = <u8>(i & 0xff)
  }
}
// Ejecutamos la inicialización ahora
initializeStaticBuffers()
// =========================================================================

/**
 * Función de benchmark interna ultra-optimizada
 */
// @ts-ignore
@inline
function runBenchmark(size: u32, iterations: i32): void {
  // En este caso, poly1305_mac es una función pura que no crea objetos,
  // por lo que no es estrictamente necesario usar el Arena.
  // Creamos vistas que apuntan directamente a nuestros buffers globales
  const key = Uint8Array.wrap(KEY_BUFFER, 0, 32)
  const message = Uint8Array.wrap(MESSAGE_BUFFER, 0, size)
  const out = Uint8Array.wrap(OUT_BUFFER, 0, 16)

  // Ejecución del benchmark
  for (let i: i32 = 0; i < iterations; i++) {
    Poly1305.mac(message, key, out)
  }
}

// Reporta la huella de memoria Wasm al host
function report_memory(): void {
  trace("Huella de memoria Wasm estable: " + memory.size().toString() + " pages") 
}

// =========================================================================
// >> EXPORTS DE BENCHMARKS PARA EL HOST
// =========================================================================

export function benchmark_poly1305_128kb(iterations: i32): void {
  runBenchmark(128 * 1024, iterations)
}

export function benchmark_poly1305_1mb(iterations: i32): void {
  runBenchmark(1024 * 1024, iterations)
}

export function benchmark_poly1305_10mb(iterations: i32): void {
  runBenchmark(10 * 1024 * 1024, iterations)
}