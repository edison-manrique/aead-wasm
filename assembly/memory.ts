/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  memory.ts — Gestión de memoria plana del módulo WASM (aead-wasm)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Toda la memoria del módulo es PLANA y estática: se reserva en el data
 * segment en tiempo de compilación (`memory.data`), NUNCA toca el heap del
 * runtime y NUNCA crece bajo carga. Compatible con runtime `stub` (el módulo
 * no usa `new` de objetos managed: solo `changetype` sobre estas regiones).
 *
 * Dos zonas con propósitos distintos:
 *
 *  ┌─────────────┬──────────────┬──────────────────────────────────────────┐
 *  │ Zona        │ Tamaño       │ Uso                                      │
 *  ├─────────────┼──────────────┼──────────────────────────────────────────┤
 *  │ ARENA       │ 64 KB        │ Trabajo interno: contextos ChaCha20/     │
 *  │             │              │ Poly1305/AEAD y buffers pequeños.        │
 *  │             │              │ Bump allocator con save/restore.         │
 *  ├─────────────┼──────────────┼──────────────────────────────────────────┤
 *  │ PARAM_IN    │ 1 MB         │ Entrada de cifrado/descifrado (plaintext │
 *  │             │              │ o ciphertext del usuario).               │
 *  ├─────────────┼──────────────┼──────────────────────────────────────────┤
 *  │ PARAM_OUT   │ 1 MB + 64 B  │ Salida (ciphertext ‖ tag). El +64 da     │
 *  │             │              │ margen para el tag (16 B) y alineación.  │
 *  └─────────────┴──────────────┴──────────────────────────────────────────┘
 *
 * ¿Por qué 1 MB por buffer? Reservados UNA sola vez al cargar, permiten:
 *  • one-shot veloz de mensajes de hasta 1 MB en una única llamada WASM
 *    (sin copias intermedias ni chunking), y
 *  • streaming por chunks de 1 MB para archivos arbitrariamente grandes
 *    (el wrapper reusa estas mismas regiones → memoria plana total).
 *  Ajustable vía IO_BUFFER_SIZE (1–2 MB o más según se prefiera velocidad
 *  vs tamaño de binario; el data segment se incluye en el .wasm).
 */

// ── Arena de trabajo (contextos y buffers pequeños) ─────────────────────────
export const ARENA_SIZE: usize = 65536 // 64 KB
const ARENA_BASE: usize = memory.data(<i32>ARENA_SIZE)

// ── I/O plano de cifrado/descifrado (reservado una sola vez) ────────────────
export const IO_BUFFER_SIZE: usize = 1 << 20 // 1 MB por buffer (ajustable)
export const PARAM_IN_SIZE: usize = IO_BUFFER_SIZE
export const PARAM_OUT_SIZE: usize = IO_BUFFER_SIZE + 64 // +tag (16 B) + margen
export const PARAM_IN_PTR: usize = memory.data(<i32>PARAM_IN_SIZE)
export const PARAM_OUT_PTR: usize = memory.data(<i32>PARAM_OUT_SIZE)

/** Redondea un puntero al siguiente múltiplo de 8 (alineación para u64). */
// @ts-ignore
@inline
export function align8(ptr: usize): usize {
  return (ptr + 7) & ~7
}

// ── Alocador de la ARENA (bump-pointer con save/restore) ────────────────────
// Solo opera sobre [ARENA_BASE, ARENA_BASE + ARENA_SIZE). PARAM_IN/OUT quedan
// fuera: los gestiona el wrapper (copia los datos del usuario allí).
// @ts-ignore
@final
export class Memory {
  static current: usize = ARENA_BASE

  /**
   * Reserva `size` bytes alineados a 8 de la arena de trabajo.
   * @throws unreachable (trap) si se excede ARENA_SIZE — red de seguridad;
   *         con save/restore por operación el uso real es ~500 B, nunca cerca.
   */
  @inline
  static alloc(size: usize): usize {
    const ptr = align8(Memory.current)
    const next = ptr + size
    if (next > ARENA_BASE + ARENA_SIZE) unreachable()
    Memory.current = next
    return ptr
  }

  @inline
  static reset(): void {
    Memory.current = ARENA_BASE
  }

  @inline
  static save(): usize {
    return Memory.current
  }

  @inline
  static restore(savedPtr: usize): void {
    Memory.current = savedPtr
  }
}