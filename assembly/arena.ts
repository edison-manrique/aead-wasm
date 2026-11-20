/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  arena.ts — Gestión de memoria plana y Arena estática (ST & Multi-Slot MT)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Toda la memoria del módulo es PLANA y estática: se reserva en tiempo de
 * compilación (`memory.data`), NUNCA toca el heap del runtime y NUNCA crece
 * bajo carga. Compatible con runtime `stub`.
 *
 * Arquitectura por compilación condicional (`ASC_FEATURE_THREADS`):
 *  • Single-thread (`dist/aead.wasm`, 1 slot, 34 págs ≈ 2.1 MB):
 *    - 1 región PARAM_IN (1 MB) + 1 región PARAM_OUT (1 MB + 64 B) + Arena 64 KB.
 *    - Cero instrucciones atómicas; guardia fail-fast contra reentrada.
 *
 *  • Multithread (`dist/aead.mt.wasm`, 8 slots paralelos, 264 págs ≈ 16.5 MB):
 *    - Cada slot `s` posee SU PROPIA región `PARAM_IN[s]`, `PARAM_OUT[s]` y su
 *      propio segmento de Arena (16 KB/slot).
 *    - Un `slotLock[s]` atómico garantiza acceso exclusivo al slot `s`.
 *    - Una vez adquirido el slot, `Arena.save()/alloc()/restore()` operan 100%
 *      sobre la variable global thread-local `Arena.current` SIN instrucciones
 *      atómicas dentro del hot-path criptográfico.
 *    - Resultado: N workers en paralelo operan en slots distintos con 0% de
 *      contención y escalado multi-core real.
 */

// ── Configuración de Slots (1 en ST, 8 en MT) ───────────────────────────────
export const MT_SLOTS: i32 = 8
export const SLOT_COUNT: i32 = ASC_FEATURE_THREADS ? MT_SLOTS : 1

export const ARENA_SIZE: usize = ASC_FEATURE_THREADS ? 16384 : 65536 // 16 KB/slot en MT · 64 KB en ST
const ARENA_BASE: usize = (memory.data(<i32>(<usize>SLOT_COUNT * ARENA_SIZE + 8)) + 7) & ~7

// ── Control compartido en memoria lineal (locks + hints + offsets de arena) ─
// Layout CTRL_BASE:
//   [0 .. SLOT_COUNT*4)          → i32 slotLock[s] (0 = libre, 1 = ocupado)
//   [SLOT_COUNT*4 .. +4)         → i32 workerHintCounter (asignación round-robin de slot)
const CTRL_BYTES: i32 = SLOT_COUNT * 4 + 16
const CTRL_BASE: usize = (memory.data(CTRL_BYTES) + 7) & ~7
const IO_LOCK_PTR: usize = CTRL_BASE // alias Slot 0
const WORKER_HINT_PTR: usize = CTRL_BASE + <usize>(SLOT_COUNT << 2)
const ARENA_OFF_BASE: usize = (memory.data(SLOT_COUNT * 4 + 8) + 7) & ~7

// ── I/O plano de cifrado/descifrado (1 región por slot) ─────────────────────
export const IO_BUFFER_SIZE: usize = 1 << 20 // 1 MB por buffer
export const PARAM_IN_SIZE: usize = IO_BUFFER_SIZE
export const PARAM_OUT_SIZE: usize = IO_BUFFER_SIZE + 64 // +tag (16 B) + margen
const SLOT_IO_STRIDE: usize = PARAM_IN_SIZE + PARAM_OUT_SIZE
const IO_BASE: usize = memory.data(<i32>(<usize>SLOT_COUNT * SLOT_IO_STRIDE))

// Punteros del Slot 0 exportados por compatibilidad directa
export const PARAM_IN_PTR: usize = IO_BASE
export const PARAM_OUT_PTR: usize = IO_BASE + PARAM_IN_SIZE

/** Redondea un puntero al siguiente múltiplo de 8 (alineación para u64). */
// @ts-ignore
@inline
export function align8(ptr: usize): usize {
  return (ptr + 7) & ~7
}

/**
 * Clase estática `Arena`: alocador bump-pointer con save/restore, aislamiento
 * por slot en multithread y bloqueo contra sobreescrituras concurrentes.
 */
// @ts-ignore
@final
export class Arena {
  // En WASM con threads, las globales (static fields) son thread-local por instancia.
  private static activeSlot: i32 = 0
  private static current: usize = ARENA_BASE
  private static slotBase: usize = ARENA_BASE
  private static slotLimit: usize = ARENA_BASE + ARENA_SIZE

  // @ts-ignore
  @inline
  static slotArenaBase(slot: i32): usize {
    if (!ASC_FEATURE_THREADS) return ARENA_BASE
    return ARENA_BASE + <usize>slot * ARENA_SIZE
  }

  // @ts-ignore
  @inline
  static slotInPtr(slot: i32): usize {
    if (!ASC_FEATURE_THREADS) return PARAM_IN_PTR
    return IO_BASE + <usize>slot * SLOT_IO_STRIDE
  }

  // @ts-ignore
  @inline
  static slotOutPtr(slot: i32): usize {
    if (!ASC_FEATURE_THREADS) return PARAM_OUT_PTR
    return IO_BASE + <usize>slot * SLOT_IO_STRIDE + PARAM_IN_SIZE
  }

  // @ts-ignore
  @inline
  static slotForPtr(ptr: usize): i32 {
    if (!ASC_FEATURE_THREADS) return 0
    if (ptr < ARENA_BASE) return 0
    const rel = ptr - ARENA_BASE
    const slot = <i32>(rel / ARENA_SIZE)
    return slot >= 0 && slot < SLOT_COUNT ? slot : 0
  }

  /**
   * Activa el slot `slot` en este hilo y sincroniza el puntero de arena local
   * desde memoria compartida (sin atómicos: protegido por `slotLock[slot]`).
   */
  // @ts-ignore
  @inline
  static useSlot(slot: i32): void {
    if (slot < 0 || slot >= SLOT_COUNT) unreachable()
    Arena.activeSlot = slot
    if (ASC_FEATURE_THREADS) {
      const base = Arena.slotArenaBase(slot)
      Arena.slotBase = base
      Arena.slotLimit = base + ARENA_SIZE
      Arena.current = base + <usize>load<u32>(ARENA_OFF_BASE + <usize>(slot << 2))
    }
  }

  /** Persiste el offset actual de la arena del slot activo antes de liberar el lock. */
  // @ts-ignore
  @inline
  static syncSlot(): void {
    if (ASC_FEATURE_THREADS) {
      const slot = Arena.activeSlot
      const base = Arena.slotArenaBase(slot)
      store<u32>(ARENA_OFF_BASE + <usize>(slot << 2), <u32>(Arena.current - base))
    }
  }

  // ── Locks de memoria por slot (y compatibilidad Slot 0) ──────────────────

  // @ts-ignore
  @inline
  static lockSlot(slot: i32): void {
    if (slot < 0 || slot >= SLOT_COUNT) unreachable()
    const ptr = CTRL_BASE + <usize>(slot << 2)
    if (ASC_FEATURE_THREADS) {
      while (atomic.cmpxchg<i32>(ptr, 0, 1) != 0) {
        // spin-wait atómico hasta que el otro hilo libere el slot
      }
      Arena.useSlot(slot)
    } else {
      if (load<i32>(ptr) != 0) unreachable()
      store<i32>(ptr, 1)
    }
  }

  // @ts-ignore
  @inline
  static tryLockSlot(slot: i32): bool {
    if (slot < 0 || slot >= SLOT_COUNT) return false
    const ptr = CTRL_BASE + <usize>(slot << 2)
    if (ASC_FEATURE_THREADS) {
      if (atomic.cmpxchg<i32>(ptr, 0, 1) == 0) {
        Arena.useSlot(slot)
        return true
      }
      return false
    }
    if (load<i32>(ptr) != 0) return false
    store<i32>(ptr, 1)
    return true
  }

  // @ts-ignore
  @inline
  static unlockSlot(slot: i32): void {
    if (slot < 0 || slot >= SLOT_COUNT) return
    const ptr = CTRL_BASE + <usize>(slot << 2)
    if (ASC_FEATURE_THREADS) {
      Arena.syncSlot()
      atomic.store<i32>(ptr, 0)
    } else {
      store<i32>(ptr, 0)
    }
  }

  /** Adquiere el lock del Slot 0 (`PARAM_IN_PTR`/`PARAM_OUT_PTR`). */
  // @ts-ignore
  @inline
  static lock(): void {
    Arena.lockSlot(0)
  }

  /** Intenta adquirir el lock del Slot 0 sin bloquear. */
  // @ts-ignore
  @inline
  static tryLock(): bool {
    return Arena.tryLockSlot(0)
  }

  /** Libera el lock del Slot 0. */
  // @ts-ignore
  @inline
  static unlock(): void {
    Arena.unlockSlot(0)
  }

  /** Indica si el Slot 0 está bloqueado por una operación en curso. */
  // @ts-ignore
  @inline
  static isLocked(): bool {
    if (ASC_FEATURE_THREADS) {
      return atomic.load<i32>(IO_LOCK_PTR) != 0
    }
    return load<i32>(IO_LOCK_PTR) != 0
  }

  /** Indica si el binario fue compilado con soporte multithread (`threads`). */
  // @ts-ignore
  @inline
  static isThreaded(): bool {
    return ASC_FEATURE_THREADS
  }

  // @ts-ignore
  @inline
  static ctrlPtr(): usize {
    return CTRL_BASE
  }

  // @ts-ignore
  @inline
  static workerHintPtr(): usize {
    return WORKER_HINT_PTR
  }

  // @ts-ignore
  @inline
  static offPtr(): usize {
    return ARENA_OFF_BASE
  }

  // @ts-ignore
  @inline
  static slotCount(): i32 {
    return SLOT_COUNT
  }

  // ── Bump allocator (zero-alloc, CERO atómicos dentro del slot activo) ─────

  /** Reserva `size` bytes alineados a 8 en la arena del slot activo. */
  // @ts-ignore
  @inline
  static alloc(size: usize): usize {
    const ptr = align8(Arena.current)
    const next = ptr + size
    if (next > Arena.slotLimit) unreachable()
    Arena.current = next
    return ptr
  }

  /** Guarda la posición actual del puntero de la arena. */
  // @ts-ignore
  @inline
  static save(): usize {
    return Arena.current
  }

  /** Restaura el puntero de la arena a un marcador previo (libera el marco). */
  // @ts-ignore
  @inline
  static restore(savedPtr: usize): void {
    if (savedPtr >= Arena.slotBase && savedPtr <= Arena.slotLimit) {
      Arena.current = savedPtr
    }
  }

  /** Reinicia la arena del slot activo (y tabla de offsets en MT). */
  // @ts-ignore
  @inline
  static reset(): void {
    if (ASC_FEATURE_THREADS) {
      for (let s: i32 = 0; s < SLOT_COUNT; s++) {
        store<u32>(ARENA_OFF_BASE + <usize>(s << 2), 0)
      }
      const base = Arena.slotArenaBase(Arena.activeSlot)
      Arena.slotBase = base
      Arena.slotLimit = base + ARENA_SIZE
      Arena.current = base
    } else {
      Arena.current = ARENA_BASE
    }
  }

  /** Bytes actualmente reservados en la arena (total en MT o activo en ST). */
  // @ts-ignore
  @inline
  static used(): usize {
    if (ASC_FEATURE_THREADS) {
      let total: usize = 0
      const active = Arena.activeSlot
      for (let s: i32 = 0; s < SLOT_COUNT; s++) {
        if (s == active) {
          total += Arena.current - Arena.slotArenaBase(s)
        } else {
          total += <usize>load<u32>(ARENA_OFF_BASE + <usize>(s << 2))
        }
      }
      return total
    }
    return Arena.current - ARENA_BASE
  }

  /** Capacidad de arena por slot en bytes. */
  // @ts-ignore
  @inline
  static capacity(): usize {
    return ARENA_SIZE
  }
}
