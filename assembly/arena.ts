/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  arena.ts — Gestión de memoria plana y Arena estática (single & multithread)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Toda la memoria del módulo es PLANA y estática: se reserva en el data
 * segment en tiempo de compilación (`memory.data`), NUNCA toca el heap del
 * runtime y NUNCA crece bajo carga. Compatible con runtime `stub`.
 *
 * Soporta dos modos de compilación mediante `ASC_FEATURE_THREADS`:
 *  • Single-thread (`dist/aead.wasm`): puntero de arena en global WASM y lock
 *    de reentrada rápido sin instrucciones atómicas.
 *  • Multithread (`dist/aead.mt.wasm`, `--enable threads --sharedMemory`):
 *    puntero de arena en memoria lineal compartida y spinlocks atómicos
 *    (`atomic.cmpxchg` / `atomic.store` / `atomic.load`) para evitar que dos
 *    hilos sobreescriban `ARENA`, `PARAM_IN` o `PARAM_OUT` simultáneamente.
 */

// ── Arena de trabajo (contextos y buffers pequeños) ─────────────────────────
export const ARENA_SIZE: usize = 65536 // 64 KB
const ARENA_BASE: usize = (memory.data(<i32>(ARENA_SIZE + 8)) + 7) & ~7

// ── Estado compartido en memoria lineal (locks + puntero MT alineados a 8 B) ─
const CTRL_BASE: usize = (memory.data(32) + 7) & ~7
const IO_LOCK_PTR: usize = CTRL_BASE // 0 = libre, 1 = ocupado (I/O + memoria)
const ARENA_LOCK_PTR: usize = CTRL_BASE + 8 // spinlock interno de Arena.alloc/restore
const ARENA_OFF_PTR: usize = CTRL_BASE + 16 // offset actual de Arena en modo MT

// ── I/O plano de cifrado/descifrado (reservado una sola vez) ────────────────
export const IO_BUFFER_SIZE: usize = 1 << 20 // 1 MB por buffer
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

/**
 * Clase estática `Arena`: alocador bump-pointer con save/restore y bloqueo
 * contra sobreescrituras concurrentes.
 */
// @ts-ignore
@final
export class Arena {
  private static current: usize = ARENA_BASE

  // ── Lectura/escritura del puntero actual (ST en global, MT en memoria) ────
  // @ts-ignore
  @inline
  private static getCurrentPtr(): usize {
    if (ASC_FEATURE_THREADS) {
      return ARENA_BASE + <usize>atomic.load<u32>(ARENA_OFF_PTR)
    }
    return Arena.current
  }

  // @ts-ignore
  @inline
  private static setCurrentPtr(ptr: usize): void {
    if (ASC_FEATURE_THREADS) {
      atomic.store<u32>(ARENA_OFF_PTR, <u32>(ptr - ARENA_BASE))
    } else {
      Arena.current = ptr
    }
  }

  // ── Spinlock interno para operaciones sobre el bump-pointer (solo MT) ─────
  // @ts-ignore
  @inline
  private static acquireArenaSpin(): void {
    if (ASC_FEATURE_THREADS) {
      while (atomic.cmpxchg<i32>(ARENA_LOCK_PTR, 0, 1) != 0) {
        // spin-wait atómico
      }
    }
  }

  // @ts-ignore
  @inline
  private static releaseArenaSpin(): void {
    if (ASC_FEATURE_THREADS) {
      atomic.store<i32>(ARENA_LOCK_PTR, 0)
    }
  }

  // ── Lock público de memoria I/O + trabajo (evita sobreescrituras) ─────────

  /**
   * Adquiere el lock exclusivo sobre la memoria de trabajo (`PARAM_IN`/`OUT`
   * y `Arena`). En modo multithread espera en spinlock atómico; en modo
   * single-thread atrapa (`unreachable`) si se intenta reentrar estando ocupado.
   */
  // @ts-ignore
  @inline
  static lock(): void {
    if (ASC_FEATURE_THREADS) {
      while (atomic.cmpxchg<i32>(IO_LOCK_PTR, 0, 1) != 0) {
        // spin-wait atómico hasta que el otro hilo libere
      }
    } else {
      if (load<i32>(IO_LOCK_PTR) != 0) unreachable()
      store<i32>(IO_LOCK_PTR, 1)
    }
  }

  /**
   * Intenta adquirir el lock sin bloquear.
   * @returns `true` si se adquirió el lock, `false` si ya está ocupado.
   */
  // @ts-ignore
  @inline
  static tryLock(): bool {
    if (ASC_FEATURE_THREADS) {
      return atomic.cmpxchg<i32>(IO_LOCK_PTR, 0, 1) == 0
    }
    if (load<i32>(IO_LOCK_PTR) != 0) return false
    store<i32>(IO_LOCK_PTR, 1)
    return true
  }

  /** Libera el lock exclusivo de memoria. */
  // @ts-ignore
  @inline
  static unlock(): void {
    if (ASC_FEATURE_THREADS) {
      atomic.store<i32>(IO_LOCK_PTR, 0)
    } else {
      store<i32>(IO_LOCK_PTR, 0)
    }
  }

  /** Indica si la memoria está bloqueada por una operación en curso. */
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

  // ── Bump allocator (zero-alloc) ───────────────────────────────────────────

  /**
   * Reserva `size` bytes alineados a 8 en la arena de trabajo.
   * Protegido internamente en multithread para evitar colisiones del puntero.
   */
  // @ts-ignore
  @inline
  static alloc(size: usize): usize {
    Arena.acquireArenaSpin()
    const ptr = align8(Arena.getCurrentPtr())
    const next = ptr + size
    if (next > ARENA_BASE + ARENA_SIZE) {
      Arena.releaseArenaSpin()
      unreachable()
    }
    Arena.setCurrentPtr(next)
    Arena.releaseArenaSpin()
    return ptr
  }

  /** Guarda la posición actual del puntero de la arena. */
  // @ts-ignore
  @inline
  static save(): usize {
    Arena.acquireArenaSpin()
    const ptr = Arena.getCurrentPtr()
    Arena.releaseArenaSpin()
    return ptr
  }

  /** Restaura el puntero de la arena a un marcador previo (libera el marco). */
  // @ts-ignore
  @inline
  static restore(savedPtr: usize): void {
    Arena.acquireArenaSpin()
    if (savedPtr >= ARENA_BASE && savedPtr <= ARENA_BASE + ARENA_SIZE) {
      Arena.setCurrentPtr(savedPtr)
    }
    Arena.releaseArenaSpin()
  }

  /** Reinicia la arena a su base inicial. */
  // @ts-ignore
  @inline
  static reset(): void {
    Arena.acquireArenaSpin()
    Arena.setCurrentPtr(ARENA_BASE)
    Arena.releaseArenaSpin()
  }

  /** Bytes actualmente reservados en la arena. */
  // @ts-ignore
  @inline
  static used(): usize {
    Arena.acquireArenaSpin()
    const u = Arena.getCurrentPtr() - ARENA_BASE
    Arena.releaseArenaSpin()
    return u
  }

  /** Capacidad total de la arena en bytes. */
  // @ts-ignore
  @inline
  static capacity(): usize {
    return ARENA_SIZE
  }
}
