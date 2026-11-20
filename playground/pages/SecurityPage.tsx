import { AlertTriangle, ShieldCheck, ShieldAlert, KeyRound, Lock, Eraser, Cpu, GlobeLock } from "lucide-solid"
import type { AlgoPageMeta } from "../types/crypto"
import shared from "../styles/PageShared.module.css"
import styles from "./SecurityPage.module.css"

interface SecurityPageProps {
  meta: AlgoPageMeta
}

export function SecurityPage(props: SecurityPageProps) {
  return (
    <div class={shared.page}>
      <p class={shared.description}>{props.meta.description}</p>

      <div class={styles.grid}>
        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconWarn}>
                <AlertTriangle size={15} />
              </span>
              <h2 class={styles.cardTitle}>ChaCha20 / XChaCha20 sin autenticación</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelWarn}`}>Maleable</span>
          </div>
          <p class={styles.body}>
            ChaCha20 y XChaCha20 por sí solos son cifradores de flujo puros (XOR con keystream) y <strong>no autentican</strong>. Un atacante puede invertir bits del ciphertext y provocar cambios predecibles en el plaintext descifrado sin ser detectado.
          </p>
          <div class={styles.ruleBox}>
            Regla: para datos que requieran confidencialidad e integridad, usa siempre ChaCha20-Poly1305 o XChaCha20-Poly1305.
          </div>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconErr}>
                <ShieldAlert size={15} />
              </span>
              <h2 class={styles.cardTitle}>Unicidad del Nonce (12 B vs 24 B)</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelErr}`}>Crítico</span>
          </div>
          <p class={styles.body}>
            Reutilizar un mismo par (clave, nonce) destruye por completo la confidencialidad (revela el XOR de ambos plaintexts) y permite recuperar la clave de autenticación Poly1305.
          </p>
          <ul class={styles.list}>
            <li>
              <strong>ChaCha20-Poly1305 (12 B):</strong> usa contadores monotónicos o nonces deterministas únicos por clave.
            </li>
            <li>
              <strong>XChaCha20-Poly1305 (24 B):</strong> seguro para nonces aleatorios mediante <code>randomXNonce()</code>.
            </li>
          </ul>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconWarn}>
                <Lock size={15} />
              </span>
              <h2 class={styles.cardTitle}>Regla del Decrypt Streaming (RFC 8439)</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelWarn}`}>Streaming</span>
          </div>
          <p class={styles.body}>
            En un AEAD de tag único al final del flujo, <code>update(chunk)</code> devuelve bytes descifrados antes de leer el tag de 16 bytes. Ese plaintext aún no está autenticado.
          </p>
          <div class={styles.ruleBox}>
            Obligatorio: descarta todo el plaintext acumulado si stream.final(tag) retorna false.
          </div>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconOk}>
                <ShieldCheck size={15} />
              </span>
              <h2 class={styles.cardTitle}>Verificación Constant-Time y Wipe</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelOk}`}>Mitigado</span>
          </div>
          <p class={styles.body}>
            El núcleo WebAssembly implementa protecciones activas contra canales laterales y persistencia de material secreto en memoria lineal:
          </p>
          <ul class={styles.list}>
            <li>
              <strong>secureEqual16:</strong> compara el tag calculado mediante XOR + OR acumulativo de longitud fija (sin early-exit).
            </li>
            <li>
              <strong>wipe():</strong> sobrescribe con ceros keystream, subclaves HChaCha20 y estado de Poly1305 al finalizar o abortar (<code>free()</code>).
            </li>
          </ul>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconOk}>
                <Cpu size={15} />
              </span>
              <h2 class={styles.cardTitle}>Lock de Memoria en Arena (ST vs MT)</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelOk}`}>Concurrencia</span>
          </div>
          <p class={styles.body}>
            La clase estática <code>Arena</code> protege los buffers planos <code>PARAM_IN</code> y <code>PARAM_OUT</code> para evitar que una segunda llamada sobrescriba memoria mientras hay trabajo en curso:
          </p>
          <ul class={styles.list}>
            <li>
              <strong>Single-Thread (aead.wasm):</strong> <code>tryLock()</code> detecta colisión de I/O y lanza error inmediato antes de tocar <code>PARAM_IN</code>.
            </li>
            <li>
              <strong>Multithread (aead.mt.wasm):</strong> <code>arena_lock()</code> espera mediante spinlock atómico (<code>atomic.cmpxchg</code>) separado del spinlock interno del bump-pointer (sin self-deadlock).
            </li>
          </ul>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconWarn}>
                <GlobeLock size={15} />
              </span>
              <h2 class={styles.cardTitle}>Aislamiento Multithread (COOP / COEP)</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelWarn}`}>Browser MT</span>
          </div>
          <p class={styles.body}>
            La variante multithread (<code>aead.mt.wasm</code>) utiliza <code>SharedArrayBuffer</code>, por lo que en navegadores exige Cross-Origin Isolation. En Workers secundarios se compila con <code>--zeroFilledMemory</code> para que <code>fromModule()</code> nunca borre memoria activa.
          </p>
          <div class={styles.ruleBox}>
            Cross-Origin-Opener-Policy: same-origin · Cross-Origin-Embedder-Policy: require-corp
          </div>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconWarn}>
                <KeyRound size={15} />
              </span>
              <h2 class={styles.cardTitle}>Claves Poly1305 One-Time y CSPRNG</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelWarn}`}>Uso correcto</span>
          </div>
          <ul class={styles.list}>
            <li>
              <strong>Poly1305 standalone:</strong> la clave de 32 bytes (<code>r ‖ s</code>) debe usarse una sola vez por mensaje; nunca reutilices la misma clave en dos tags distintos.
            </li>
            <li>
              <strong>CSPRNG fail-fast:</strong> <code>randomKey()</code>, <code>randomNonce()</code> y <code>randomXNonce()</code> exigen <code>crypto.getRandomValues</code> y lanzan un error si el entorno carece de entropía segura.
            </li>
          </ul>
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <div class={styles.titleGroup}>
              <span class={styles.iconOk}>
                <Eraser size={15} />
              </span>
              <h2 class={styles.cardTitle}>Validación ST/MT y exención de auditoría</h2>
            </div>
            <span class={`${styles.levelText} ${styles.levelOk}`}>RFC 8439</span>
          </div>
          <p class={styles.body}>
            La correctitud está verificada en ambas compilaciones (<code>aead.wasm</code> y <code>aead.mt.wasm</code>) contra vectores oficiales RFC 8439, streaming &gt; 1 MB y 4 Worker Threads concurrentes compartiendo <code>SharedArrayBuffer</code> sin corrupción.
          </p>
          <div class={styles.ruleBox}>
            Aviso: esta implementación no cuenta con auditoría formal externa; evalúala de forma independiente antes de emplearla en infraestructura crítica.
          </div>
        </section>
      </div>
    </div>
  )
}
