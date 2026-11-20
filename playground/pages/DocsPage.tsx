import { createMemo, createSignal, For, Show } from "solid-js"
import { Copy, Check } from "lucide-solid"
import type { AlgoPageMeta } from "../types/crypto"
import { tokenizeCode, type TokenKind } from "../utils/syntaxHighlight"
import shared from "../styles/PageShared.module.css"
import styles from "./DocsPage.module.css"

interface DocsPageProps {
  meta: AlgoPageMeta
}

interface CodeBlockProps {
  lang: string
  code: string
}

function tokenClass(kind: TokenKind): string {
  switch (kind) {
    case "keyword":
      return styles.tokKeyword
    case "string":
      return styles.tokString
    case "comment":
      return styles.tokComment
    case "type":
      return styles.tokType
    case "fn":
      return styles.tokFn
    case "number":
      return styles.tokNumber
    case "operator":
      return styles.tokOperator
    default:
      return styles.tokPlain
  }
}

function CodeBlock(props: CodeBlockProps) {
  const [copied, setCopied] = createSignal(false)
  const tokens = createMemo(() => tokenizeCode(props.code, props.lang))

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(props.code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch {
      // Clipboard no disponible
    }
  }

  return (
    <div class={styles.codeWrap}>
      <div class={styles.codeBar}>
        <span class={styles.codeLang}>{props.lang}</span>
        <button type="button" class={styles.copyBtn} onClick={handleCopy}>
          <Show when={copied()} fallback={<Copy size={10} />}>
            <Check size={10} />
          </Show>
          <span>{copied() ? "Copiado" : "Copiar"}</span>
        </button>
      </div>
      <pre class={styles.pre}>
        <code>
          <For each={tokens()}>
            {(tok) => <span class={tokenClass(tok.kind)}>{tok.text}</span>}
          </For>
        </code>
      </pre>
    </div>
  )
}

const INIT_ST_SNIPPET = `import { AeadWasm } from "aead-wasm"

// ── Single-Thread (dist/aead.wasm, 8.1 KB) ──
// Navegador / bundler (carga única del singleton)
await AeadWasm.load()

// Node.js / Bun desde buffer binario explícito
import { readFileSync } from "node:fs"
const stBuf = readFileSync("node_modules/aead-wasm/dist/aead.wasm")
await AeadWasm.fromBuffer(stBuf)`

const INIT_MT_SNIPPET = `import { AeadWasm } from "aead-wasm"

// ── Multithread (dist/aead.mt.wasm, 9.1 KB) ──
// Navegador (requiere COOP/COEP para SharedArrayBuffer)
const wasm = await AeadWasm.loadThreaded("/aead.mt.wasm")

// Node.js / Worker: compartir módulo + memoria lineal
import { Worker } from "node:worker_threads"
const worker = new Worker("./crypto-worker.mjs", {
  workerData: {
    wasmModule: wasm.getModule(),
    sharedMemory: wasm.getMemory() // WebAssembly.Memory (shared: true)
  }
})`

const WORKER_MT_SNIPPET = `// crypto-worker.ts (Web Worker o node:worker_threads)
import { workerData, parentPort } from "node:worker_threads"
import { AeadWasm, ChaCha20Poly1305 } from "aead-wasm"

const { wasmModule, sharedMemory, key, nonce, data } = workerData

// Instancia usando la MISMA SharedArrayBuffer del hilo principal
// (--zeroFilledMemory evita borrar datos activos y arena_lock sincroniza I/O)
await AeadWasm.fromModule(wasmModule, {
  env: { memory: sharedMemory }
})

const sealed = ChaCha20Poly1305.encrypt(key, nonce, data, "worker-aad")
parentPort!.postMessage(sealed)`

const LOCK_SNIPPET = `import { AeadWasm } from "aead-wasm"

const wasm = AeadWasm.getInstance()
console.log(wasm.getArenaStats())
// → { used: 0, capacity: 65536, locked: false, threaded: true }

// Lock manual opcional al operar directo sobre WasmAllocator:
// • ST: tryLock() retorna false (y lock() lanza Error) si está ocupado
// • MT: lock() espera en spinlock atómico hasta que el otro hilo libere
if (wasm.tryLock()) {
  try {
    wasm.getAllocator().writeInput(new Uint8Array([1, 2, 3, 4]), 0)
  } finally {
    wasm.unlock()
  }
}`

const AEAD_SNIPPET = `import {
  AeadWasm, ChaCha20Poly1305, XChaCha20Poly1305,
  randomKey, randomNonce, randomXNonce
} from "aead-wasm"

await AeadWasm.load()

const key = randomKey()        // 32 B
const nonce = randomNonce()    // 12 B (o randomXNonce() = 24 B)

// Cifrado autenticado → combined (ciphertext ‖ tag)
const sealed = ChaCha20Poly1305.encrypt(key, nonce, "secreto", "aad")
const plain  = ChaCha20Poly1305.decrypt(key, nonce, sealed, "aad")

// Formato detached (ciphertext y tag de 16 B por separado)
const { ciphertext, tag } = XChaCha20Poly1305.encryptDetached(
  key, randomXNonce(), "secreto"
)`

const STREAM_SNIPPET = `import { ChaCha20Poly1305, concatBytes } from "aead-wasm"

// Cifrado streaming (memoria plana por chunks de 1 MB)
const enc = ChaCha20Poly1305.createEncryptStream(key, nonce, aad)
const out: Uint8Array[] = []
for (const chunk of chunks) out.push(enc.update(chunk))
out.push(enc.final()) // tag de 16 B al final

// Descifrado streaming: verifica el tag al cierre
const dec = ChaCha20Poly1305.createDecryptStream(key, nonce, aad)
const pt: Uint8Array[] = []
for (const chunk of ctChunks) pt.push(dec.update(chunk))
if (!dec.final(tag)) throw new Error("Tag inválido")
const plaintext = concatBytes(...pt)`

const PRIMITIVES_SNIPPET = `import { ChaCha20, XChaCha20, Poly1305, bytesToHex } from "aead-wasm"

// Cifrado de flujo puro (XOR simétrico)
const ct = ChaCha20.encrypt(key, nonce12, "datos", 0)
const pt = ChaCha20.decrypt(key, nonce12, ct, 0)

// MAC Poly1305 one-shot (tag de 16 bytes)
const mac = Poly1305.mac(key, "mensaje a autenticar")
console.log(bytesToHex(mac)) // → 32 chars hex`

export function DocsPage(props: DocsPageProps) {
  return (
    <div class={shared.page}>
      <p class={shared.description}>{props.meta.description}</p>

      <div class={styles.grid}>
        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>1. Instalación e init Single-Thread</h2>
            <span class={styles.cardTag}>aead.wasm · 8.1 KB</span>
          </div>
          <p class={styles.prose}>
            Usa la variante single-thread por defecto cuando operes en el hilo principal o quieras cero overhead de instrucciones atómicas.
          </p>
          <CodeBlock lang="bash" code="npm install aead-wasm" />
          <CodeBlock lang="typescript" code={INIT_ST_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>2. Inicialización Multithread (MT)</h2>
            <span class={styles.cardTag}>aead.mt.wasm · 9.1 KB</span>
          </div>
          <p class={styles.prose}>
            Carga el binario con soporte de hilos y <code style={{ color: "var(--gold-mono)" }}>SharedArrayBuffer</code> para compartir la memoria lineal entre múltiples workers sin duplicarla.
          </p>
          <CodeBlock lang="typescript" code={INIT_MT_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>3. Ejecución en Workers (MT)</h2>
            <span class={styles.cardTag}>SharedArrayBuffer</span>
          </div>
          <p class={styles.prose}>
            Cada worker instancia el módulo mediante <code style={{ color: "var(--gold-mono)" }}>AeadWasm.fromModule()</code> reutilizando la misma memoria compartida de 34 páginas.
          </p>
          <CodeBlock lang="typescript" code={WORKER_MT_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>4. Lock de Memoria y Arena</h2>
            <span class={styles.cardTag}>arena_lock · Zero-Alloc</span>
          </div>
          <p class={styles.prose}>
            El wrapper adquiere el lock automáticamente en cada operación. En modo MT usa spinlock atómico; en modo ST evita sobreescrituras lanzando un error si la memoria está ocupada.
          </p>
          <CodeBlock lang="typescript" code={LOCK_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>5. AEAD (ChaCha20 / XChaCha20-Poly1305)</h2>
            <span class={styles.cardTag}>RFC 8439</span>
          </div>
          <p class={styles.prose}>
            Proporciona confidencialidad e integridad en una sola operación. Si el tag falla la verificación
            constant-time, <code style={{ color: "var(--gold-mono)" }}>decrypt</code> retorna{" "}
            <code style={{ color: "var(--gold-mono)" }}>null</code> sin exponer datos.
          </p>
          <CodeBlock lang="typescript" code={AEAD_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>6. Streaming de archivos por chunks</h2>
            <span class={styles.cardTag}>Zero-Alloc · 1 MB</span>
          </div>
          <p class={styles.prose}>
            Procesa archivos de cualquier tamaño reutilizando los buffers estáticos{" "}
            <code style={{ color: "var(--gold-mono)" }}>PARAM_IN</code> /{" "}
            <code style={{ color: "var(--gold-mono)" }}>PARAM_OUT</code> de 1 MB sin presionar al Garbage Collector.
          </p>
          <CodeBlock lang="typescript" code={STREAM_SNIPPET} />
        </section>

        <section class={`${styles.card} ${styles.cardFull}`}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>7. Flujo puro (ChaCha20 / XChaCha20) y MAC Poly1305</h2>
            <span class={styles.cardTag}>CSPRNG + Hex</span>
          </div>
          <p class={styles.prose}>
            Usa <code style={{ color: "var(--gold-mono)" }}>ChaCha20</code> /{" "}
            <code style={{ color: "var(--gold-mono)" }}>XChaCha20</code> para cifrado de flujo con contador explícito, y{" "}
            <code style={{ color: "var(--gold-mono)" }}>Poly1305</code> para generar tags de 16 bytes.
          </p>
          <CodeBlock lang="typescript" code={PRIMITIVES_SNIPPET} />
        </section>

        <section class={`${styles.card} ${styles.cardFull}`}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>Comparativa de binarios: Single-Thread vs Multithread</h2>
            <span class={styles.cardTag}>Arena · asconfig.json</span>
          </div>
          <div class={styles.tableWrap}>
            <table class={styles.table}>
              <thead>
                <tr>
                  <th>Binario</th>
                  <th>Target</th>
                  <th>Tamaño</th>
                  <th>Memoria</th>
                  <th>Modelo de Lock</th>
                  <th>Uso recomendado</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td class={styles.nameCell}>dist/aead.wasm</td>
                  <td class={styles.monoCell}>release</td>
                  <td class={styles.monoCell}>8.1 KB</td>
                  <td>ArrayBuffer (34 págs)</td>
                  <td>Guardia reentrada JS/WASM (fail-fast)</td>
                  <td>Hilo principal, SSR/Node o Workers independientes</td>
                </tr>
                <tr>
                  <td class={styles.nameCell}>dist/aead.mt.wasm</td>
                  <td class={styles.monoCell}>release-mt</td>
                  <td class={styles.monoCell}>9.1 KB</td>
                  <td>SharedArrayBuffer (importada)</td>
                  <td>Spinlock atómico (atomic.cmpxchg)</td>
                  <td>Pool de Workers compartiendo la misma memoria WASM</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class={`${styles.card} ${styles.cardFull}`}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>Referencia rápida de parámetros y longitudes</h2>
            <span class={styles.cardTag}>Especificación RFC 8439</span>
          </div>
          <div class={styles.tableWrap}>
            <table class={styles.table}>
              <thead>
                <tr>
                  <th>Primitiva</th>
                  <th>Tipo</th>
                  <th>Clave</th>
                  <th>Nonce</th>
                  <th>Tag</th>
                  <th>Streaming archivos</th>
                  <th>Uso recomendado</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td class={styles.nameCell}>ChaCha20-Poly1305</td>
                  <td>AEAD</td>
                  <td class={styles.monoCell}>32 B</td>
                  <td class={styles.monoCell}>12 B</td>
                  <td class={styles.monoCell}>16 B</td>
                  <td>Nativo (chunks 1 MB)</td>
                  <td>Estándar principal cuando el nonce es secuencial o único</td>
                </tr>
                <tr>
                  <td class={styles.nameCell}>XChaCha20-Poly1305</td>
                  <td>AEAD</td>
                  <td class={styles.monoCell}>32 B</td>
                  <td class={styles.monoCell}>24 B</td>
                  <td class={styles.monoCell}>16 B</td>
                  <td>Nativo (chunks 1 MB)</td>
                  <td>Ideal para nonces aleatorios con randomXNonce()</td>
                </tr>
                <tr>
                  <td class={styles.nameCell}>ChaCha20</td>
                  <td>Stream Cipher</td>
                  <td class={styles.monoCell}>32 B</td>
                  <td class={styles.monoCell}>12 B</td>
                  <td class={styles.monoCell}>—</td>
                  <td>Por bloques (counter)</td>
                  <td>Generación de keystream o cifrado sin MAC integrado</td>
                </tr>
                <tr>
                  <td class={styles.nameCell}>XChaCha20</td>
                  <td>Stream Cipher</td>
                  <td class={styles.monoCell}>32 B</td>
                  <td class={styles.monoCell}>24 B</td>
                  <td class={styles.monoCell}>—</td>
                  <td>Por bloques (counter)</td>
                  <td>Flujo extendido con subclave HChaCha20</td>
                </tr>
                <tr>
                  <td class={styles.nameCell}>Poly1305</td>
                  <td>MAC</td>
                  <td class={styles.monoCell}>32 B</td>
                  <td class={styles.monoCell}>—</td>
                  <td class={styles.monoCell}>16 B</td>
                  <td>One-shot (~1 MB máx.)</td>
                  <td>Autenticación rápida de mensajes con clave de un solo uso</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  )
}
