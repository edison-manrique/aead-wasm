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

const INIT_SNIPPET = `import { AeadWasm } from "aead-wasm"

// Navegador / bundler (carga única del singleton)
await AeadWasm.load()

// Node.js / Bun desde buffer binario explícito
import { readFileSync } from "node:fs"
const wasmBuffer = readFileSync("node_modules/aead-wasm/dist/aead.wasm")
await AeadWasm.fromBuffer(wasmBuffer)`

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
            <h2 class={styles.cardTitle}>1. Instalación e inicialización</h2>
            <span class={styles.cardTag}>Singleton WASM</span>
          </div>
          <p class={styles.prose}>
            Carga el binario WebAssembly una sola vez al arrancar la aplicación. Después puedes invocar directamente las
            clases estáticas o instanciables con clave fija.
          </p>
          <CodeBlock lang="bash" code="npm install aead-wasm" />
          <CodeBlock lang="typescript" code={INIT_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>2. AEAD (ChaCha20 / XChaCha20-Poly1305)</h2>
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
            <h2 class={styles.cardTitle}>3. Streaming de archivos por chunks</h2>
            <span class={styles.cardTag}>Zero-Alloc</span>
          </div>
          <p class={styles.prose}>
            Procesa archivos de cualquier tamaño reutilizando los buffers estáticos{" "}
            <code style={{ color: "var(--gold-mono)" }}>PARAM_IN</code> /{" "}
            <code style={{ color: "var(--gold-mono)" }}>PARAM_OUT</code> de 1 MB sin presionar al Garbage Collector.
          </p>
          <CodeBlock lang="typescript" code={STREAM_SNIPPET} />
        </section>

        <section class={styles.card}>
          <div class={styles.cardHeader}>
            <h2 class={styles.cardTitle}>4. Flujo puro, MAC y utilidades</h2>
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
