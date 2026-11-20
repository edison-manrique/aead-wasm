import { createSignal, Show } from "solid-js"
import { Fingerprint, ShieldCheck, CheckCircle2, AlertCircle } from "lucide-solid"
import { Poly1305, bytesToHex, randomKey } from "@aead-wasm"
import type { AlgoPageMeta, InputMode } from "../types/crypto"
import { computeFilePoly1305, formatBytes, parseStrictHex } from "../utils/cryptoHelpers"
import { KeyNoncePanel } from "../components/KeyNoncePanel"
import { ModeSwitch } from "../components/ModeSwitch"
import { FileDropZone } from "../components/FileDropZone"
import { OutputBox } from "../components/OutputBox"
import styles from "../styles/PageShared.module.css"

interface Poly1305PageProps {
  meta: AlgoPageMeta
  wasmReady: boolean
  registerRotateHandler: (fn: () => void) => void
}

const MAX_POLY_FILE_BYTES = 1024 * 1024 - 32 // ~1 MB límite de PARAM_IN menos clave de 32 B

export function Poly1305Page(props: Poly1305PageProps) {
  const [mode, setMode] = createSignal<InputMode>("text")
  const [keyHex, setKeyHex] = createSignal(bytesToHex(randomKey()))

  // Modo texto
  const [message, setMessage] = createSignal("Mensaje autenticado con Poly1305 RFC 8439 en WebAssembly.")
  const [tagOutput, setTagOutput] = createSignal<string | null>(null)
  const [tagMeta, setTagMeta] = createSignal<string | undefined>(undefined)
  const [tagStatus, setTagStatus] = createSignal<"idle" | "ok" | "err">("idle")

  // Verificación de tag esperado
  const [expectedTagHex, setExpectedTagHex] = createSignal("")
  const [verifyState, setVerifyState] = createSignal<{ ok: boolean; msg: string } | null>(null)

  // Modo archivo
  const [selectedFile, setSelectedFile] = createSignal<File | null>(null)
  const [fileBusy, setFileBusy] = createSignal(false)
  const [fileTagHex, setFileTagHex] = createSignal<string | null>(null)
  const [fileMeta, setFileMeta] = createSignal<string | undefined>(undefined)
  const [fileError, setFileError] = createSignal<string | null>(null)

  const rotateKey = () => {
    setKeyHex(bytesToHex(randomKey()))
  }

  props.registerRotateHandler(rotateKey)

  const fileExceedsLimit = () => {
    const f = selectedFile()
    return f ? f.size > MAX_POLY_FILE_BYTES : false
  }

  const handleComputeTextMac = () => {
    if (!props.wasmReady) return
    setVerifyState(null)
    try {
      const started = performance.now()
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const tag = Poly1305.mac(key, message())
      const elapsed = performance.now() - started

      const hex = bytesToHex(tag)
      setTagOutput(hex)
      setExpectedTagHex(hex)
      setTagMeta(`16 B · ${elapsed.toFixed(3)} ms`)
      setTagStatus("ok")
    } catch (err) {
      setTagOutput(err instanceof Error ? err.message : String(err))
      setTagMeta(undefined)
      setTagStatus("err")
    }
  }

  const handleComputeFileMac = async () => {
    const file = selectedFile()
    if (!props.wasmReady || !file || fileBusy()) return
    setFileError(null)
    setVerifyState(null)
    if (file.size > MAX_POLY_FILE_BYTES) {
      setFileError(
        `El archivo pesa ${formatBytes(file.size)}, superando el límite one-shot de ${formatBytes(
          MAX_POLY_FILE_BYTES
        )} para Poly1305 standalone. Usa ChaCha20-Poly1305 para autenticar archivos grandes por streaming.`
      )
      return
    }
    setFileBusy(true)
    try {
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const { tag, elapsedMs } = await computeFilePoly1305(file, key)
      const hex = bytesToHex(tag)
      setFileTagHex(hex)
      setExpectedTagHex(hex)
      setFileMeta(`${formatBytes(file.size)} · ${elapsedMs.toFixed(2)} ms`)
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err))
    } finally {
      setFileBusy(false)
    }
  }

  const handleVerifyTag = () => {
    const computed = mode() === "text" ? (tagStatus() === "ok" ? tagOutput() : null) : fileTagHex()
    if (!computed) {
      setVerifyState({ ok: false, msg: "Primero genera el MAC para poder compararlo." })
      return
    }
    try {
      const expectedBytes = parseStrictHex(expectedTagHex(), 16, "Tag esperado")
      const computedBytes = parseStrictHex(computed, 16, "Tag calculado")
      let diff = 0
      for (let i = 0; i < 16; i++) diff |= expectedBytes[i] ^ computedBytes[i]
      if (diff === 0) {
        setVerifyState({
          ok: true,
          msg: "Tag válido: coincide exactamente con el MAC calculado (comparación constant-time)."
        })
      } else {
        setVerifyState({
          ok: false,
          msg: "Tag inválido: el MAC calculado no coincide con el tag esperado."
        })
      }
    } catch (err) {
      setVerifyState({ ok: false, msg: err instanceof Error ? err.message : String(err) })
    }
  }

  return (
    <div class={styles.page}>
      <div class={styles.introRow}>
        <p class={styles.description}>{props.meta.description}</p>
        <ModeSwitch mode={mode()} onChange={setMode} />
      </div>

      <section class={styles.section}>
        <div class={styles.sectionHeader}>
          <h2 class={styles.sectionTitle}>Clave de un solo uso (r ‖ s)</h2>
          <span class={styles.sectionMeta}>32 bytes · Sin nonce</span>
        </div>

        <KeyNoncePanel
          keyHex={keyHex()}
          onKeyChange={setKeyHex}
          onGenerateKey={() => setKeyHex(bytesToHex(randomKey()))}
        />
      </section>

      <div class={styles.twoCol}>
        <section class={styles.section}>
          <Show
            when={mode() === "text"}
            fallback={
              <>
                <div class={styles.sectionHeader}>
                  <h2 class={styles.sectionTitle}>Autenticar archivo (One-Shot)</h2>
                  <span class={styles.sectionMeta}>Máximo ~1 MB</span>
                </div>

                <FileDropZone
                  file={selectedFile()}
                  onSelectFile={(f) => {
                    setSelectedFile(f)
                    setFileTagHex(null)
                    setFileError(null)
                    setVerifyState(null)
                  }}
                  progress={null}
                  hint={`Calcula el tag Poly1305 de archivos de hasta ${formatBytes(MAX_POLY_FILE_BYTES)}`}
                />

                <Show when={fileExceedsLimit()}>
                  <div class={`${styles.notice} ${styles.noticeErr}`}>
                    <AlertCircle size={16} class={styles.noticeIcon} />
                    <span>
                      Archivo demasiado grande ({formatBytes(selectedFile()!.size)}). Poly1305 standalone admite hasta{" "}
                      {formatBytes(MAX_POLY_FILE_BYTES)}.
                    </span>
                  </div>
                </Show>

                <div class={styles.btnRow}>
                  <button
                    type="button"
                    class={styles.btnPrimary}
                    disabled={!props.wasmReady || !selectedFile() || fileBusy() || fileExceedsLimit()}
                    onClick={handleComputeFileMac}
                  >
                    <Fingerprint size={14} />
                    <span>Calcular MAC del archivo</span>
                  </button>
                </div>

                <Show when={fileError()}>
                  {(err) => (
                    <div class={`${styles.notice} ${styles.noticeErr}`}>
                      <AlertCircle size={16} class={styles.noticeIcon} />
                      <span>{err()}</span>
                    </div>
                  )}
                </Show>

                <OutputBox
                  label="Tag Poly1305 del archivo (16 B)"
                  value={fileTagHex()}
                  status={fileTagHex() ? "ok" : "idle"}
                  meta={fileMeta()}
                  placeholder="Selecciona un archivo y calcula su MAC"
                />
              </>
            }
          >
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Generar MAC de mensaje</h2>
              <span class={styles.sectionMeta}>Tag de 16 bytes</span>
            </div>

            <div class={styles.field}>
              <div class={styles.labelRow}>
                <label class={styles.label} for="poly-msg">
                  Mensaje (UTF-8)
                </label>
                <span class={styles.hint}>{new TextEncoder().encode(message()).length} bytes</span>
              </div>
              <textarea
                id="poly-msg"
                class={`${styles.textarea} ${styles.textareaSans}`}
                value={message()}
                onInput={(e) => setMessage(e.currentTarget.value)}
                placeholder="Mensaje a autenticar..."
              />
            </div>

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady}
                onClick={handleComputeTextMac}
              >
                <Fingerprint size={14} />
                <span>Generar tag MAC</span>
              </button>
            </div>

            <OutputBox
              label="Tag Poly1305 (16 B hex)"
              value={tagOutput()}
              status={tagStatus()}
              meta={tagMeta()}
              placeholder="Pulsa Generar tag MAC para calcular la firma"
            />
          </Show>
        </section>

        <section class={styles.section}>
          <div class={styles.sectionHeader}>
            <h2 class={styles.sectionTitle}>Verificar autenticidad</h2>
            <span class={styles.sectionMeta}>Comparación constant-time</span>
          </div>

          <div class={styles.field}>
            <div class={styles.labelRow}>
              <label class={styles.label} for="poly-expected">
                Tag esperado (hex 16 B)
              </label>
              <span class={styles.hint}>
                {expectedTagHex().trim().replace(/\s+/g, "").length} / 32 hex
              </span>
            </div>
            <input
              id="poly-expected"
              type="text"
              class={styles.input}
              value={expectedTagHex()}
              onInput={(e) => setExpectedTagHex(e.currentTarget.value)}
              placeholder="32 caracteres hexadecimales..."
              spellcheck={false}
            />
          </div>

          <div class={styles.btnRow}>
            <button
              type="button"
              class={styles.btnSecondary}
              disabled={!props.wasmReady}
              onClick={handleVerifyTag}
            >
              <ShieldCheck size={14} />
              <span>Verificar coincidencia</span>
            </button>
          </div>

          <Show when={verifyState()}>
            {(st) => (
              <div class={`${styles.notice} ${st().ok ? styles.noticeOk : styles.noticeErr}`}>
                <Show when={st().ok} fallback={<AlertCircle size={16} class={styles.noticeIcon} />}>
                  <CheckCircle2 size={16} class={styles.noticeIcon} />
                </Show>
                <span>{st().msg}</span>
              </div>
            )}
          </Show>
        </section>
      </div>
    </div>
  )
}
