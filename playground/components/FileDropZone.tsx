import { createSignal, Show } from "solid-js"
import { Upload, File as FileIcon, X } from "lucide-solid"
import { formatBytes } from "../utils/cryptoHelpers"
import styles from "./FileDropZone.module.css"

interface FileDropZoneProps {
  file: File | null
  onSelectFile: (file: File | null) => void
  progress: number | null
  hint?: string
}

export function FileDropZone(props: FileDropZoneProps) {
  const [dragging, setDragging] = createSignal(false)
  let inputRef: HTMLInputElement | undefined

  const handleFiles = (files: FileList | null) => {
    if (files && files.length > 0) {
      props.onSelectFile(files[0])
    }
  }

  return (
    <div class={styles.wrapper}>
      <Show
        when={props.file}
        fallback={
          <div
            class={`${styles.dropzone} ${dragging() ? styles.dropzoneActive : ""}`}
            onClick={() => inputRef?.click()}
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              handleFiles(e.dataTransfer?.files ?? null)
            }}
            role="button"
            tabindex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault()
                inputRef?.click()
              }
            }}
          >
            <input
              ref={(el) => {
                inputRef = el
              }}
              type="file"
              class={styles.hiddenInput}
              onChange={(e) => handleFiles(e.currentTarget.files)}
            />
            <div class={styles.dropIcon} aria-hidden="true">
              <Upload size={18} />
            </div>
            <div class={styles.dropTitle}>Arrastra un archivo aquí o haz clic para seleccionar</div>
            <div class={styles.dropHint}>
              {props.hint ?? "Procesamiento local en memoria WASM por streaming"}
            </div>
          </div>
        }
      >
        {(selectedFile) => (
          <div class={styles.fileRow}>
            <div class={styles.fileMeta}>
              <span class={styles.fileIcon} aria-hidden="true">
                <FileIcon size={18} />
              </span>
              <div class={styles.fileDetails}>
                <span class={styles.fileName}>{selectedFile().name}</span>
                <span class={styles.fileSize}>
                  {formatBytes(selectedFile().size)} ({selectedFile().size.toLocaleString("es-ES")} bytes)
                </span>
              </div>
            </div>
            <button
              type="button"
              class={styles.clearBtn}
              onClick={() => {
                if (inputRef) inputRef.value = ""
                props.onSelectFile(null)
              }}
              title="Quitar archivo"
            >
              <X size={15} />
            </button>
          </div>
        )}
      </Show>

      <Show when={props.progress !== null}>
        <div class={styles.progressWrap}>
          <div class={styles.progressHeader}>
            <span>Procesando chunks en WASM</span>
            <span>{Math.round((props.progress ?? 0) * 100)}%</span>
          </div>
          <div class={styles.progressTrack}>
            <div class={styles.progressBar} style={{ width: `${Math.round((props.progress ?? 0) * 100)}%` }} />
          </div>
        </div>
      </Show>
    </div>
  )
}
