import { Show } from "solid-js"
import { Dices, FlaskConical } from "lucide-solid"
import type { AlgoPageMeta } from "../types/crypto"
import styles from "./Header.module.css"

interface HeaderProps {
  page: AlgoPageMeta
  onRegenerateKeys: () => void
  onGoToLab: () => void
}

export function Header(props: HeaderProps) {
  return (
    <header class={styles.header}>
      <div class={styles.left}>
        <h1 class={styles.title}>{props.page.name}</h1>
        <div class={styles.meta}>
          <span aria-hidden="true">/</span>
          <span>{props.page.standard}</span>
          <Show when={props.page.keyBytes !== null}>
            <span aria-hidden="true">·</span>
            <span class={styles.mono}>Clave {props.page.keyBytes}B</span>
          </Show>
          <Show when={props.page.nonceBytes !== null}>
            <span aria-hidden="true">·</span>
            <span class={styles.mono}>Nonce {props.page.nonceBytes}B</span>
          </Show>
          <Show when={props.page.tagBytes !== null}>
            <span aria-hidden="true">·</span>
            <span class={styles.mono}>Tag {props.page.tagBytes}B</span>
          </Show>
        </div>
      </div>

      <div class={styles.actions}>
        <Show
          when={props.page.id !== "docs" && props.page.id !== "security"}
          fallback={
            <button type="button" class={styles.goldBtn} onClick={props.onGoToLab}>
              <FlaskConical size={13} />
              <span>Ir al laboratorio</span>
            </button>
          }
        >
          <button
            type="button"
            class={styles.goldBtn}
            onClick={props.onRegenerateKeys}
            title="Generar nueva clave y nonce criptográficamente seguros"
          >
            <Dices size={13} />
            <span>Nueva Clave Aleatoria</span>
          </button>
        </Show>
      </div>
    </header>
  )
}
