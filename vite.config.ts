import { defineConfig, type Plugin } from "vite"
import solidPlugin from "vite-plugin-solid"
import fs from "node:fs"
import path from "node:path"

/**
 * Sirve `dist/aead.wasm` y `dist/aead.mt.wasm` durante el desarrollo y los
 * emite en la raíz del bundle (`dist-app/`) al compilar para producción.
 */
function aeadWasmPlugin(): Plugin {
  const assets = [
    { fileName: "aead.wasm", source: path.resolve(process.cwd(), "dist", "aead.wasm") },
    { fileName: "aead.mt.wasm", source: path.resolve(process.cwd(), "dist", "aead.mt.wasm") }
  ]

  return {
    name: "aead-wasm-asset",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const cleanPath = (req.url || "").split("?")[0]
        const match = assets.find(
          (a) => cleanPath.endsWith(`/${a.fileName}`) || cleanPath.endsWith(`/dist/${a.fileName}`)
        )
        if (match) {
          if (!fs.existsSync(match.source)) {
            res.statusCode = 404
            res.end(`${match.fileName} not built yet. Run npm run asbuild.`)
            return
          }
          res.setHeader("Content-Type", "application/wasm")
          fs.createReadStream(match.source).pipe(res)
          return
        }
        next()
      })
    },
    generateBundle() {
      for (const asset of assets) {
        if (fs.existsSync(asset.source)) {
          this.emitFile({
            type: "asset",
            fileName: asset.fileName,
            source: fs.readFileSync(asset.source)
          })
        }
      }
    },
    closeBundle() {
      const privateAssetsOut = path.resolve(process.cwd(), "dist-app", "assets", "aistudio")
      if (fs.existsSync(privateAssetsOut)) {
        fs.rmSync(privateAssetsOut, { recursive: true, force: true })
      }
    }
  }
}

export default defineConfig({
  base: process.env.VITE_BASE_PATH || "/",
  plugins: [solidPlugin(), aeadWasmPlugin()],
  resolve: {
    alias: {
      "@aead-wasm": path.resolve(process.cwd(), "src/index.ts")
    }
  },
  css: {
    modules: {
      localsConvention: "camelCaseOnly"
    }
  },
  server: {
    host: "0.0.0.0",
    port: 3000
  },
  build: {
    outDir: "dist-app",
    emptyOutDir: true,
    target: "esnext"
  }
})
