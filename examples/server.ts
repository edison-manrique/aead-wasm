import express from "express"
import path from "node:path"
import { fileURLToPath } from "node:url"

const PORT = Number(process.env.PORT) || 3000
const HOST = "0.0.0.0"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const rootDir = path.resolve(__dirname, "..")
const appDistDir = path.join(rootDir, "dist-app")

const app = express()

app.use(express.static(appDistDir))
app.use("/dist", express.static(path.join(rootDir, "dist")))

app.get("/{*splat}", (_req, res) => {
  res.sendFile(path.join(appDistDir, "index.html"))
})

app.listen(PORT, HOST, () => {
  console.log(`🚀 AEAD-WASM Crypto Lab ejecutándose en http://${HOST}:${PORT}/`)
})
