/**
 * @anna/executa-sdk — Node.js helpers for Executa plugins.
 *
 * Exposes:
 *   - SamplingClient (./sampling.js)
 *   - StorageClient + FilesClient (./storage.js) for Anna Persistent Storage
 *   - InvokeContext (./context.js) — typed view of params.context with
 *     remainingS() / expired() helpers honouring the host deadline_ms.
 *   - makeResponseRouter helper to multiplex stdin frames across clients.
 */

const sampling = require("./sampling");
const storage = require("./storage");
const image = require("./image");
const hostUpload = require("./host_upload");
const context = require("./context");

module.exports = {
  ...sampling,
  ...storage,
  ...image,
  ...hostUpload,
  ...context,
};
