/**
 * Invoke context — typed view of ``params.context`` for a single tool
 * invocation. Mirrors :mod:`executa_sdk.context` in the Python SDK so
 * dual-language plugins share the same mental model.
 *
 * The host (matrix Agent) propagates ``deadline_ms`` (Unix epoch
 * milliseconds, derived from the invoke ``timeoutMs``) into
 * ``params.context.deadline_ms``. Older hosts will simply omit it, in
 * which case :func:`remainingS` returns ``Number.POSITIVE_INFINITY``.
 *
 * Example
 * -------
 *
 *   const { InvokeContext } = require("@anna/executa-sdk");
 *
 *   async function handleInvoke(request) {
 *     const ctx = InvokeContext.fromParams(request.params);
 *     if (ctx.expired()) {
 *       return _err(req.id, SUBCALL_TIMEOUT, "no time left in budget");
 *     }
 *     // Tighten the next reverse-RPC. The host loader auto-injects
 *     // ``_clientTimeoutS`` from ``ctx.deadline_ms`` when missing, but
 *     // explicit is friendlier when you want a shorter slice than
 *     // "all remaining time".
 *     await storage.set(key, value, {
 *       timeoutMs: Math.min(5000, ctx.remainingS() * 1000),
 *     });
 *   }
 */

class InvokeContext {
  /**
   * @param {object} [opts]
   * @param {string|null} [opts.invokeId]
   * @param {string|null} [opts.pluginName]
   * @param {number|null} [opts.deadlineMs]
   * @param {object|null} [opts.credentials]
   * @param {object|null} [opts.raw]
   */
  constructor({
    invokeId = null,
    pluginName = null,
    deadlineMs = null,
    credentials = null,
    raw = null,
  } = {}) {
    this.invokeId = invokeId;
    this.pluginName = pluginName;
    this.deadlineMs = deadlineMs;
    this.credentials = credentials;
    this.raw = raw;
    Object.freeze(this);
  }

  /**
   * Build an :class:`InvokeContext` from the raw ``params`` object of an
   * ``invoke`` JSON-RPC request.
   *
   * @param {object|null|undefined} params
   * @returns {InvokeContext}
   */
  static fromParams(params) {
    if (!params || typeof params !== "object") return new InvokeContext();
    const ctx =
      params.context && typeof params.context === "object" ? params.context : {};
    let deadlineInt = null;
    if (ctx.deadline_ms != null) {
      const n = Number(ctx.deadline_ms);
      if (Number.isFinite(n)) deadlineInt = Math.trunc(n);
    }
    const credentials =
      ctx.credentials && typeof ctx.credentials === "object"
        ? ctx.credentials
        : null;
    return new InvokeContext({
      invokeId: ctx.invoke_id ?? params.invoke_id ?? null,
      pluginName: ctx.plugin_name ?? null,
      deadlineMs: deadlineInt,
      credentials,
      raw: ctx && Object.keys(ctx).length > 0 ? ctx : null,
    });
  }

  /**
   * Seconds left in the invoke budget.
   * Returns ``Number.POSITIVE_INFINITY`` when no deadline was sent.
   *
   * @returns {number}
   */
  remainingS() {
    if (this.deadlineMs == null) return Number.POSITIVE_INFINITY;
    return Math.max(0, this.deadlineMs / 1000 - Date.now() / 1000);
  }

  /** @returns {boolean} */
  hasDeadline() {
    return this.deadlineMs != null;
  }

  /** True iff a deadline is set and has already passed. */
  expired() {
    return this.hasDeadline() && this.remainingS() <= 0;
  }
}

module.exports = { InvokeContext };
