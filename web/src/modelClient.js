export class ModelClient {
  constructor({ onProgress, onWorkerError } = {}) {
    this.onProgress = onProgress ?? (() => {});
    this.onWorkerError = onWorkerError ?? (() => {});
    this.pending = new Map();
    this.nextId = 1;
    this.worker = new Worker(new URL("./model.worker.js", import.meta.url), {
      type: "module",
    });

    this.worker.onmessage = (event) => {
      const { type, id, payload } = event.data ?? {};
      if (type === "progress") {
        this.onProgress(payload);
        return;
      }
      if (type === "ready" || type === "result") {
        const pending = this.pending.get(id);
        if (pending) {
          this.pending.delete(id);
          pending.resolve(payload);
        }
        return;
      }
      if (type === "error") {
        const pending = this.pending.get(id);
        if (pending) {
          this.pending.delete(id);
          const error = new Error(payload?.message ?? "The model worker failed.");
          error.stack = payload?.stack || error.stack;
          pending.reject(error);
        } else {
          this.onWorkerError(new Error(payload?.message ?? "The model worker failed."));
        }
      }
    };

    this.worker.onerror = (event) => {
      const error = new Error(event.message || "The model worker crashed.");
      this.onWorkerError(error);
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
    };
  }

  request(type, payload) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, payload });
    });
  }

  load(modelRoot) {
    return this.request("load", { modelRoot });
  }

  embed(texts) {
    return this.request("embed", { texts });
  }

  terminate() {
    this.worker.terminate();
    const error = new Error("The model worker was stopped.");
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}
