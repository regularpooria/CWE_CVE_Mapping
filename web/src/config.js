// Shared configuration for the browser app and the model worker.
//
// The model files under web/public/model/ are mirrored from the anonymous
// review copy at https://anonymous-hf.com/a/rizm2zd9qgqe/. They are served
// from this site so the browser does not depend on that host's CORS policy.
export const MODEL_ID = "HiCWE-MiniLM-L12";
export const MODEL_REVISION = "rizm2zd9qgqe";
export const MODEL_SOURCE_URL = "https://anonymous-hf.com/a/rizm2zd9qgqe/";
// Valid Hugging Face-style id resolved against env.localModelPath in the worker.
// The files live under web/public/models/hicwe/.
export const MODEL_LOCAL_ID = "models/hicwe";
export const MODEL_DTYPE = "q8";
export const MAX_LENGTH = 512;
export const BEAM = 20;

export const INDEX_VERSION = 3;
export const DB_NAME = "cwe-cve-mapper";
export const DB_VERSION = 1;
export const DB_STORE = "embeddings";
