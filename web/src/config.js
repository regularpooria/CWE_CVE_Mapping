// Shared configuration for the browser app and the model worker.
//
// All model files are bundled under web/public/models/hicwe/ and served from
// this site. The app never downloads a model from a remote host.
export const MODEL_ID = "HiCWE-MiniLM-L12";
// Local revision label used to invalidate cached vectors when the bundled
// model files change.
export const MODEL_REVISION = "local-v1";
// Model directory resolved against env.localModelPath in the worker.
// The files live under web/public/models/hicwe/.
export const MODEL_LOCAL_ID = "models/hicwe";
export const MODEL_DTYPE = "q8";
export const MAX_LENGTH = 512;
export const BEAM = 20;

export const INDEX_VERSION = 3;
export const DB_NAME = "cwe-cve-mapper";
export const DB_VERSION = 1;
export const DB_STORE = "embeddings";
