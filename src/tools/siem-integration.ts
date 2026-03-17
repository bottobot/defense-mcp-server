/**
 * @deprecated Merged into logging.ts as of v0.7.0.
 * This file exists only for backward-compatible re-exports.
 * It is NOT registered in index.ts — do not call registerSiemIntegrationTools().
 */
export { validateSiemHost } from "./logging.js";

// Removed: registerSiemIntegrationTools (was re-registering all logging tools under alias)
