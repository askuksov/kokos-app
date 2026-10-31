import type { TFn } from "./i18n";

const ERROR_TOKENS: ReadonlyArray<readonly [string, string]> = [
  ["biometric_unsupported_build", "settings.touchIdUnsupportedBuild"],
  ["biometric_store_failed", "errors.biometricStoreFailed"],
  ["fast_unlock_keyfile_unsupported", "errors.fastUnlockKeyfileUnsupported"],
  ["fast_unlock_store_failed", "errors.fastUnlockStoreFailed"],
];

/** Translate a known backend error token, else show the raw error verbatim. */
export function errorMessage(err: unknown, t: TFn): string {
  const raw = String(err);
  for (const [token, key] of ERROR_TOKENS) {
    if (raw.includes(token)) return t(key);
  }
  return raw;
}
