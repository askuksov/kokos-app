export type EntryType = "login" | "card" | "secure_note" | "wifi";

export const ENTRY_TYPES: EntryType[] = ["login", "card", "secure_note", "wifi"];

export interface EntryTypeMeta {
  color: string;
  icon: string;
  labelKey: string;
  titleLabelKey: string;
}

export const ENTRY_TYPE_META: Record<EntryType, EntryTypeMeta> = {
  login:       { color: "oklch(0.64 0.16 250)", icon: "user", labelKey: "entryType.login",       titleLabelKey: "editor.titleLabel.login" },
  card:        { color: "oklch(0.66 0.15 152)", icon: "card", labelKey: "entryType.card",        titleLabelKey: "editor.titleLabel.card" },
  secure_note: { color: "oklch(0.74 0.14 85)",  icon: "note", labelKey: "entryType.secure_note", titleLabelKey: "editor.titleLabel.secure_note" },
  wifi:        { color: "oklch(0.68 0.16 48)",  icon: "wifi", labelKey: "entryType.wifi",        titleLabelKey: "editor.titleLabel.wifi" },
};

export function entryTypeMeta(t: string): EntryTypeMeta {
  return ENTRY_TYPE_META[(t as EntryType)] ?? ENTRY_TYPE_META.login;
}

export const WIFI_SECURITY_OPTIONS = ["WPA3", "WPA2", "WPA", "WEP", "None (open)"];
export const WIFI_SECURITY_FIELD_NAME = "Security";
export const SECURE_NOTE_BODY_FIELD_NAME = "Note";
