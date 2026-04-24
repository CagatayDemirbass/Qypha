type AuthProfileStore = {
  profiles?: Record<string, { provider?: string; type?: string }>;
};

type CreateProviderApiKeyAuthMethodOptions = {
  providerId: string;
  methodId?: string;
  label?: string;
  hint?: string;
  defaultModel?: string;
  wizard?: Record<string, unknown>;
  applyConfig?: (cfg: Record<string, unknown>) => Record<string, unknown>;
};

export const CLAUDE_CLI_PROFILE_ID = "anthropic:default";
export const CODEX_CLI_PROFILE_ID = "openai-codex:default";

export function createProviderApiKeyAuthMethod(options: CreateProviderApiKeyAuthMethodOptions) {
  return {
    id: options.methodId ?? "api-key",
    label: options.label ?? "API key",
    hint: options.hint,
    kind: "api_key" as const,
    wizard: options.wizard,
    run: async () => ({
      profiles: [],
      defaultModel: options.defaultModel,
      notes: ["Interactive auth is handled by Qypha outside the embedded worker."],
    }),
    runNonInteractive: async (ctx: { config?: Record<string, unknown> }) =>
      options.applyConfig?.(ctx.config ?? {}) ?? null,
  };
}

export function applyAuthProfileConfig<T>(cfg: T): T {
  return cfg;
}

export function buildTokenProfileId(params: { provider: string; name?: string }) {
  const suffix = params.name?.trim() || "default";
  return `${params.provider}:${suffix}`;
}

export async function ensureApiKeyFromOptionEnvOrPrompt(params: {
  envVar?: string;
  opts?: Record<string, unknown>;
}) {
  const fromOption = typeof params.opts?.token === "string" ? params.opts.token.trim() : "";
  if (fromOption) {
    return fromOption;
  }
  const fromEnv = params.envVar ? process.env[params.envVar]?.trim() : "";
  return fromEnv || "";
}

export function listProfilesForProvider(store: AuthProfileStore | undefined, provider: string) {
  return Object.entries(store?.profiles ?? {})
    .filter(([, profile]) => profile?.provider === provider)
    .map(([id]) => id);
}

export function normalizeApiKeyInput(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

export function normalizeSecretInput(value: unknown) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

export function normalizeSecretInputModeInput(value: unknown) {
  return value === "ref" ? "ref" : "plaintext";
}

export async function promptSecretRefForSetup() {
  throw new Error("Secret-reference onboarding is not available inside the embedded worker.");
}

export async function resolveSecretInputModeForEnvSelection(params: { explicitMode?: unknown }) {
  return normalizeSecretInputModeInput(params.explicitMode);
}

export async function upsertAuthProfile() {
  return;
}

export function suggestOAuthProfileIdForLegacyDefault() {
  return undefined;
}

export function validateAnthropicSetupToken(value: unknown) {
  return typeof value === "string" && value.trim() ? undefined : "Anthropic setup token is required";
}

export function validateApiKeyInput(value: unknown) {
  return typeof value === "string" && value.trim() ? undefined : "API key is required";
}

export function ensureAuthProfileStore(): AuthProfileStore {
  return { profiles: {} };
}

export function buildOauthProviderAuthResult(params: {
  providerId: string;
  defaultModel?: string;
  access?: string;
  notes?: string[];
}) {
  const access = typeof params.access === "string" ? params.access.trim() : "";
  return {
    profiles: access
      ? [
          {
            profileId: `${params.providerId}:default`,
            credential: {
              type: "oauth",
              provider: params.providerId,
              access,
            },
          },
        ]
      : [],
    defaultModel: params.defaultModel,
    notes: params.notes,
  };
}

export function resolveDefaultSecretProviderAlias() {
  return "env";
}

export function resolveApiKeyForProvider(params: {
  envVars?: string[];
  providerId?: string;
  fallback?: string;
}) {
  for (const envVar of params.envVars ?? []) {
    const value = process.env[envVar]?.trim();
    if (value) {
      return value;
    }
  }
  return params.fallback ?? "";
}
