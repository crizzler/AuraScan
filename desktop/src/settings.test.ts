import { describe, expect, it } from "vitest";

import { MAX_FEATURES, MAX_PROVIDERS, SETTINGS_SCHEMA, parseSettings, parseSettingsWrite } from "./contract";

function settingsFixture(change?: (value: Record<string, unknown>) => void): unknown {
  const value: Record<string, unknown> = {
    schema: SETTINGS_SCHEMA,
    config: {
      path: "~/.config/aurascan/.env",
      present: true,
      mode: "0600",
      mode_ok: true,
      readable: true
    },
    ai: {
      enabled: false,
      provider: "deepseek",
      provider_label: "DeepSeek",
      model: "deepseek-chat",
      base_url: null,
      local: false,
      requires_key: true,
      key_env: "AURASCAN_DEEPSEEK_API_KEY",
      key_present: true,
      supported: true,
      authentication_ready: true,
      error: "",
      ready: false
    },
    providers: [
      {
        id: "deepseek",
        label: "DeepSeek",
        local: false,
        requires_key: true,
        key_env: "AURASCAN_DEEPSEEK_API_KEY",
        default_model: "deepseek-chat",
        key_present: true,
        selected: true
      },
      {
        id: "lmstudio",
        label: "LM Studio",
        local: true,
        requires_key: false,
        key_env: "AURASCAN_LOCAL_AI_API_KEY",
        default_model: "local-model",
        key_present: false,
        selected: false
      }
    ],
    features: [
      { id: "ai", label: "AI assistance", env: "AURASCAN_AI_ENABLED", enabled: false, declared: true },
      { id: "recovery_ai", label: "Recovery AI", env: "AURASCAN_RECOVERY_AI_ENABLED", enabled: null, declared: false }
    ]
  };
  if (change) {
    change(value);
  }
  return value;
}

describe("parseSettings", () => {
  it("accepts a complete payload", () => {
    const result = parseSettings(settingsFixture());

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.settings.schema).toBe(SETTINGS_SCHEMA);
    expect(result.settings.providers).toHaveLength(2);
    expect(result.settings.features[1].enabled).toBeNull();
  });

  it("never surfaces an unexpected secret field", () => {
    const result = parseSettings(
      settingsFixture((value) => {
        (value.ai as Record<string, unknown>).api_key = "sk-should-never-render";
      })
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect("api_key" in result.settings.ai).toBe(false);
    expect(JSON.stringify(result.settings)).not.toContain("sk-should-never-render");
  });

  it("rejects an unsupported schema", () => {
    const result = parseSettings(settingsFixture((value) => {
      value.schema = "aurascan-settings/2";
    }));

    expect(result.ok).toBe(false);
  });

  it("rejects malformed sections", () => {
    const cases: Array<(value: Record<string, unknown>) => void> = [
      (value) => {
        value.config = null;
      },
      (value) => {
        (value.config as Record<string, unknown>).mode = 6;
      },
      (value) => {
        (value.ai as Record<string, unknown>).ready = "yes";
      },
      (value) => {
        (value.ai as Record<string, unknown>).base_url = 7;
      },
      (value) => {
        (value.providers as Record<string, unknown>[])[0].id = "DeepSeek";
      },
      (value) => {
        (value.features as Record<string, unknown>[])[0].enabled = "on";
      }
    ];
    for (const change of cases) {
      expect(parseSettings(settingsFixture(change)).ok).toBe(false);
    }
  });

  it("bounds the provider and feature lists", () => {
    const manyProviders = parseSettings(
      settingsFixture((value) => {
        const entry = (value.providers as Record<string, unknown>[])[0];
        value.providers = new Array(MAX_PROVIDERS + 1).fill(entry);
      })
    );
    expect(manyProviders.ok).toBe(false);

    const manyFeatures = parseSettings(
      settingsFixture((value) => {
        const entry = (value.features as Record<string, unknown>[])[0];
        value.features = new Array(MAX_FEATURES + 1).fill(entry);
      })
    );
    expect(manyFeatures.ok).toBe(false);
  });
});

describe("parseSettingsWrite", () => {
  it("accepts a stored confirmation", () => {
    const result = parseSettingsWrite({
      schema: SETTINGS_SCHEMA,
      action: "set_ai_key",
      stored: true,
      provider: "deepseek",
      key_env: "AURASCAN_DEEPSEEK_API_KEY",
      ai: (settingsFixture() as Record<string, any>).ai
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ai.provider).toBe("deepseek");
    }
  });

  it("rejects anything that is not an explicit confirmation", () => {
    expect(parseSettingsWrite({ schema: SETTINGS_SCHEMA }).ok).toBe(false);
    expect(parseSettingsWrite({ schema: SETTINGS_SCHEMA, stored: false }).ok).toBe(false);
    expect(
      parseSettingsWrite({
        schema: SETTINGS_SCHEMA,
        stored: true,
        ai: { provider: "deepseek" }
      }).ok
    ).toBe(false);
    expect(parseSettingsWrite(null).ok).toBe(false);
  });
});
