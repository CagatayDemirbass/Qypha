import { createRequire } from "node:module";
import type { RetryOptions, WebClientOptions, WebClient } from "@slack/web-api";

const require = createRequire(import.meta.url);
let slackWebApiModule: typeof import("@slack/web-api") | null = null;

function loadSlackWebApiModule(): typeof import("@slack/web-api") {
  if (slackWebApiModule) {
    return slackWebApiModule;
  }
  try {
    slackWebApiModule = require("@slack/web-api") as typeof import("@slack/web-api");
    return slackWebApiModule;
  } catch (error) {
    throw new Error(
      `Slack runtime dependency "@slack/web-api" is unavailable: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export const SLACK_DEFAULT_RETRY_OPTIONS: RetryOptions = {
  retries: 2,
  factor: 2,
  minTimeout: 500,
  maxTimeout: 3000,
  randomize: true,
};

export function resolveSlackWebClientOptions(options: WebClientOptions = {}): WebClientOptions {
  return {
    ...options,
    retryConfig: options.retryConfig ?? SLACK_DEFAULT_RETRY_OPTIONS,
  };
}

export function createSlackWebClient(token: string, options: WebClientOptions = {}) {
  const { WebClient } = loadSlackWebApiModule();
  return new WebClient(token, resolveSlackWebClientOptions(options));
}
