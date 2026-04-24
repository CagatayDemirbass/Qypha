declare module "@slack/web-api" {
  export type Block = any;
  export type KnownBlock = any;
  export type RetryOptions = any;
  export type WebClientOptions = any;
  export type WebClient = any;
  export const WebClient: any;
}

declare module "@slack/web-api/dist/chat-stream.js" {
  export type ChatStreamer = any;
}

declare module "@slack/bolt" {
  export type App = any;
  export type SlackEventMiddlewareArgs<T = any> = any;
  export type SlackActionMiddlewareArgs<T = any> = any;
  export type SlackCommandMiddlewareArgs = any;
  export const App: any;
  export const HTTPReceiver: any;
  const DefaultExport: any;
  export default DefaultExport;
}
