declare module "@whiskeysockets/baileys" {
  export namespace proto {
    export type IContextInfo = any;
    export type IMessage = any;
    export type IWebMessageInfo = any;
  }

  export type AnyMessageContent = any;
  export type WAPresence = any;
  export type ConnectionState = any;
  export type WAMessage = any;

  export const DisconnectReason: any;
  export const isJidGroup: any;
  export const extractMessageContent: any;
  export const getContentType: any;
  export const normalizeMessageContent: any;
  export const downloadMediaMessage: any;
  export const fetchLatestBaileysVersion: any;
  export const makeCacheableSignalKeyStore: any;
  export const makeWASocket: any;
  export const useMultiFileAuthState: any;
}
