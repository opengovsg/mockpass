import { Request } from 'express'

export interface IServiceProvider {
  cert: Buffer
  pubKey: Buffer
}

export interface IMyInfoContext {
  clientSecret?: string
  redirectURI?: string
}

export type MyInfoSignatureFn = (
  authHeader: string,
  req: Request,
  context: IMyInfoContext,
) => { signature: string; baseString: string }
