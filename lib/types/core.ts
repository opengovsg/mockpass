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

interface IBaseAssertion {
  singPass: string[]
  corpPass: {
    nric: string
    uen: string
    name?: string
    isSingPassHolder?: boolean
  }[]
}

export interface ISamlAssertion extends IBaseAssertion {
  create: {
    singPass: (
      nric: string,
      issuer: string,
      recipient: string,
      inResponseTo: string,
      audience: string,
    ) => string
    corpPass: (
      source: { uen: string },
      issuer: string,
      recipient: string,
      inResponseTo: string,
      audience: string,
    ) => string
  }
}

interface IOidcAssertionFnReturn {
  accessToken: string
  idTokenClaims: {
    rt_hash: string
    at_hash: string
    iat?: number
    exp?: number
    iss: string
    amr: string[]
    aud: string
    sub: string
    nonce?: string
  }
}

export interface IOidcAssertion extends IBaseAssertion {
  create: {
    singPass: (
      uuid: number,
      iss: string,
      aud: string,
      nonce: string,
    ) => IOidcAssertionFnReturn
    corpPass: (
      uuid: number,
      iss: string,
      aud: string,
      nonce: string,
    ) => Promise<IOidcAssertionFnReturn>
  }
}
