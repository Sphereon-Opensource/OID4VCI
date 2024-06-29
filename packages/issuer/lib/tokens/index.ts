import {
  AccessTokenRequest,
  AccessTokenResponse,
  Alg,
  CNonceState,
  CredentialOfferSession,
  EXPIRED_PRE_AUTHORIZED_CODE,
  GrantTypes,
  INVALID_PRE_AUTHORIZED_CODE,
  IssueStatus,
  IStateManager,
  Jwt,
  JWTSignerCallback,
  JWTVerifyCallback,
  PIN_NOT_MATCH_ERROR,
  PIN_VALIDATION_ERROR,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  TokenError,
  TokenErrorResponse,
  UNSUPPORTED_GRANT_TYPE_ERROR,
  USER_PIN_NOT_REQUIRED_ERROR,
  USER_PIN_REQUIRED_ERROR,
} from '@sphereon/oid4vci-common'
import { v4 } from 'uuid'

import { isPreAuthorizedCodeExpired } from '../functions'

export interface ITokenEndpointOpts {
  tokenEndpointDisabled?: boolean // Disable if used in an existing OAuth2/OIDC environment and have the AS handle tokens
  tokenPath?: string // token path can either be defined here, or will be deduced from issuer metadata
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  preAuthorizedCodeExpirationDuration?: number
  accessTokenSignerCallback?: JWTSignerCallback
  accessTokenVerificationCallback?: JWTVerifyCallback<never>
  accessTokenIssuer?: string
}

export const generateAccessToken = async (
  opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'accessTokenIssuer'>> & {
    preAuthorizedCode?: string
    alg?: Alg
  },
): Promise<string> => {
  const { accessTokenIssuer, alg, accessTokenSignerCallback, tokenExpiresIn, preAuthorizedCode } = opts
  // JWT uses seconds for iat and exp
  const iat = new Date().getTime() / 1000
  const exp = iat + tokenExpiresIn
  const jwt: Jwt = {
    header: { typ: 'JWT', alg: alg ?? Alg.ES256 },
    payload: {
      iat,
      exp,
      iss: accessTokenIssuer,
      ...(preAuthorizedCode && { preAuthorizedCode }),
    },
  }
  return await accessTokenSignerCallback(jwt)
}

export const isValidGrant = (assertedState: CredentialOfferSession, grantType: string): boolean => {
  if (assertedState.credentialOffer?.credential_offer?.grants) {
    // TODO implement authorization_code
    return (
      Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantTypes.PRE_AUTHORIZED_CODE) &&
      grantType === GrantTypes.PRE_AUTHORIZED_CODE
    )
  }
  return false
}

export const assertValidAccessTokenRequest = async (
  request: AccessTokenRequest,
  opts: {
    credentialOfferSessions: IStateManager<CredentialOfferSession>
    expirationDuration: number
  },
) => {
  const { credentialOfferSessions, expirationDuration } = opts
  // Only pre-auth supported for now
  if (request.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
  }

  // Pre-auth flow
  if (!request['pre-authorized_code']) {
    throw new TokenError(400, TokenErrorResponse.invalid_request, PRE_AUTHORIZED_CODE_REQUIRED_ERROR)
  }

  const credentialOfferSession = await credentialOfferSessions.getAsserted(request['pre-authorized_code'])
  credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_REQUESTED
  credentialOfferSession.lastUpdatedAt = +new Date()
  await credentialOfferSessions.set(request[PRE_AUTH_CODE_LITERAL], credentialOfferSession)
  if (!isValidGrant(credentialOfferSession, request.grant_type)) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
  }
  /*
  invalid_request:
  the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
   */
  if (
    credentialOfferSession.credentialOffer.credential_offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.tx_code &&
    !request.user_pin
  ) {
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_REQUIRED_ERROR)
  }
  /*
  invalid_request:
  the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
   */
  if (!credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.tx_code && request.user_pin) {
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_NOT_REQUIRED_ERROR)
  }
  /*
  invalid_grant:
  the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
  the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
   */
  if (request.user_pin && !/[0-9{,8}]/.test(request.user_pin)) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_VALIDATION_ERROR)
  } else if (request.user_pin !== credentialOfferSession.userPin) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_NOT_MATCH_ERROR)
  } else if (isPreAuthorizedCodeExpired(credentialOfferSession, expirationDuration)) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, EXPIRED_PRE_AUTHORIZED_CODE)
  } else if (
    request[PRE_AUTH_CODE_LITERAL] !==
    credentialOfferSession.credentialOffer?.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
  ) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, INVALID_PRE_AUTHORIZED_CODE)
  }
  return { preAuthSession: credentialOfferSession }
}

export const createAccessTokenResponse = async (
  request: AccessTokenRequest,
  opts: {
    credentialOfferSessions: IStateManager<CredentialOfferSession>
    cNonces: IStateManager<CNonceState>
    cNonce?: string
    cNonceExpiresIn?: number // expiration in seconds
    tokenExpiresIn: number // expiration in seconds
    // preAuthorizedCodeExpirationDuration?: number
    accessTokenSignerCallback: JWTSignerCallback
    accessTokenIssuer: string
    interval?: number
  },
) => {
  const { credentialOfferSessions, cNonces, cNonceExpiresIn, tokenExpiresIn, accessTokenIssuer, accessTokenSignerCallback, interval } = opts
  // Pre-auth flow
  const preAuthorizedCode = request[PRE_AUTH_CODE_LITERAL] as string

  const cNonce = opts.cNonce ?? v4()
  await cNonces.set(cNonce, { cNonce, createdAt: +new Date(), preAuthorizedCode })

  const access_token = await generateAccessToken({
    tokenExpiresIn,
    accessTokenSignerCallback,
    preAuthorizedCode,
    accessTokenIssuer,
  })
  const response: AccessTokenResponse = {
    access_token,
    token_type: 'bearer',
    expires_in: tokenExpiresIn,
    c_nonce: cNonce,
    c_nonce_expires_in: cNonceExpiresIn,
    authorization_pending: false,
    interval,
  }
  const credentialOfferSession = await credentialOfferSessions.getAsserted(preAuthorizedCode)
  credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_CREATED
  credentialOfferSession.lastUpdatedAt = +new Date()
  await credentialOfferSessions.set(preAuthorizedCode, credentialOfferSession)
  return response
}
