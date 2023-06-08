import http from 'http'
import process from 'process'

import {
  ACCESS_TOKEN_ISSUER_REQUIRED_ERROR,
  AuthorizationRequest,
  CredentialOfferV1_0_11,
  CredentialRequestV1_0_11,
  CredentialSupported,
  determineGrantTypes,
  getNumberOrUndefined,
  Grant,
  IssuerCredentialSubjectDisplay,
  JWT_SIGNER_CALLBACK_REQUIRED_ERROR,
  OID4VCICredentialFormat,
} from '@sphereon/oid4vci-common'
import { CredentialSupportedBuilderV1_11, VcIssuer, VcIssuerBuilder } from '@sphereon/oid4vci-issuer'
import { CredentialFormat } from '@sphereon/ssi-types'
import bodyParser from 'body-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express, NextFunction, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'

import { handleTokenRequest, ITokenEndpointOpts, verifyTokenRequest } from './IssuerTokenEndpoint'
import { sendErrorResponse, validateRequestBody } from './expressUtils'

const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90

function buildVCIFromEnvironment() {
  const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
    .withCryptographicSuitesSupported(process.env.cryptographic_suites_supported as string)
    .withCryptographicBindingMethod(process.env.cryptographic_binding_methods_supported as string)
    .withFormat(process.env.credential_supported_format as unknown as OID4VCICredentialFormat)
    .withId(process.env.credential_supported_id as string)
    .withTypes([process.env.credential_supported_types_1 as string, process.env.credential_supported_types_2 as string])
    .withCredentialSupportedDisplay({
      name: process.env.credential_display_name as string,
      locale: process.env.credential_display_locale as string,
      logo: {
        url: process.env.credential_display_logo_url as string,
        alt_text: process.env.credential_display_logo_alt_text as string,
      },
      background_color: process.env.credential_display_background_color as string,
      text_color: process.env.credential_display_text_color as string,
    })
    .addCredentialSubjectPropertyDisplay(
      process.env.credential_subject_display_key1 as string,
      {
        name: process.env.credential_subject_display_key1_name as string,
        locale: process.env.credential_subject_display_key1_locale as string,
      } as IssuerCredentialSubjectDisplay // fixme: This is wrong (remove the cast and see it has no matches)
    )
    .build()
  return new VcIssuerBuilder()
    .withUserPinRequired(process.env.user_pin_required as unknown as boolean)
    .withAuthorizationServer(process.env.authorization_server as string)
    .withCredentialEndpoint(process.env.credential_endpoint as string)
    .withCredentialIssuer(process.env.credential_issuer as string)
    .withIssuerDisplay({
      name: process.env.issuer_name as string,
      locale: process.env.issuer_locale as string,
    })
    .withCredentialsSupported(credentialsSupported)
    .withInMemoryCredentialOfferState()
    .withInMemoryCNonceState()
    .build()
}

interface IOID4VCIServerOpts {
  tokenEndpointOpts?: ITokenEndpointOpts
  credentialOfferOpts?: {
    createOfferEndpointDisabled?: boolean // Disable the REST endpoint for creating offers. You can directly call the Issuer to create the offer object
    //todo: Add authn/z, as this endpoint would be called by an integration instead of wallets
  }
  serverOpts?: {
    app?: Express
    port?: number
    baseUrl?: string
    host?: string
  }
}

export class OID4VCIServer {
  private readonly _issuer: VcIssuer
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()
  private readonly _app: Express
  private readonly _baseUrl: URL
  private readonly cNonceExpiresIn: number
  private readonly tokenExpiresIn: number
  private readonly _server: http.Server

  public get app(): Express {
    return this._app
  }

  public get server(): http.Server {
    return this._server
  }

  constructor(
    opts?: IOID4VCIServerOpts & { issuer?: VcIssuer } /*If not supplied as argument, it will be fully configured from environment variables*/
  ) {
    dotenv.config()

    this._baseUrl = new URL(opts?.serverOpts?.baseUrl ?? process.env.BASE_URL ?? 'http://localhost')
    const httpPort = opts?.serverOpts?.port ?? getNumberOrUndefined(this._baseUrl.port) ?? getNumberOrUndefined(process.env.PORT) ?? 3000
    const host = opts?.serverOpts?.host ?? this._baseUrl.host.split(':')[0]

    if (!opts?.serverOpts?.app) {
      this._app = express()
      this.app.use(cors())
      this.app.use(bodyParser.urlencoded({ extended: true }))
      this.app.use(bodyParser.json())
      // this._app.use(cookieParser(secret))
    } else {
      this._app = opts.serverOpts.app
    }
    this._issuer = opts?.issuer ? opts.issuer : buildVCIFromEnvironment()

    this.pushedAuthorizationEndpoint()
    this.getMetadataEndpoint()
    if (!(opts?.credentialOfferOpts?.createOfferEndpointDisabled === true || process.env.CREDENTIAL_OFFER_ENDPOINT_DISABLED === 'true')) {
      this.createCredentialOfferEndpoint()
    }
    this.getCredentialOfferEndpoint()
    this.getCredentialEndpoint()
    this.assertAccessTokenHandling()
    if (!this.isTokenEndpointDisabled(opts?.tokenEndpointOpts)) {
      this.accessTokenEndpoint(opts?.tokenEndpointOpts)
    }
    this.cNonceExpiresIn = opts?.tokenEndpointOpts?.cNonceExpiresIn ?? 300000
    this.tokenExpiresIn = opts?.tokenEndpointOpts?.tokenExpiresIn ?? 300000
    this._server = this.app.listen(httpPort, host, () => console.log(`HTTP server listening on port ${httpPort}`))
  }

  private accessTokenEndpoint(tokenEndpointOpts?: ITokenEndpointOpts) {
    const issuerEndpoint = this.issuer.issuerMetadata.token_endpoint
    let path: string

    const accessTokenIssuer = tokenEndpointOpts?.accessTokenIssuer ?? process.env.ACCESS_TOKEN_ISSUER ?? this.issuer.issuerMetadata.credential_issuer

    const preAuthorizedCodeExpirationDuration =
      tokenEndpointOpts?.preAuthorizedCodeExpirationDuration ?? getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300000
    const interval = tokenEndpointOpts?.interval ?? getNumberOrUndefined(process.env.INTERVAL) ?? 300000
    const tokenExpiresIn = tokenEndpointOpts?.tokenExpiresIn ?? 300

    // todo: this means we cannot sign JWTs or issue access tokens when configured from env vars!
    if (tokenEndpointOpts?.accessTokenSignerCallback === undefined) {
      throw new Error(JWT_SIGNER_CALLBACK_REQUIRED_ERROR)
    } else if (!accessTokenIssuer) {
      throw new Error(ACCESS_TOKEN_ISSUER_REQUIRED_ERROR)
    }
    let url: URL
    let baseUrl = this._baseUrl?.toString()
    if (baseUrl.endsWith('/')) {
      baseUrl = baseUrl.substring(0, baseUrl.length - 1)
    }
    if (!issuerEndpoint) {
      path = this.extractPath(tokenEndpointOpts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token', true)
      // let's fix any baseUrl ending with a slash as path will always start with a slash

      url = new URL(`${baseUrl}${path}`)
      this.issuer.issuerMetadata.token_endpoint = url.toString()
    } else {
      this.assertEndpointHasIssuerBaseUrl(issuerEndpoint)
      path = this.extractPath(issuerEndpoint)
      url = new URL(`${baseUrl}${path}`)
    }

    this.app.post(
      url.pathname,
      verifyTokenRequest({
        issuer: this.issuer,
        preAuthorizedCodeExpirationDuration,
      }),
      handleTokenRequest({
        issuer: this.issuer,
        accessTokenSignerCallback: tokenEndpointOpts.accessTokenSignerCallback,
        cNonceExpiresIn: this.issuer.cNonceExpiresIn,
        interval,
        tokenExpiresIn,
        accessTokenIssuer,
      })
    )
  }

  private getMetadataEndpoint() {
    let basePath = this.extractPath(this._baseUrl.toString())
    if (basePath.endsWith('/')) {
      basePath = basePath.substring(0, basePath.length - 1)
    }
    const path = basePath + '/.well-known/openid-credential-issuer'
    this.app.get(path, (request: Request, response: Response) => {
      return response.send(this.issuer.issuerMetadata)
    })
  }

  private getCredentialEndpoint() {
    const endpoint = this.issuer.issuerMetadata.credential_endpoint
    let path: string
    if (!endpoint) {
      path = this._baseUrl.toString().endsWith('/') ? 'credentials' : '/credentials'
      this.issuer.issuerMetadata.credential_endpoint = `${this._baseUrl}${path}`
    } else {
      this.assertEndpointHasIssuerBaseUrl(endpoint)
      path = this.extractPath(endpoint)
    }
    this.app.post(path, async (request: Request, response: Response) => {
      try {
        const credentialRequest = request.body as CredentialRequestV1_0_11
        const credential = await this.issuer.issueCredential({
          credentialRequest: credentialRequest,
          tokenExpiresIn: this.tokenExpiresIn,
          cNonceExpiresIn: this.cNonceExpiresIn,
        })
        return response.send(credential)
      } catch (e) {
        return sendErrorResponse(
          response,
          500,
          {
            error: 'invalid_request',
            error_description: (e as Error).message,
          },
          e
        )
      }
    })
  }

  // fixme authz and enable/disable
  private createCredentialOfferEndpoint() {
    this.app.post('/credential-offers', async (request: Request<CredentialOfferV1_0_11>, response: Response) => {
      const grantTypes = determineGrantTypes(request.body)
      if (grantTypes.length === 0) {
        return sendErrorResponse(response, 400, 'No grant type supplied')
      }
      const grants = request.body.grants as Grant
      const credentials = request.body.credentials as (string | CredentialFormat)[]
      if (!credentials || credentials.length === 0) {
        return sendErrorResponse(response, 400, 'No credentials supplied')
      }

      try {
        const uri = await this.issuer.createCredentialOfferURI({ grants, credentials })
        return response.send(JSON.stringify({ uri }))
      } catch (e) {
        return sendErrorResponse(
          response,
          500,
          {
            error: 'invalid_request',
            error_description: (e as Error).message,
          },
          e
        )
      }
    })
  }

  private getCredentialOfferEndpoint() {
    this.app.get('/credential-offers/:id', async (request: Request, response: Response) => {
      const { id } = request.params
      try {
        const session = await this.issuer.credentialOfferSessions.get(id)
        if (!session || !session.credentialOffer) {
          return sendErrorResponse(response, 404, {
            error: 'invalid_request',
            error_description: `Credential offer ${id} not found`,
          })
        }
        return response.send(JSON.stringify(session.credentialOffer.credential_offer))
      } catch (e) {
        return sendErrorResponse(
          response,
          500,
          {
            error: 'invalid_request',
            error_description: (e as Error).message,
          },
          e
        )
      }
    })
  }

  private pushedAuthorizationEndpoint() {
    const handleHttpStatus400 = async (req: Request, res: Response, next: NextFunction) => {
      if (!req.body) {
        return res.status(400).send({ error: 'invalid_request', error_description: 'Request body must be present' })
      }
      const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
      const conditional = ['authorization_details', 'scope']
      try {
        validateRequestBody({ required, conditional, body: req.body })
      } catch (e: unknown) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_request',
          error_description: (e as Error).message,
        })
      }
      return next()
    }

    this.app.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
      // FIXME Fake client for testing, it needs to come from a registered client
      const client = {
        scope: ['openid', 'test'],
        redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart', 'http:*'],
      }

      // For security reasons the redirect_uri from the request needs to be matched against the ones present in the registered client
      const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
      if (!matched.length) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_request',
          error_description: 'redirect_uri is not valid for the given client',
        })
      }

      // The scopes from the request need to be matched against the ones present in the registered client
      if (!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_scope',
          error_description: 'scope is not valid for the given client',
        })
      }

      //TODO Implement authorization_details verification

      // TODO: Both UUID and requestURI need to be configurable for the server
      const uuid = uuidv4()
      const requestUri = `urn:ietf:params:oauth:request_uri:${uuid}`
      // The redirect_uri is created and set in a map, to keep track of the actual request
      this.authRequestsData.set(requestUri, req.body)
      // Invalidates the request_uri removing it from the mapping after it is expired, needs to be refactored because
      // some of the properties will be needed in subsequent steps if the authorization succeeds
      // TODO in the /token endpoint the code_challenge must be matched against the hashed code_verifier
      setTimeout(() => {
        this.authRequestsData.delete(requestUri)
      }, expiresIn * 1000)

      return res.status(201).json({ request_uri: requestUri, expires_in: expiresIn })
    })
  }

  get issuer(): VcIssuer {
    return this._issuer
  }

  public stop() {
    this.server.close()
  }

  private isTokenEndpointDisabled(tokenEndpointOpts?: ITokenEndpointOpts) {
    return tokenEndpointOpts?.tokenEndpointDisabled === true || process.env.TOKEN_ENDPOINT_DISABLED === 'true'
  }

  private assertAccessTokenHandling(tokenEndpointOpts?: ITokenEndpointOpts) {
    const authServer = this.issuer.issuerMetadata.authorization_server
    if (this.isTokenEndpointDisabled(tokenEndpointOpts)) {
      if (!authServer) {
        throw Error(
          `No Authorization Server (AS) is defined in the issuer metadata and the token endpoint is disabled. An AS or token endpoints needs to be present`
        )
      }
      console.log('Token endpoint disabled by configuration')
    } else {
      if (authServer) {
        throw Error(
          `A Authorization Server (AS) was already enabled in the issuer metadata (${authServer}). Cannot both have an AS and enable the token endpoint at the same time `
        )
      }
    }
  }

  private extractPath(endpoint: string, skipBaseUrlCheck?: boolean) {
    if (endpoint.startsWith('/')) {
      return endpoint
    }
    if (skipBaseUrlCheck !== true) {
      this.assertEndpointHasIssuerBaseUrl(endpoint)
    }
    let path = endpoint
    if (endpoint.toLowerCase().includes('://')) {
      path = new URL(endpoint).pathname
    }
    return path.startsWith('/') ? path : `/${path}`
  }

  private assertEndpointHasIssuerBaseUrl(endpoint: string) {
    if (!endpoint.startsWith(this._baseUrl.toString())) {
      throw Error(`endpoint '${endpoint}' does not have base url '${this._baseUrl}'`)
    }
  }
}