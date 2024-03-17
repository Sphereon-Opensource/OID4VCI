import {
  ALG_ERROR,
  AUD_ERROR,
  CNonceState,
  CreateCredentialOfferURIResult,
  CREDENTIAL_MISSING_ERROR,
  CredentialDataSupplierInput,
  CredentialIssuerMetadataOpts,
  CredentialOfferFormat,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferSession,
  CredentialOfferV1_0_11,
  CredentialRequestV1_0_11,
  CredentialResponse,
  DID_NO_DIDDOC_ERROR,
  Grant,
  IAT_ERROR,
  ISSUER_CONFIG_ERROR,
  IssueStatus,
  IStateManager,
  JsonLdIssuerCredentialDefinition,
  JWT_VERIFY_CONFIG_ERROR,
  JWTVerifyCallback,
  JwtVerifyResult,
  KID_DID_NO_DID_ERROR,
  KID_JWK_X5C_ERROR,
  NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  QRCodeOpts,
  TokenErrorResponse,
  toUniformCredentialOfferRequest,
  TYP_ERROR,
  UniformCredentialRequest,
  URIState,
} from '@sphereon/oid4vci-common'
import { CompactSdJwtVc, CredentialMapper, W3CVerifiableCredential } from '@sphereon/ssi-types'
import { v4 } from 'uuid'

import { assertValidPinNumber, createCredentialOfferObject, createCredentialOfferURIFromObject } from './functions'
import { LookupStateManager } from './state-manager'
import { CredentialDataSupplier, CredentialDataSupplierArgs, CredentialIssuanceInput, CredentialSignerCallback } from './types'

export class VcIssuer<DIDDoc extends object> {
  private readonly _issuerMetadata: CredentialIssuerMetadataOpts
  private readonly _userPinRequired: boolean
  private readonly _defaultCredentialOfferBaseUri?: string
  private readonly _credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
  private readonly _jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
  private readonly _credentialDataSupplier?: CredentialDataSupplier
  private readonly _credentialOfferSessions: IStateManager<CredentialOfferSession>
  private readonly _cNonces: IStateManager<CNonceState>
  private readonly _uris?: IStateManager<URIState>
  private readonly _cNonceExpiresIn: number

  constructor(
    issuerMetadata: CredentialIssuerMetadataOpts,
    args: {
      userPinRequired?: boolean
      baseUri?: string
      credentialOfferSessions: IStateManager<CredentialOfferSession>
      defaultCredentialOfferBaseUri?: string
      cNonces: IStateManager<CNonceState>
      uris?: IStateManager<URIState>
      credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
      jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
      credentialDataSupplier?: CredentialDataSupplier
      cNonceExpiresIn?: number | undefined // expiration duration in seconds
    },
  ) {
    this._issuerMetadata = issuerMetadata
    this._defaultCredentialOfferBaseUri = args.defaultCredentialOfferBaseUri
    this._credentialOfferSessions = args.credentialOfferSessions
    this._cNonces = args.cNonces
    this._uris = args.uris
    this._userPinRequired = args?.userPinRequired ?? false
    this._credentialSignerCallback = args?.credentialSignerCallback
    this._jwtVerifyCallback = args?.jwtVerifyCallback
    this._credentialDataSupplier = args?.credentialDataSupplier
    this._cNonceExpiresIn = (args?.cNonceExpiresIn ?? (process.env.C_NONCE_EXPIRES_IN ? parseInt(process.env.C_NONCE_EXPIRES_IN) : 300)) as number
  }

  public getCredentialOfferSessionById(id: string): Promise<CredentialOfferSession> {
    if (!this.uris) {
      throw Error('Cannot lookup credential offer by id if URI state manager is not set')
    }
    return new LookupStateManager<URIState, CredentialOfferSession>(this.uris, this._credentialOfferSessions, 'uri').getAsserted(id)
  }

  public async createCredentialOfferURI(opts: {
    grants?: Grant
    credentials?: (CredentialOfferFormat | string)[]
    credentialDefinition?: JsonLdIssuerCredentialDefinition
    credentialOfferUri?: string
    credentialDataSupplierInput?: CredentialDataSupplierInput // Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
    baseUri?: string
    scheme?: string
    pinLength?: number
    qrCodeOpts?: QRCodeOpts
  }): Promise<CreateCredentialOfferURIResult> {
    let preAuthorizedCode: string | undefined = undefined
    let issuerState: string | undefined = undefined
    const { grants, credentials, credentialDefinition } = opts

    if (!grants?.authorization_code && !grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      throw Error(`No grant issuer state or pre-authorized code could be deduced`)
    }
    const credentialOfferPayload: CredentialOfferPayloadV1_0_11 = {
      ...(grants && { grants }),
      ...(credentials && { credentials }),
      ...(credentialDefinition && { credential_definition: credentialDefinition }),
      credential_issuer: this.issuerMetadata.credential_issuer,
    } as CredentialOfferPayloadV1_0_11
    if (grants?.authorization_code) {
      issuerState = grants?.authorization_code.issuer_state
      if (!issuerState) {
        issuerState = v4()
        grants.authorization_code.issuer_state = issuerState
      }
    }

    let userPinRequired: boolean | undefined
    if (grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      preAuthorizedCode = grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']
      userPinRequired = grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.user_pin_required
      if (userPinRequired === undefined) {
        userPinRequired = false
        grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].user_pin_required = userPinRequired
      }
      if (!preAuthorizedCode) {
        preAuthorizedCode = v4()
        grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'] = preAuthorizedCode
      }
    }

    const baseUri = opts?.baseUri ?? this.defaultCredentialOfferBaseUri

    const credentialOfferObject = createCredentialOfferObject(this._issuerMetadata, {
      ...opts,
      credentialOffer: credentialOfferPayload,
      baseUri,
      userPinRequired,
      preAuthorizedCode,
      issuerState,
    })

    let userPin: string | undefined
    // todo: Double check this can only happen in pre-auth flow and if so make sure to not do the below when in a state is present (authorized flow)
    if (userPinRequired) {
      const pinLength = opts.pinLength ?? 4

      userPin = ('' + Math.round((Math.pow(10, pinLength) - 1) * Math.random())).padStart(pinLength, '0')
      assertValidPinNumber(userPin)
    }
    const createdAt = +new Date()
    const lastUpdatedAt = createdAt
    if (opts?.credentialOfferUri) {
      if (!this.uris) {
        throw Error('No URI state manager set, whilst apparently credential offer URIs are being used')
      }
      await this.uris.set(opts.credentialOfferUri, {
        uri: opts.credentialOfferUri,
        createdAt: createdAt,
        preAuthorizedCode,
        issuerState,
      })
    }

    const credentialOffer = await toUniformCredentialOfferRequest(
      {
        credential_offer: credentialOfferObject.credential_offer,
        credential_offer_uri: credentialOfferObject.credential_offer_uri,
      } as CredentialOfferV1_0_11,
      {
        version: OpenId4VCIVersion.VER_1_0_11,
        resolve: false, // We are creating the object, so do not resolve
      },
    )

    const status = IssueStatus.OFFER_CREATED
    const session: CredentialOfferSession = {
      preAuthorizedCode,
      issuerState,
      createdAt,
      lastUpdatedAt,
      status,
      ...(userPin && { userPin }),
      ...(opts.credentialDataSupplierInput && { credentialDataSupplierInput: opts.credentialDataSupplierInput }),
      credentialOffer,
    }

    if (preAuthorizedCode) {
      await this.credentialOfferSessions.set(preAuthorizedCode, session)
    }
    // todo: check whether we could have the same value for issuer state and pre auth code if both are supported.
    if (issuerState) {
      await this.credentialOfferSessions.set(issuerState, session)
    }

    const uri = createCredentialOfferURIFromObject(credentialOffer, { ...opts, baseUri })
    let qrCodeDataUri: string | undefined
    if (opts.qrCodeOpts) {
      const { AwesomeQR } = await import('awesome-qr')
      console.log(uri)

      const qrCode = new AwesomeQR({ ...opts.qrCodeOpts, text: uri })
      qrCodeDataUri = `data:image/png;base64,${(await qrCode.draw())!.toString('base64')}`
    }
    return {
      session,
      uri,
      qrCodeDataUri,
      userPinRequired: userPinRequired ?? false,
      ...(userPin !== undefined && { userPin, pinLength: userPin?.length ?? 0 }),
    }
  }

  /**
   * issueCredentialFromIssueRequest
   * @param opts issuerRequestParams
   *  - issueCredentialsRequest the credential request
   *  - issuerState the state of the issuer
   *  - jwtVerifyCallback callback that verifies the Proof of Possession JWT
   *  - issuerCallback callback to issue a Verifiable Credential
   *  - cNonce an existing c_nonce
   */
  public async issueCredential(opts: {
    credentialRequest: CredentialRequestV1_0_11
    credential?: CredentialIssuanceInput
    credentialDataSupplier?: CredentialDataSupplier
    credentialDataSupplierInput?: CredentialDataSupplierInput
    newCNonce?: string
    cNonceExpiresIn?: number
    tokenExpiresIn?: number
    jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
    credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
    responseCNonce?: string
  }): Promise<CredentialResponse> {
    let preAuthorizedCode: string | undefined
    let issuerState: string | undefined
    try {
      if (!this.isMetadataSupportCredentialRequestFormat(opts.credentialRequest.format)) {
        throw new Error(TokenErrorResponse.invalid_request)
      }
      const validated = await this.validateCredentialRequestProof({
        ...opts,
        tokenExpiresIn: opts.tokenExpiresIn ?? 180,
      })
      preAuthorizedCode = validated.preAuthorizedCode
      issuerState = validated.issuerState

      const { preAuthSession, authSession, cNonceState, jwtVerifyResult } = validated
      const did = jwtVerifyResult.did
      const jwk = jwtVerifyResult.jwk
      const kid = jwtVerifyResult.kid
      const newcNonce = opts.newCNonce ? opts.newCNonce : v4()
      const newcNonceState = {
        cNonce: newcNonce,
        createdAt: +new Date(),
        ...(authSession?.issuerState && { issuerState: authSession.issuerState }),
        ...(preAuthSession && { preAuthorizedCode: preAuthSession.preAuthorizedCode }),
      }
      await this.cNonces.set(newcNonce, newcNonceState)
      if (!opts.credential && this._credentialDataSupplier === undefined && opts.credentialDataSupplier === undefined) {
        throw Error(`Either a credential needs to be supplied or a credentialDataSupplier`)
      }
      let credential: CredentialIssuanceInput | undefined
      let format: OID4VCICredentialFormat = opts.credentialRequest.format
      let signerCallback: CredentialSignerCallback<DIDDoc> | undefined = opts.credentialSignerCallback
      if (opts.credential) {
        credential = opts.credential
      } else {
        const credentialDataSupplier: CredentialDataSupplier | undefined =
          typeof opts.credentialDataSupplier === 'function' ? opts.credentialDataSupplier : this._credentialDataSupplier
        if (typeof credentialDataSupplier !== 'function') {
          throw Error('Data supplier is mandatory if no credential is supplied')
        }
        const session = preAuthorizedCode && preAuthSession ? preAuthSession : authSession
        if (!session) {
          throw Error('Either a preAuth or Auth session is required, none found')
        }
        const credentialOffer = session.credentialOffer
        if (!credentialOffer) {
          throw Error('Credential Offer missing')
        }
        const credentialDataSupplierInput = opts.credentialDataSupplierInput ?? session.credentialDataSupplierInput

        const result = await credentialDataSupplier({
          ...cNonceState,
          credentialRequest: opts.credentialRequest,
          credentialSupplierConfig: this._issuerMetadata.credential_supplier_config,
          credentialOffer /*todo: clientId: */,
          ...(credentialDataSupplierInput && { credentialDataSupplierInput }),
        } as CredentialDataSupplierArgs)
        credential = result.credential
        if (result.format) {
          format = result.format
        }
        if (typeof result.signCallback === 'function') {
          signerCallback = result.signCallback
        }
      }
      if (!credential) {
        throw Error('A credential needs to be supplied at this point')
      }
      // Bind credential to the provided proof of possession
      if (CredentialMapper.isSdJwtDecodedCredentialPayload(credential) && (kid || jwk) && !credential.cnf) {
        if (kid) {
          credential.cnf = {
            kid,
          }
        } else if (jwk) {
          credential.cnf = {
            jwk,
          }
        }
      }
      if (did && !CredentialMapper.isSdJwtDecodedCredentialPayload(credential)) {
        const credentialSubjects = Array.isArray(credential.credentialSubject) ? credential.credentialSubject : [credential.credentialSubject]
        credentialSubjects.map((subject) => {
          if (!subject.id) {
            subject.id = did
          }
          return subject
        })
        credential.credentialSubject = Array.isArray(credential.credentialSubject) ? credentialSubjects : credentialSubjects[0]
      }

      const verifiableCredential = await this.issueCredentialImpl(
        {
          credentialRequest: opts.credentialRequest,
          format,
          credential,
          jwtVerifyResult,
        },
        signerCallback,
      )
      // TODO implement acceptance_token (deferred response)
      // TODO update verification accordingly
      if (!verifiableCredential) {
        // credential: OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned. MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements
        throw new Error(CREDENTIAL_MISSING_ERROR)
      }
      // remove the previous nonce
      await this.cNonces.delete(cNonceState.cNonce)

      if (preAuthorizedCode && preAuthSession) {
        preAuthSession.lastUpdatedAt = +new Date()
        preAuthSession.status = IssueStatus.CREDENTIAL_ISSUED
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      } else if (issuerState && authSession) {
        // If both were set we used the pre auth flow above as well, hence the else if
        authSession.lastUpdatedAt = +new Date()
        authSession.status = IssueStatus.CREDENTIAL_ISSUED
        await this._credentialOfferSessions.set(issuerState, authSession)
      }

      return {
        credential: verifiableCredential,
        format: opts.credentialRequest.format,
        c_nonce: newcNonce,
        c_nonce_expires_in: this._cNonceExpiresIn,
      }
    } catch (error: unknown) {
      await this.updateErrorStatus({ preAuthorizedCode, issuerState, error })
      throw error
    }
  }

  private async updateErrorStatus({
    preAuthorizedCode,
    error,
    issuerState,
  }: {
    preAuthorizedCode: string | undefined
    issuerState: string | undefined
    error: unknown
  }) {
    if (preAuthorizedCode) {
      const preAuthSession = await this._credentialOfferSessions.get(preAuthorizedCode)
      if (preAuthSession) {
        preAuthSession.lastUpdatedAt = +new Date()
        preAuthSession.status = IssueStatus.ERROR
        preAuthSession.error = error instanceof Error ? error.message : error?.toString()
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      }
    }
    if (issuerState) {
      const authSession = await this._credentialOfferSessions.get(issuerState)
      if (authSession) {
        authSession.lastUpdatedAt = +new Date()
        authSession.status = IssueStatus.ERROR
        authSession.error = error instanceof Error ? error.message : error?.toString()
        await this._credentialOfferSessions.set(issuerState, authSession)
      }
    }
  }

  /*
    private async retrieveGrantsAndCredentialOfferSession(id: string): Promise<{
      clientId?: string;
      grants?: Grant,
      session: CredentialOfferSession
    }> {
      const session: CredentialOfferSession | undefined = await this._credentialOfferSessions.getAsserted(id)
      const clientId = session?.clientId
      const grants = session?.credentialOffer?.credential_offer?.grants
      if (!grants?.authorization_code?.issuer_state && !grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']) {
        throw new Error(GRANTS_MUST_NOT_BE_UNDEFINED)
      }
      return { session, clientId, grants }
    }*/

  private async validateCredentialRequestProof({
    credentialRequest,
    jwtVerifyCallback,
    tokenExpiresIn,
  }: {
    credentialRequest: UniformCredentialRequest
    tokenExpiresIn: number
    // grants?: Grant,
    clientId?: string
    jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
  }) {
    let preAuthorizedCode: string | undefined
    let issuerState: string | undefined

    const supportedIssuanceFormats = ['jwt_vc_json', 'jwt_vc_json-ld', 'vc+sd-jwt', 'ldp_vc']
    try {
      if (!supportedIssuanceFormats.includes(credentialRequest.format)) {
        throw Error(`Format ${credentialRequest.format} not supported yet`)
      } else if (typeof this._jwtVerifyCallback !== 'function' && typeof jwtVerifyCallback !== 'function') {
        throw new Error(JWT_VERIFY_CONFIG_ERROR)
      } else if (!credentialRequest.proof) {
        throw Error('Proof of possession is required. No proof value present in credential request')
      }

      const jwtVerifyResult = jwtVerifyCallback
        ? await jwtVerifyCallback(credentialRequest.proof)
        : // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          await this._jwtVerifyCallback!(credentialRequest.proof)

      const { didDocument, did, jwt } = jwtVerifyResult
      const { header, payload } = jwt
      const { iss, aud, iat, nonce } = payload
      if (!nonce) {
        throw Error('No nonce was found in the Proof of Possession')
      }
      const cNonceState = await this.cNonces.getAsserted(nonce)
      preAuthorizedCode = cNonceState.preAuthorizedCode
      issuerState = cNonceState.issuerState
      const createdAt = cNonceState.createdAt
      // The verify callback should set the correct values, but let's look at the JWT ourselves to to be sure
      const alg = jwtVerifyResult.alg ?? header.alg
      const kid = jwtVerifyResult.kid ?? header.kid
      const jwk = jwtVerifyResult.jwk ?? header.jwk
      const x5c = jwtVerifyResult.x5c ?? header.x5c
      const typ = header.typ

      if (typ !== 'openid4vci-proof+jwt') {
        throw Error(TYP_ERROR)
      } else if (!alg) {
        throw Error(ALG_ERROR)
      } else if (!([kid, jwk, x5c].filter((x) => !!x).length === 1)) {
        // only 1 is allowed, but need to look into whether jwk and x5c are allowed together
        throw Error(KID_JWK_X5C_ERROR)
      } else if (kid && !did) {
        // Make sure the callback function extracts the DID from the kid
        throw Error(KID_DID_NO_DID_ERROR)
      } else if (did && !didDocument) {
        // Make sure the callback function does DID resolution when a did is present
        throw Error(DID_NO_DIDDOC_ERROR)
      }

      const preAuthSession = preAuthorizedCode ? await this.credentialOfferSessions.get(preAuthorizedCode) : undefined
      const authSession = issuerState ? await this.credentialOfferSessions.get(issuerState) : undefined
      if (!preAuthSession && !authSession) {
        throw Error('Either a pre-authorized code or issuer state needs to be present')
      }
      if (preAuthSession) {
        if (!preAuthSession.preAuthorizedCode || preAuthSession.preAuthorizedCode !== preAuthorizedCode) {
          throw Error('Invalid pre-authorized code')
        }
        preAuthSession.lastUpdatedAt = +new Date()
        preAuthSession.status = IssueStatus.CREDENTIAL_REQUEST_RECEIVED
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      }
      if (authSession) {
        if (!authSession.issuerState || authSession.issuerState !== issuerState) {
          throw Error('Invalid issuer state')
        }
        authSession.lastUpdatedAt = +new Date()
        authSession.status = IssueStatus.CREDENTIAL_REQUEST_RECEIVED
      }

      // https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
      // A client MAY use the "client_id" request parameter to identify itself
      // when sending requests to the token endpoint.  In the
      // "authorization_code" "grant_type" request to the token endpoint, an
      // unauthenticated client MUST send its "client_id" to prevent itself
      // from inadvertently accepting a code intended for a client with a
      // different "client_id".  This protects the client from substitution of
      // the authentication code.  (It provides no additional security for the
      // protected resource.)
      if (!iss && authSession?.credentialOffer.credential_offer?.grants?.authorization_code) {
        throw new Error(NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT)
      }
      // iss: OPTIONAL (string). The value of this claim MUST be the client_id of the client making the credential request.
      // This claim MUST be omitted if the Access Token authorizing the issuance call was obtained from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
      // TODO We need to investigate further what the comment above means, because it's not clear if the client or the user may be authorized anonymously
      // if (iss && grants && grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      //   throw new Error(ISS_PRESENT_IN_PRE_AUTHORIZED_CODE_CONTEXT)
      // }
      /*if (iss && iss !== clientId) {
        throw new Error(ISS_MUST_BE_CLIENT_ID + `iss: ${iss}, client_id: ${clientId}`)
      }*/
      if (!aud || aud !== this._issuerMetadata.credential_issuer) {
        throw new Error(AUD_ERROR)
      }
      if (!iat) {
        throw new Error(IAT_ERROR)
      } else if (iat > createdAt + tokenExpiresIn * 1000) {
        throw new Error(IAT_ERROR)
      }
      // todo: Add a check of iat against current TS on server with a skew

      return { jwtVerifyResult, preAuthorizedCode, preAuthSession, issuerState, authSession, cNonceState }
    } catch (error: unknown) {
      await this.updateErrorStatus({ preAuthorizedCode, issuerState, error })
      throw error
    }
  }

  private isMetadataSupportCredentialRequestFormat(requestFormat: string | string[]): boolean {
    for (const credentialSupported of this._issuerMetadata.credentials_supported) {
      if (!Array.isArray(requestFormat) && credentialSupported.format === requestFormat) {
        return true
      } else if (Array.isArray(requestFormat)) {
        for (const format of requestFormat as string[]) {
          if (credentialSupported.format === format) {
            return true
          }
        }
      }
    }
    return false
  }

  private async issueCredentialImpl(
    opts: {
      credentialRequest: UniformCredentialRequest
      credential: CredentialIssuanceInput
      jwtVerifyResult: JwtVerifyResult<DIDDoc>
      format?: OID4VCICredentialFormat
    },
    issuerCallback?: CredentialSignerCallback<DIDDoc>,
  ): Promise<W3CVerifiableCredential | CompactSdJwtVc> {
    if ((!opts.credential && !opts.credentialRequest) || !this._credentialSignerCallback) {
      throw new Error(ISSUER_CONFIG_ERROR)
    }
    return issuerCallback ? await issuerCallback(opts) : this._credentialSignerCallback(opts)
  }

  get userPinRequired(): boolean {
    return this._userPinRequired
  }

  get credentialSignerCallback(): CredentialSignerCallback<DIDDoc> | undefined {
    return this._credentialSignerCallback
  }

  get jwtVerifyCallback(): JWTVerifyCallback<DIDDoc> | undefined {
    return this._jwtVerifyCallback
  }

  get credentialDataSupplier(): CredentialDataSupplier | undefined {
    return this._credentialDataSupplier
  }

  get uris(): IStateManager<URIState> | undefined {
    return this._uris
  }

  get cNonceExpiresIn(): number {
    return this._cNonceExpiresIn
  }

  public get credentialOfferSessions(): IStateManager<CredentialOfferSession> {
    return this._credentialOfferSessions
  }

  public get cNonces(): IStateManager<CNonceState> {
    return this._cNonces
  }

  get defaultCredentialOfferBaseUri(): string | undefined {
    return this._defaultCredentialOfferBaseUri
  }

  public get issuerMetadata() {
    return this._issuerMetadata
  }
}
