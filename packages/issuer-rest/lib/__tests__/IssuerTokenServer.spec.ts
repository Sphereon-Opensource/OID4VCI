import { KeyObject } from 'crypto'

import {
  Alg,
  CNonceState,
  CredentialIssuerMetadataOptsV1_0_13,
  CredentialOfferSession,
  IssueStatus,
  Jwt,
  STATE_MISSING_ERROR,
  URIState,
} from '@sphereon/oid4vci-common'
import { VcIssuer } from '@sphereon/oid4vci-issuer'
import { MemoryStates } from '@sphereon/oid4vci-issuer/dist/state-manager'
import { ExpressBuilder, ExpressSupport } from '@sphereon/ssi-express-support'
import { DIDDocument } from 'did-resolver'
import { Express } from 'express'
import * as jose from 'jose'
import requests from 'supertest'
import { v4 } from 'uuid'

import { OID4VCIServer } from '../OID4VCIServer'

describe('OID4VCIServer', () => {
  let app: Express
  let expressSupport: ExpressSupport
  // let server: http.Server
  const preAuthorizedCode1 = 'SplxlOBeZQQYbYS6WxSbIA1'
  const preAuthorizedCode2 = 'SplxlOBeZQQYbYS6WxSbIA2'
  const preAuthorizedCode3 = 'SplxlOBeZQQYbYS6WxSbIA3'

  beforeAll(async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const signerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
      const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
      return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header, alg: Alg.ES256 }).sign(privateKey)
    }

    const credentialOfferState1: CredentialOfferSession = {
      preAuthorizedCode: preAuthorizedCode1,
      userPin: '493536',
      notification_id: v4(),
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'test_issuer',
          credentials: [
            {
              format: 'ldp_vc',
              credential_definition: {
                '@context': ['test_context'],
                types: ['VerifiableCredential'],
                credentialSubject: {},
              },
            },
          ],

          grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              user_pin_required: true,
              tx_code: {
                length: 6,
                input_mode: 'numeric',
                description: 'Please enter the 6 digit code you received on your phone',
              },
              'pre-authorized_code': preAuthorizedCode1,
            },
          },
        },
      },
    }
    const credentialOfferState2: CredentialOfferSession = {
      ...credentialOfferState1,
      preAuthorizedCode: preAuthorizedCode2,
      credentialOffer: {
        ...credentialOfferState1.credentialOffer,
        credential_offer: {
          ...credentialOfferState1.credentialOffer.credential_offer,

          grants: {
            ...credentialOfferState1.credentialOffer.credential_offer!.grants!,
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              ...credentialOfferState1.credentialOffer.credential_offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
              'pre-authorized_code': preAuthorizedCode2,
            },
          },
        },
      },
    }
    const credentialOfferState3: CredentialOfferSession = { ...credentialOfferState1, preAuthorizedCode: preAuthorizedCode3, createdAt: 0 }
    const credentialOfferSessions = new MemoryStates<CredentialOfferSession>()
    await credentialOfferSessions.set(preAuthorizedCode1, credentialOfferState1)
    await credentialOfferSessions.set(preAuthorizedCode2, credentialOfferState2)
    await credentialOfferSessions.set(preAuthorizedCode3, credentialOfferState3)

    const vcIssuer: VcIssuer<DIDDocument> = new VcIssuer<DIDDocument>(
      {
        // authorization_server: 'https://authorization-server',
        credential_endpoint: 'http://localhost:9000',
        credential_issuer: 'https://credential-issuer',
        display: [{ name: 'example issuer', locale: 'en-US' }],
        credential_configurations_supported: {
          UniversityDegree_JWT: {
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
              credentialSubject: {
                given_name: {
                  display: [
                    {
                      name: 'given name',
                      locale: 'en-US',
                    },
                  ],
                },
              },
            },
            format: 'jwt_vc_json',
            credential_signing_alg_values_supported: ['ES256K'],
            cryptographic_binding_methods_supported: ['did'],
            display: [
              {
                name: 'University Credential',
                locale: 'en-US',
                logo: {
                  url: 'https://exampleuniversity.com/public/logo.png',
                  alt_text: 'a square logo of a university',
                },
                background_color: '#12107c',
                text_color: '#FFFFFF',
              },
            ],
          },
        },
      } as CredentialIssuerMetadataOptsV1_0_13,
      {
        cNonceExpiresIn: 300,
        credentialOfferSessions,
        cNonces: new MemoryStates<CNonceState>(),
        uris: new MemoryStates<URIState>(),
      },
    )

    expressSupport = ExpressBuilder.fromServerOpts({
      startListening: false,
      port: 9000,
      hostname: '0.0.0.0',
    }).build({ startListening: false })
    const vcIssuerServer = new OID4VCIServer(expressSupport, {
      issuer: vcIssuer,
      baseUrl: 'http://localhost:9000',
      endpointOpts: {
        tokenEndpointOpts: {
          accessTokenSignerCallback: signerCallback,
          accessTokenIssuer: 'https://www.example.com',
          preAuthorizedCodeExpirationDuration: 2000,
          tokenExpiresIn: 300,
        },
      },
    })
    expressSupport.start()
    app = vcIssuerServer.app
  })

  afterAll(async () => {
    if (expressSupport) {
      await expressSupport.stop()
    }
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should return the access token', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode1}&user_pin=493536`)
    expect(res.statusCode).toEqual(200)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      access_token: expect.stringContaining('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQi'),
      token_type: 'bearer',
      expires_in: 300,
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      authorization_pending: false,
      interval: 300,
    })
  })
  it('should return http code 400 with message User pin is required', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode1}&user_pin=12345678`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'PIN is invalid',
    })
  })
  it('should return http code 400 with message pre-authorized_code is required', async () => {
    const res = await requests(app).post('/token').send('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&user_pin=493536')
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: 'pre-authorized_code is required',
    })
  })
  it('should return http code 400 with message unsupported grant_type', async () => {
    const res = await requests(app).post('/token').send(`grant_type=non-existent&pre-authorized_code=${preAuthorizedCode1}&user_pin=493536`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'unsupported grant_type',
    })
  })
  it('should return http code 400 with message PIN does not match', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode1}&user_pin=493537`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'PIN is invalid',
    })
  })
  it('should return http code 400 with message PIN must consist of maximum 8 numeric characters', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode1}&user_pin=invalid`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'PIN must consist of maximum 8 numeric characters',
    })
  })
  it('should return http code 400 with message pre-authorized_code not found', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=test&user_pin=493536`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: STATE_MISSING_ERROR + ' (test)',
    })
  })
  it('should return http code 400 with message User pin is not required', async () => {
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode2}&user_pin=493536`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: 'User pin is not required',
    })
  })
  it('should return http code 400 with message pre-authorized code expired', async () => {
    await new Promise((r) => setTimeout(r, 2000))
    const res = await requests(app)
      .post('/token')
      .send(`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=${preAuthorizedCode3}&user_pin=493536`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'pre-authorized_code is expired',
    })
  })
})
