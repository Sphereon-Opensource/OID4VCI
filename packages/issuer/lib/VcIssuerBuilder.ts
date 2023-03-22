import {
  ICredentialIssuerMetadataParametersV1_11,
  ICredentialSupportedV1_11,
  IIssuerDisplay,
  invalid_request,
} from '@sphereon/openid4vci-common'

import { VcIssuer } from './VcIssuer'

export class VcIssuerBuilder {
  credentialIssuer?: string
  authorizationServer?: string
  credentialEndpoint?: string
  batchCredentialEndpoint?: string
  issuerDisplay?: IIssuerDisplay[]
  credentialsSupported?: ICredentialSupportedV1_11[]
  userPinRequired?: boolean

  public withCredentialIssuer(issuer: string): VcIssuerBuilder {
    this.credentialIssuer = issuer
    return this
  }
  public withAuthorizationServer(authorizationServer: string): VcIssuerBuilder {
    this.authorizationServer = authorizationServer
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): VcIssuerBuilder {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string): VcIssuerBuilder {
    this.batchCredentialEndpoint = batchCredentialEndpoint
    return this
  }

  public withIssuerDisplay(issuerDisplay: IIssuerDisplay | IIssuerDisplay[]): VcIssuerBuilder {
    if (!Array.isArray(issuerDisplay)) this.issuerDisplay = this.issuerDisplay ? [...this.issuerDisplay, issuerDisplay] : [issuerDisplay]
    else {
      this.issuerDisplay = this.issuerDisplay ? [...this.issuerDisplay, ...issuerDisplay] : issuerDisplay
    }
    return this
  }

  public withCredentialsSupported(credentialSupported: ICredentialSupportedV1_11 | ICredentialSupportedV1_11[]): VcIssuerBuilder {
    if (!Array.isArray(credentialSupported))
      this.credentialsSupported = this.credentialsSupported ? [...this.credentialsSupported, credentialSupported] : [credentialSupported]
    else {
      this.credentialsSupported = this.credentialsSupported ? [...this.credentialsSupported, ...credentialSupported] : credentialSupported
    }
    return this
  }

  public withUserPinRequired(userPinRequired: boolean): VcIssuerBuilder {
    this.userPinRequired = userPinRequired
    return this
  }

  public build(): VcIssuer {
    if (!this.credentialEndpoint || !this.credentialIssuer || !this.credentialsSupported) {
      throw new Error(invalid_request)
    }
    if (!this.userPinRequired) {
      this.userPinRequired = false
    }
    const metadata: ICredentialIssuerMetadataParametersV1_11 = {
      credential_endpoint: this.credentialEndpoint,
      credential_issuer: this.credentialIssuer,
      credentials_supported: this.credentialsSupported,
    }
    if (this.issuerDisplay) {
      metadata.display = this.issuerDisplay
    }
    if (this.batchCredentialEndpoint) {
      metadata.batch_credential_endpoint = this.batchCredentialEndpoint
    }
    if (this.authorizationServer) {
      metadata.authorization_server = this.authorizationServer
    }
    return new VcIssuer(metadata, this.userPinRequired)
  }
}