import { JWK } from 'common/dist';

import { ExperimentalSubjectIssuance } from '../experimental/holder-vci';

import { ProofOfPossession } from './CredentialIssuance.types';
import {
  AlgValue,
  CommonCredentialRequest,
  CredentialDataSupplierInput,
  CredentialRequestSdJwtVc,
  CredentialsSupportedDisplay,
  CredentialSupplierConfig,
  EncValue,
  Grant,
  IssuerCredentialSubject,
  MetadataDisplay,
  OID4VCICredentialFormat,
  ProofTypesSupported,
  ResponseEncryption,
} from './Generic.types';
import { QRCodeOpts } from './QRCode.types';
import { AuthorizationServerMetadata, AuthorizationServerType, EndpointMetadata } from './ServerMetadata';

export interface IssuerMetadataV1_0_13 {
  issuer?: string;
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_13>; // REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer: string; // A Credential Issuer is identified by a case sensitive URL using the https scheme that contains scheme, host and, optionally, port number and path components, but no query or fragment components.
  credential_endpoint: string; // REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  authorization_servers?: string[];
  batch_credential_endpoint?: string;
  deferred_credential_endpoint?: string;
  notification_endpoint?: string;
  credential_response_encryption?: ResponseEncryption;
  token_endpoint?: string;
  session_endpoint?: string;
  display?: MetadataDisplay[];

  [x: string]: unknown;
}

export type CredentialDefinitionJwtVcJsonV1_0_13 = {
  type: string[];
  credentialSubject?: IssuerCredentialSubject;
};

export type CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13 = {
  '@context': string[];
  type: string[];
  credentialSubject?: IssuerCredentialSubject;
};

export type CredentialConfigurationSupportedV1_0_13 = CredentialConfigurationSupportedCommonV1_0_13 &
  (
    | CredentialConfigurationSupportedSdJwtVcV1_0_13
    | CredentialConfigurationSupportedJwtVcJsonV1_0_13
    | CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0_13
  );

// Base type covering credential configurations supported
export type CredentialConfigurationSupportedCommonV1_0_13 = {
  format: OID4VCICredentialFormat | 'string'; //REQUIRED. A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc.
  scope?: string; // OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential. The value can be the same across multiple credential_configurations_supported objects. The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the scope value. The Wallet can use this value in the Authorization Request as defined in Section 5.1.2. Scope values in this Credential Issuer metadata MAY duplicate those in the scopes_supported parameter of the Authorization Server.
  cryptographic_binding_methods_supported?: string[];
  credential_signing_alg_values_supported?: string[];
  proof_types_supported?: ProofTypesSupported;
  display?: CredentialsSupportedDisplay[]; // OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language
  [x: string]: unknown;
};

export interface CredentialConfigurationSupportedSdJwtVcV1_0_13 extends CredentialConfigurationSupportedCommonV1_0_13 {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;

  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface CredentialConfigurationSupportedJwtVcJsonV1_0_13 extends CredentialConfigurationSupportedCommonV1_0_13 {
  format: 'jwt_vc_json' | 'jwt_vc';
  credential_definition: CredentialDefinitionJwtVcJsonV1_0_13;
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0_13 extends CredentialConfigurationSupportedCommonV1_0_13 {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  credential_definition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13;
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export type CredentialRequestV1_0_13ResponseEncryption = {
  jwk: JWK;
  alg: AlgValue;
  enc: EncValue;
};

export interface CredentialRequestV1_0_13Common extends ExperimentalSubjectIssuance {
  credential_response_encryption?: CredentialRequestV1_0_13ResponseEncryption;
  proof?: ProofOfPossession;
}

export type CredentialRequestV1_0_13 = CredentialRequestV1_0_13Common &
  (
    | CredentialRequestJwtVcJsonV1_0_13
    | CredentialRequestJwtVcJsonLdAndLdpVcV1_0_13
    | CredentialRequestSdJwtVc
    | CredentialRequestV1_0_13CredentialIdentifier
  );

export interface CredentialRequestV1_0_13CredentialIdentifier extends CredentialRequestV1_0_13Common {
  // Format cannot be defined when credential_identifier is used
  format?: undefined;
  credential_identifier: string;
}

export interface CredentialRequestJwtVcJsonV1_0_13 extends CommonCredentialRequest {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc for backwards compat
  credential_definition: CredentialDefinitionJwtVcJsonV1_0_13;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVcV1_0_13 extends CommonCredentialRequest {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  credential_definition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13;
}

export interface CredentialOfferV1_0_13 {
  credential_offer?: CredentialOfferPayloadV1_0_13;
  credential_offer_uri?: string;
}

export interface CredentialOfferRESTRequest extends CredentialOfferV1_0_13 {
  baseUri?: string;
  scheme?: string;
  pinLength?: number;
  qrCodeOpts?: QRCodeOpts;
  credentialDataSupplierInput?: CredentialDataSupplierInput;
}

export interface CredentialOfferPayloadV1_0_13 {
  /**
   * REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is requested to
   * obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata following the steps
   * defined in Section 11.2.2.
   */
  credential_issuer: string;

  /**
   *  REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
   *  the credential_configurations_supported Credential Issuer metadata. The Wallet uses these string values
   *  to obtain the respective object that contains information about the Credential being offered as defined
   *  in Section 11.2.3. For example, these string values can be used to obtain scope values to be used in
   *  the Authorization Request.
   */
  credential_configuration_ids: string[];
  /**
   * OPTIONAL. A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
   * to process for this credential offer. Every grant is represented by a key and an object.
   * The key value is the Grant Type identifier, the object MAY contain parameters either determining the way
   * the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with the respective request(s).
   * If grants is not present or empty, the Wallet MUST determine the Grant Types the Credential Issuer's AS supports
   * using the respective metadata. When multiple grants are present, it's at the Wallet's discretion which one to use.
   */
  grants?: Grant;

  /**
   * Some implementations might include a client_id in the offer. For instance EBSI in a same-device flow. (Cross-device tucks it in the state JWT)
   */
  client_id?: string;
}

export interface CredentialIssuerMetadataOptsV1_0_13 {
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  deferred_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
  notification_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 10. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
  credential_response_encryption?: ResponseEncryption; // OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential and Batch Credential Response on top of TLS.
  credential_identifiers_supported?: boolean; // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_13>; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_servers?: string[]; // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  signed_metadata?: string; // OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims.
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:

  //todo: these two are not mentioned in the spec
  token_endpoint?: string;
  credential_supplier_config?: CredentialSupplierConfig;
}

export interface EndpointMetadataResultV1_0_13 extends EndpointMetadata {
  // The EndpointMetadata are snake-case so they can easily be used in payloads/JSON.
  // The values below should not end up in requests/responses directly, so they are using our normal CamelCase convention
  authorizationServerType: AuthorizationServerType;
  authorizationServerMetadata?: AuthorizationServerMetadata;
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & IssuerMetadataV1_0_13;
  session_endpoint?: string;
}

// For now we extend the opts above. Only difference is that the credential endpoint is optional in the Opts, as it can come from other sources. The value is however required in the eventual Issuer Metadata
export interface CredentialIssuerMetadataV1_0_13 extends CredentialIssuerMetadataOptsV1_0_13, Partial<AuthorizationServerMetadata> {
  authorization_servers?: string[]; // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_13>; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  credential_response_encryption_alg_values_supported?: string; // OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  credential_response_encryption_enc_values_supported?: string; //OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  require_credential_response_encryption?: boolean; //OPTIONAL. Boolean value specifying whether the Credential Issuer requires additional encryption on top of TLS for the Credential Response and expects encryption parameters to be present in the Credential Request and/or Batch Credential Request, with true indicating support. When the value is true, credential_response_encryption_alg_values_supported parameter MUST also be provided. If omitted, the default value is false.
  credential_identifiers_supported?: boolean; // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
}
