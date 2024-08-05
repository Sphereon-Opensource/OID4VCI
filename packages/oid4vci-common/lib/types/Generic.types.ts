import { ICredentialContextType, IVerifiableCredential, W3CVerifiableCredential } from '@sphereon/ssi-types';

import { ExperimentalSubjectIssuance } from '../experimental/holder-vci';

import { ProofOfPossession } from './CredentialIssuance.types';
import { AuthorizationServerMetadata } from './ServerMetadata';
import { CredentialOfferSession } from './StateManager.types';
import { IssuerMetadataV1_0_08 } from './v1_0_08.types';
import { CredentialRequestV1_0_11, EndpointMetadataResultV1_0_11 } from './v1_0_11.types';
import {
  CredentialConfigurationSupportedV1_0_13,
  CredentialRequestV1_0_13,
  EndpointMetadataResultV1_0_13,
  IssuerMetadataV1_0_13,
} from './v1_0_13.types';

export type InputCharSet = 'numeric' | 'text';
export type KeyProofType = 'jwt' | 'cwt' | 'ldp_vp';

export type PoPMode = 'pop' | 'JWT'; // Proof of posession, or regular JWT

/**
 * Important Note: please be aware that these Common interfaces are based on versions v1_0.11 and v1_0.09
 */
export interface ImageInfo {
  url?: string;
  alt_text?: string;

  [key: string]: unknown;
}

export type OID4VCICredentialFormat = 'jwt_vc_json' | 'jwt_vc_json-ld' | 'ldp_vc' | 'vc+sd-jwt' | 'jwt_vc'; // jwt_vc is added for backwards compat /*| 'mso_mdoc'*/; // we do not support mdocs at this point

export interface NameAndLocale {
  name?: string; // REQUIRED. String value of a display name for the Credential.
  locale?: string; // OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object with the same language identifier.
  [key: string]: unknown;
}

export interface LogoAndColor {
  logo?: ImageInfo; // OPTIONAL. A JSON object with information about the logo of the Credential with a following non-exhaustive list of parameters that MAY be included:
  description?: string; // OPTIONAL. String value of a description of the Credential.
  background_color?: string; //OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  text_color?: string; // OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
}

export type CredentialsSupportedDisplay = NameAndLocale &
  LogoAndColor & {
    name: string; // REQUIRED. String value of a display name for the Credential.
    background_image?: ImageInfo; //OPTIONAL, NON-SPEC compliant!. URL of a background image useful for card views of credentials. Expected to an image that fills the full card-view of a wallet
  };

export type MetadataDisplay = NameAndLocale &
  LogoAndColor & {
    name?: string; //OPTIONAL. String value of a display name for the Credential Issuer.
  };

export interface CredentialSupplierConfig {
  [key: string]: any; // This allows additional properties for credential suppliers
}

export interface CredentialIssuerMetadataOpts {
  credential_endpoint?: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  credentials_supported: CredentialsSupportedLegacy[]; // REQUIRED in versions below 13. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_server?: string; // OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  token_endpoint?: string;
  notification_endpoint?: string;
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  credential_supplier_config?: CredentialSupplierConfig;
}

//todo: investigate if these values are enough.
export type AlgValue = 'RS256' | 'ES256' | 'PS256' | 'HS256' | string;
export type EncValue = 'A128GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A256CBC-HS512' | string;

export interface ResponseEncryption {
  /**
   * REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms
   * (alg values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the
   * Credential or Batch Credential Response in a JWT
   */
  alg_values_supported: AlgValue[];

  /**
   * REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms
   * (enc values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the
   * Credential or Batch Credential Response in a JWT
   */
  enc_values_supported: EncValue[];

  /**
   * REQUIRED. Boolean value specifying whether the Credential Issuer requires the
   * additional encryption on top of TLS for the Credential Response. If the value is true, the Credential
   * Issuer requires encryption for every Credential Response and therefore the Wallet MUST provide
   * encryption keys in the Credential Request. If the value is false, the Wallet MAY chose whether it
   * provides encryption keys or not.
   */
  encryption_required: boolean;
}

// For now we extend the opts above. Only difference is that the credential endpoint is optional in the Opts, as it can come from other sources. The value is however required in the eventual Issuer Metadata
export interface CredentialIssuerMetadata extends CredentialIssuerMetadataOpts, Partial<AuthorizationServerMetadata> {
  authorization_servers?: string[]; // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credential_configurations_supported: Record<string, CredentialConfigurationSupported>; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  credential_response_encryption_alg_values_supported?: string; // OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  credential_response_encryption_enc_values_supported?: string; //OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  require_credential_response_encryption?: boolean; //OPTIONAL. Boolean value specifying whether the Credential Issuer requires additional encryption on top of TLS for the Credential Response and expects encryption parameters to be present in the Credential Request and/or Batch Credential Request, with true indicating support. When the value is true, credential_response_encryption_alg_values_supported parameter MUST also be provided. If omitted, the default value is false.
  credential_identifiers_supported?: boolean; // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
}

// For now we extend the opts above. Only difference is that the credential endpoint is optional in the Opts, as it can come from other sources. The value is however required in the eventual Issuer Metadata

export interface CredentialSupportedBrief {
  cryptographic_binding_methods_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential
  cryptographic_suites_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported
}

export interface ProofType {
  proof_signing_alg_values_supported: string[];
}

export type ProofTypesSupported = {
  [key in KeyProofType]?: ProofType;
};

export type CommonCredentialSupported = CredentialSupportedBrief &
  ExperimentalSubjectIssuance & {
    format: OID4VCICredentialFormat | string; //REQUIRED. A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc.
    id?: string; // OPTIONAL. A JSON string identifying the respective object. The value MUST be unique across all credentials_supported entries in the Credential Issuer Metadata
    display?: CredentialsSupportedDisplay[]; // OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language
    scope?: string; // OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential. The value can be the same across multiple credential_configurations_supported objects. The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the scope value. The Wallet can use this value in the Authorization Request as defined in Section 5.1.2. Scope values in this Credential Issuer metadata MAY duplicate those in the scopes_supported parameter of the Authorization Server.
    proof_types_supported?: ProofTypesSupported;

    /**
     * following properties are non-mso_mdoc specific and we might wanna rethink them when we're going to support mso_mdoc
     */
  };

export interface CredentialSupportedJwtVcJsonLdAndLdpVc extends CommonCredentialSupported {
  types: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  '@context': ICredentialContextType[]; // REQUIRED. JSON array as defined in [VC_DATA], Section 4.1.
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  format: 'ldp_vc' | 'jwt_vc_json-ld';
}

export interface CredentialSupportedJwtVcJson extends CommonCredentialSupported {
  types: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc added for backwards compat
}

export interface CredentialSupportedSdJwtVc extends CommonCredentialSupported {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;

  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export type CredentialConfigurationSupported =
  | CredentialConfigurationSupportedV1_0_13
  | (CommonCredentialSupported & (CredentialSupportedJwtVcJson | CredentialSupportedJwtVcJsonLdAndLdpVc | CredentialSupportedSdJwtVc));

export type CredentialsSupportedLegacy = CommonCredentialSupported &
  (CredentialSupportedJwtVcJson | CredentialSupportedJwtVcJsonLdAndLdpVc | CredentialSupportedSdJwtVc);

export interface CommonCredentialOfferFormat {
  format: OID4VCICredentialFormat | string;
}

export interface CredentialOfferFormatJwtVcJsonLdAndLdpVc extends CommonCredentialOfferFormat {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  // REQUIRED. JSON object containing (and isolating) the detailed description of the credential type. This object MUST be processed using full JSON-LD processing.
  credential_definition: JsonLdIssuerCredentialDefinition;
}

export interface CredentialOfferFormatJwtVcJson extends CommonCredentialOfferFormat {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc is added for backwards compat
  types: string[]; // REQUIRED. JSON array as defined in Appendix E.1.1.2. This claim contains the type values the Wallet shall request in the subsequent Credential Request.
}

// NOTE: the sd-jwt format is added to oid4vci in a later draft version than currently
// supported, so there's no defined offer format. However, based on the request structure
// we support sd-jwt for older drafts of oid4vci as well
export interface CredentialOfferFormatSdJwtVc extends CommonCredentialOfferFormat {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;
}

export type CredentialOfferFormat = CommonCredentialOfferFormat &
  (CredentialOfferFormatJwtVcJsonLdAndLdpVc | CredentialOfferFormatJwtVcJson | CredentialOfferFormatSdJwtVc);

/**
 * Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
 */
export type CredentialDataSupplierInput = any;

export type CreateCredentialOfferURIResult = {
  uri: string;
  qrCodeDataUri?: string;
  session: CredentialOfferSession;
  userPin?: string;
  txCode?: TxCode;
};

export interface JsonLdIssuerCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export type UniformCredentialRequest = CredentialRequestV1_0_11 | CredentialRequestV1_0_13;

export interface CommonCredentialRequest extends ExperimentalSubjectIssuance {
  format: OID4VCICredentialFormat /* | OID4VCICredentialFormat[];*/; // for now it seems only one is supported in the spec
  proof?: ProofOfPossession;
}

export interface CredentialRequestJwtVcJson extends CommonCredentialRequest {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc for backwards compat
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVc extends CommonCredentialRequest {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  credential_definition: JsonLdIssuerCredentialDefinition;
}

export interface CredentialRequestSdJwtVc extends CommonCredentialRequest {
  format: 'vc+sd-jwt';
  vct: string;
  claims?: IssuerCredentialSubject;
}

export interface CommonCredentialResponse extends ExperimentalSubjectIssuance {
  // format: string;  TODO do we still need this for previous version support?
  credential?: W3CVerifiableCredential;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: string;
}

export interface CredentialResponseLdpVc extends CommonCredentialResponse {
  //  format: 'ldp_vc';
  credential: IVerifiableCredential;
}

export interface CredentialResponseJwtVc {
  //  format: 'jwt_vc_json' | 'jwt_vc_json-ld';  TODO do we still need this for previous version support?
  credential: string;
}

export interface CredentialResponseSdJwtVc {
  //  format: 'vc+sd-jwt';   TODO do we still need this for previous version support?
  credential: string;
}

// export type CredentialSubjectDisplay = NameAndLocale[];

export type IssuerCredentialSubjectDisplay = CredentialSubjectDisplay & { [key: string]: CredentialSubjectDisplay };

export interface CredentialSubjectDisplay {
  mandatory?: boolean; // OPTIONAL. Boolean which when set to true indicates the claim MUST be present in the issued Credential. If the mandatory property is omitted its default should be assumed to be false.
  value_type?: string; // OPTIONAL. String value determining type of value of the claim. A non-exhaustive list of valid values defined by this specification are string, number, and image media types such as image/jpeg as defined in IANA media type registry for images
  display?: NameAndLocale[]; // OPTIONAL. An array of objects, where each object contains display properties of a certain claim in the Credential for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
}

export interface IssuerCredentialSubject {
  [key: string]: IssuerCredentialSubjectDisplay;
}

export interface Grant {
  authorization_code?: GrantAuthorizationCode;
  'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: GrantUrnIetf;
}

export interface GrantAuthorizationCode {
  /**
   * OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent
   * Authorization Request with the Credential Issuer to a context set up during previous steps.
   */
  issuer_state?: string;

  // v12 feature
  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when authorization_servers parameter in the Credential Issuer metadata has multiple entries. MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the authorization_servers array obtained from the Credential Issuer metadata
   */
  authorization_server?: string;
}

export interface TxCode {
  /**
   * OPTIONAL. String specifying the input character set. Possible values are numeric (only digits) and text (any characters). The default is numeric.
   */
  input_mode?: InputCharSet;

  /**
   * OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the input screen and improve the user experience.
   */
  length?: number;

  /**
   * OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction Code, e.g.,
   * describing over which communication channel it is delivered. The Wallet is RECOMMENDED to display this description
   * next to the Transaction Code input screen to improve the user experience. The length of the string MUST NOT exceed
   * 300 characters. The description does not support internationalization, however the Issuer MAY detect the Holder's
   * language by previous communication or an HTTP Accept-Language header within an HTTP GET request for a Credential Offer URI.
   */
  description?: string;
}

export interface GrantUrnIetf {
  /**
   * REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain Credentials of a certain type.
   */
  'pre-authorized_code': string;

  // v13
  /**
   * OPTIONAL. Object specifying whether the Authorization Server expects presentation of a Transaction Code by the
   * End-User along with the Token Request in a Pre-Authorized Code Flow. If the Authorization Server does not expect a
   * Transaction Code, this object is absent; this is the default. The Transaction Code is intended to bind the Pre-Authorized
   * Code to a certain transaction to prevent replay of this code by an attacker that, for example, scanned the QR code while
   * standing behind the legitimate End-User. It is RECOMMENDED to send the Transaction Code via a separate channel. If the Wallet
   * decides to use the Pre-Authorized Code Flow, the Transaction Code value MUST be sent in the tx_code parameter with
   * the respective Token Request as defined in Section 6.1. If no length or description is given, this object may be empty,
   * indicating that a Transaction Code is required.
   */
  tx_code?: TxCode;

  // v12, v13
  /**
   * OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to the token endpoint (in case the Authorization Server responds with error code authorization_pending - see Section 6.3). If no value is provided, Wallets MUST use 5 as the default.
   */
  interval?: number;

  // v12, v13 feature
  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when authorization_servers parameter in the Credential Issuer metadata has multiple entries. MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the authorization_servers array obtained from the Credential Issuer metadata
   */
  authorization_server?: string;

  // v12 and below feature
  /**
   * OPTIONAL. Boolean value specifying whether the AS
   * expects presentation of the End-User PIN along with the Token Request
   * in a Pre-Authorized Code Flow. Default is false. This PIN is intended
   * to bind the Pre-Authorized Code to a certain transaction to prevent
   * replay of this code by an attacker that, for example, scanned the QR
   * code while standing behind the legitimate End-User. It is RECOMMENDED
   * to send a PIN via a separate channel. If the Wallet decides to use
   * the Pre-Authorized Code Flow, a PIN value MUST be sent in
   * the user_pin parameter with the respective Token Request.
   */
  user_pin_required?: boolean;
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';
export const PRE_AUTH_GRANT_LITERAL = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

export type EndpointMetadataResult = EndpointMetadataResultV1_0_13 | EndpointMetadataResultV1_0_11;

export type IssuerMetadata = IssuerMetadataV1_0_13 | IssuerMetadataV1_0_08;

export type NotificationEventType = 'credential_accepted' | 'credential_failure' | 'credential_deleted';

export interface NotificationRequest {
  notification_id: string;
  event: NotificationEventType | string;
  event_description?: string;
  credential?: any; // Experimental support to have a wallet sign a credential. Not part of the spec
}

export type NotificationError = 'invalid_notification_id' | 'invalid_notification_request';

export type NotificationResult = {
  error: boolean;
  response?: NotificationErrorResponse;
};

export interface NotificationErrorResponse {
  error: NotificationError | string;
}

export interface IssuerSessionIdRequestOpts {
  sessionEndpoint: string;
}
