import { VCI_LOGGERS } from '@sphereon/oid4vci-common';
import { ISimpleLogger } from '@sphereon/ssi-types';

export const LOG: ISimpleLogger<string> = VCI_LOGGERS.get('sphereon:oid4vci:client');

export * from './AccessTokenClient';
export * from './AccessTokenClientV1_0_11';
export * from './AuthorizationCodeClient';
export * from './AuthorizationCodeClientV1_0_11';
export * from './CredentialRequestClient';
export * from './CredentialOfferClient';
export * from './CredentialOfferClientV1_0_11';
export * from './CredentialOfferClientV1_0_13';
export * from './CredentialRequestClientV1_0_11';
export * from './CredentialRequestClientBuilder';
export * from './CredentialRequestClientBuilderV1_0_13';
export * from './CredentialRequestClientBuilderV1_0_11';
export * from './functions';
export * from './MetadataClient';
export * from './MetadataClientV1_0_13';
export * from './MetadataClientV1_0_11';
export * from './OpenID4VCIClient';
export * from './OpenID4VCIClientV1_0_13';
export * from './OpenID4VCIClientV1_0_11';
export * from './IssuerSessionClient';
export * from './ProofOfPossessionBuilder';
