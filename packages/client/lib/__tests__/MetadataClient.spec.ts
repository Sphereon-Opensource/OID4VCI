import { WellKnownEndpoints } from '@sphereon/openid4vci-common';
import nock from 'nock';

import { CredentialOffer } from '../CredentialOffer';
import { MetadataClient } from '../MetadataClient';

import {
  DANUBE_ISSUER_URL,
  DANUBE_OIDC_METADATA,
  IDENTIPROOF_AS_METADATA,
  IDENTIPROOF_AS_URL,
  IDENTIPROOF_ISSUER_URL,
  IDENTIPROOF_OID4VCI_METADATA,
  SPRUCE_ISSUER_URL,
  SPRUCE_OID4VCI_METADATA,
  WALT_ISSUER_URL,
  WALT_OID4VCI_METADATA,
} from './MetadataMocks';

describe('MetadataClient with IdentiProof Issuer should', () => {
  beforeAll(() => {
    nock.cleanAll();
  });
  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token');
    expect(metadata.openid4vci_metadata).toEqual(IDENTIPROOF_OID4VCI_METADATA);
  });

  it('succeed with OID4VCI and separate AS metadata from Initiation', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    const INITIATE_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';
    const initiation = CredentialOffer.fromURI(INITIATE_URI);
    const metadata = await MetadataClient.retrieveAllMetadata(initiation.request.issuer);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token');
    expect(metadata.openid4vci_metadata).toEqual(IDENTIPROOF_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI and only AS metadata (no credential endpoint)', async () => {
    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OPENID4VCI_ISSUER)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OPENID_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OAUTH_AS)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the token endpoint for https://issuer.research.identiproof.io'
    );
  });

  it('Fail with OID4VCI and no AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OPENID_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, JSON.stringify({}));
    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)).rejects.toThrowError('{"error": "not found"}');
  });

  it('Fail if there is no token endpoint with errors enabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    const meta = JSON.parse(JSON.stringify(IDENTIPROOF_AS_METADATA));
    delete meta.token_endpoint;
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(meta));

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the token endpoint for https://issuer.research.identiproof.io'
    );
  });

  it('Fail if there is no credential endpoint with errors enabled', async () => {
    const meta = JSON.parse(JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    delete meta.credential_endpoint;
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(meta));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the credential endpoint for https://issuer.research.identiproof.io'
    );
  });

  it('Succeed with default value if there is no credential endpoint with errors disabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
  });

  it('Succeed with no well-known endpoints and errors disabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(404, {});
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential');
  });

  it('Fail when specific well-known is not found with errors enabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(404, {});
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});

    const metadata = MetadataClient.retrieveWellknown(IDENTIPROOF_ISSUER_URL, WellKnownEndpoints.OPENID4VCI_ISSUER, { errorOnNotFound: true });
    await expect(metadata).rejects.toThrowError('{"error": "not found"}');
  });
});

describe('Metadataclient with Spruce Issuer should', () => {
  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(SPRUCE_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(SPRUCE_OID4VCI_METADATA));

    const metadata = await MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/credential');
    expect(metadata.token_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/token');
    expect(metadata.openid4vci_metadata).toEqual(SPRUCE_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the token endpoint for https://ngi-oidc4vci-test.spruceid.xyz'
    );
  });
});

describe('Metadataclient with Danubetech should', () => {
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    nock(DANUBE_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(200, JSON.stringify(DANUBE_OIDC_METADATA));

    nock(DANUBE_ISSUER_URL)
      .get(/.well-known\/.*/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));
    const metadata = await MetadataClient.retrieveAllMetadata(DANUBE_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://oidc4vc.uniissuer.io/credential');
    expect(metadata.token_endpoint).toEqual('https://oidc4vc.uniissuer.io/token');
    expect(metadata.openid4vci_metadata).toEqual(DANUBE_OIDC_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the token endpoint for https://ngi-oidc4vci-test.spruceid.xyz'
    );
  });
});

describe('Metadataclient with Walt-id should', () => {
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    nock(WALT_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(WALT_OID4VCI_METADATA));

    nock(WALT_ISSUER_URL)
      .get(/.well-known\/.*/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    const metadata = await MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL);
    expect(metadata.credential_endpoint).toEqual('https://jff.walt.id/issuer-api/oidc/credential');
    expect(metadata.token_endpoint).toEqual('https://jff.walt.id/issuer-api/oidc/token');
    expect(metadata.openid4vci_metadata).toEqual(WALT_OID4VCI_METADATA);
  });

  it('Fail without OID4VCI', async () => {
    nock(WALT_ISSUER_URL)
      .get(/.*/)
      .times(4)
      .reply(404, JSON.stringify({ error: 'does not exist' }));

    await expect(() => MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the token endpoint for https://jff.walt.id/issuer-api/oidc'
    );
  });
});
