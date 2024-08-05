import { IssuerSessionIdRequestOpts } from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { acquireIssuerSessionId } from '../IssuerSessionClient';

describe('IssuerSessionClient', () => {
  describe('acquireIssuerSessionId', () => {
    const mockSessionEndpoint = 'https://server.example.com/session_endpoint';
    const mockSessionId = 'iOiJSUzI1NiIsInR';

    beforeEach(() => {
      nock.cleanAll();
    });

    it('should successfully acquire an issuer session ID', async () => {
      const mockResponse = {
        session_id: mockSessionId,
      };

      nock('https://server.example.com').post('/session_endpoint').reply(200, mockResponse, { 'Content-Type': 'application/json' });

      const opts: IssuerSessionIdRequestOpts = {
        sessionEndpoint: mockSessionEndpoint,
      };

      const result = await acquireIssuerSessionId(opts);

      expect(result).toEqual(mockResponse);
    });

    it('should reject with an error if the response contains an error body', async () => {
      const mockErrorResponse = {
        error: 'invalid_request',
        error_description: 'The request is missing a required parameter',
      };

      nock('https://server.example.com').post('/session_endpoint').reply(400, mockErrorResponse, { 'Content-Type': 'application/json' });

      const opts: IssuerSessionIdRequestOpts = {
        sessionEndpoint: mockSessionEndpoint,
      };

      await expect(acquireIssuerSessionId(opts)).rejects.toMatch(/an error occurred while requesting a issuer session token/);
    });

    it('should reject with an error if the response is missing the session_token', async () => {
      nock('https://server.example.com').post('/session_endpoint').reply(200, undefined, { 'Content-Type': 'application/json' });

      const opts: IssuerSessionIdRequestOpts = {
        sessionEndpoint: mockSessionEndpoint,
      };

      await expect(acquireIssuerSessionId(opts)).rejects.toMatch(
        /an error occurred while requesting a issuer session token.*missing session_token response/,
      );
    });
  });
});
