import { IssuerSessionIdRequestOpts, IssuerSessionResponse, OpenIDResponse, post } from '@sphereon/oid4vci-common';

import { LOG } from './index';

export const acquireIssuerSessionId = async (opts: IssuerSessionIdRequestOpts): Promise<IssuerSessionResponse> => {
  LOG.debug(`acquiring issuer session endpoint from endpoint ${opts.sessionEndpoint}`);
  const sessionResponse = (await post(opts.sessionEndpoint)) as OpenIDResponse<IssuerSessionResponse>;
  if (sessionResponse.errorBody !== undefined) {
    return Promise.reject(`an error occurred while requesting a issuer session token from endpoint ${opts.sessionEndpoint}:
     ${sessionResponse.errorBody.error} - ${sessionResponse.errorBody.error_description}`);
  }
  if (sessionResponse.successBody === undefined || !Object.keys(sessionResponse.successBody).includes('session_id')) {
    return Promise.reject(
      `an error occurred while requesting a issuer session token from endpoint ${opts.sessionEndpoint}, missing session_token response`,
    );
  }
  return sessionResponse.successBody;
};
