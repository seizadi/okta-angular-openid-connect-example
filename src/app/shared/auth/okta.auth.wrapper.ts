import { OAuthService } from 'angular-oauth2-oidc';
import { Injectable } from '@angular/core';
import * as OktaAuth from '@okta/okta-auth-js';

@Injectable({
  providedIn: 'root'
})
export class OktaAuthWrapper {

  private authClient: any;

  constructor(private oauthService: OAuthService) {
    this.authClient = new OktaAuth({
      url: 'https://dev-551469.oktapreview.com',
      issuer: 'default'
    });
  }

  getIdToken() {
    return this.oauthService.getIdToken();
  }

  login(username: string, password: string): Promise<any> {
    return this.oauthService.createAndSaveNonce().then(nonce => {
      return this.authClient.signIn({
        username: username,
        password: password
      }).then((response) => {
        if (response.status === 'SUCCESS') {
          return this.authClient.token.getWithoutPrompt({
            clientId: this.oauthService.clientId,
            responseType: ['id_token', 'token'],
            scopes: ['openid', 'profile', 'email', 'groups'],
            sessionToken: response.sessionToken,
            nonce: nonce,
            redirectUri: window.location.origin
          })
            .then((tokens) => {
              const idToken = tokens[0].idToken;
              const accessToken = tokens[1].accessToken;
              if (tokens[0]) {
                this.authClient.tokenManager.add('idToken', tokens[0]);
              }
              if (tokens[1]) {
                this.authClient.tokenManager.add('accessToken', tokens[1]);
              }
              const keyValuePair = `#id_token=${encodeURIComponent(idToken)}&access_token=${encodeURIComponent(accessToken)}`;
              return this.oauthService.tryLogin({
                customHashFragment: keyValuePair,
                disableOAuth2StateCheck: true
              });
            });
        } else {
          return Promise.reject('We cannot handle the ' + response.status + ' status');
        }
      });
    });
  }
}
