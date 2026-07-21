import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import { Construct } from 'constructs';

export interface CognitoStackProps extends cdk.StackProps {
  /**
   * Globally-unique-within-the-region prefix for the Cognito Hosted UI
   * domain (e.g. "acme-claude-gateway" -> https://acme-claude-gateway.auth.<region>.amazoncognito.com).
   * A domain is required because the OIDC discovery document points its
   * authorize/token/userinfo endpoints at this domain -- without it the
   * gateway's OIDC flow has nothing to redirect to.
   */
  readonly domainPrefix: string;
  /**
   * The gateway's OAuth redirect URI. Like the Okta setup in
   * docs/01-prerequisites.md, the gateway's real URL is only known AFTER it
   * is deployed, so start with the placeholder default and re-deploy this
   * stack with the real value (`-c cognitoCallbackUrl=https://<gateway-url>/oauth/callback`)
   * once the gateway exists.
   */
  readonly callbackUrl: string;
  /** Where Cognito sends the browser after sign-out. Placeholder-friendly. */
  readonly logoutUrl: string;
  /**
   * Name of the admin group created in the pool. Mirrors the Okta
   * `adminOktaGroupName` concept. NOTE: without a Pre-Token-Generation
   * Lambda this membership surfaces in the ID token as `cognito:groups`,
   * NOT the `groups` claim the gateway checks -- so admin authorization
   * will not work on this Lambda-free first pass. Developer sign-in still
   * exercises end-to-end. See this stack's CfnOutputs for the details.
   */
  readonly adminGroupName: string;
}

/**
 * A deliberately minimal, standalone Amazon Cognito user pool that stands in
 * for the Okta tenant this reference deployment normally uses as its OIDC
 * IdP. It is intentionally NOT wired into bin/app.ts: the main app consumes
 * `oidcIssuer` / `oidcClientId` / `oidcClientSecret` as CDK context at synth
 * time, and this stack is what PRODUCES those values -- a bootstrap ordering
 * that only works if this deploys first, in isolation. Deploy it with its own
 * app entry (bin/cognito.ts), read the outputs, then feed them into the main
 * `cdk deploy` as context. Zero changes to any existing stack.
 *
 * This is a throwaway test pool (RemovalPolicy.DESTROY, self-signup off).
 */
export class CognitoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CognitoStackProps) {
    super(scope, id, props);

    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'claude-gateway-pool',
      // Admins create users by hand for a test pool; no open registration.
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      // Throwaway pool: let `cdk destroy` take the pool (and its users) with it.
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // The Hosted UI domain that backs the OIDC authorize/token/userinfo
    // endpoints referenced by the pool's discovery document.
    userPool.addDomain('HostedUiDomain', {
      cognitoDomain: { domainPrefix: props.domainPrefix },
    });

    const client = userPool.addClient('GatewayClient', {
      userPoolClientName: 'claude-gateway',
      // The gateway's config schema treats client_secret as required and
      // validates it at boot (see bin/app.ts), so this must be a
      // confidential client.
      generateSecret: true,
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        // Only Cognito-valid scopes here. Cognito has NO `offline_access`
        // and NO `groups` scope (unlike Okta) -- requesting either at the
        // authorize endpoint is an error, so the gateway.yaml scopes list
        // must be trimmed to these three when pointing at Cognito. Refresh
        // tokens are issued automatically for the auth-code grant; no
        // offline_access scope needed.
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: [props.callbackUrl],
        logoutUrls: [props.logoutUrl],
      },
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
      ],
    });

    // Present for parity with the Okta admin group. Harmless on this
    // Lambda-free pass (it just won't reach the gateway as `groups` yet).
    new cognito.CfnUserPoolGroup(this, 'AdminGroup', {
      userPoolId: userPool.userPoolId,
      groupName: props.adminGroupName,
      description: 'Members intended to have gateway admin-console access',
    });

    // OIDC issuer for a Cognito user pool. Its discovery document lives at
    // `${issuer}/.well-known/openid-configuration` -- exactly what the
    // gateway fetches. This is the value to pass as `-c oidcIssuer=...`.
    const issuer = `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`;

    new cdk.CfnOutput(this, 'OidcIssuer', {
      value: issuer,
      description: 'Pass to the main deploy as -c oidcIssuer=...',
    });
    new cdk.CfnOutput(this, 'OidcClientId', {
      value: client.userPoolClientId,
      description: 'Pass to the main deploy as -c oidcClientId=...',
    });
    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
    });
    // The client secret is intentionally NOT emitted as an output (that would
    // print it into the CloudFormation template / console in plaintext, and
    // reading it in-stack would pull in a Lambda-backed custom resource --
    // which this Lambda-free pass avoids). Fetch it out-of-band with the CLI:
    new cdk.CfnOutput(this, 'GetClientSecretCommand', {
      value:
        `aws cognito-idp describe-user-pool-client` +
        ` --user-pool-id ${userPool.userPoolId}` +
        ` --client-id ${client.userPoolClientId}` +
        ` --region ${this.region}` +
        ` --query 'UserPoolClient.ClientSecret' --output text`,
      description: 'Run this to get the value for -c oidcClientSecret=...',
    });
  }
}
