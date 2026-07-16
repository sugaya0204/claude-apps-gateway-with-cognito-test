import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejsLambda from 'aws-cdk-lib/aws-lambda-nodejs';
import { Construct } from 'constructs';
import * as path from 'path';

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
   * `adminOktaGroupName` concept. Membership surfaces natively only as the
   * reserved `cognito:groups` claim; the Pre-Token-Generation trigger in
   * this stack copies it into a top-level `groups` claim (an array) so the
   * gateway's admin_groups check matches. Pass the SAME value here as the
   * main deploy's `-c adminOktaGroupName=...`.
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
 * A Pre-Token-Generation trigger (lambda/cognito-groups-claim-mapper.ts)
 * remaps Cognito's `cognito:groups` into the `groups` claim the gateway
 * reads, so admin authorization works -- the one piece that a config-only
 * Cognito swap cannot cover.
 *
 * This is a throwaway test pool (RemovalPolicy.DESTROY, self-signup off).
 */
export class CognitoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CognitoStackProps) {
    super(scope, id, props);

    // Pre-Token-Generation trigger that copies `cognito:groups` into a
    // top-level `groups` array claim the gateway reads. Pure event transform,
    // no AWS SDK calls -- see lambda/cognito-groups-claim-mapper.ts.
    const groupsClaimMapper = new nodejsLambda.NodejsFunction(this, 'GroupsClaimMapper', {
      runtime: lambda.Runtime.NODEJS_20_X,
      entry: path.join(__dirname, 'lambda', 'cognito-groups-claim-mapper.ts'),
      handler: 'handler',
      timeout: cdk.Duration.seconds(5),
    });

    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'claude-gateway-pool',
      // Admins create users by hand for a test pool; no open registration.
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      // Emitting the `groups` claim as an ARRAY needs a V2 pre-token event,
      // which requires the Essentials feature plan. Essentials is already the
      // default for new pools; set explicitly so the V2 wiring below is
      // deterministic and the (per-MAU) cost choice is visible in code.
      // Downgrade to LITE only if you switch the trigger back to V1 (which
      // can emit string claims only -- likely insufficient for the gateway).
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      lambdaTriggers: {
        // L2 wires the Cognito->Lambda invoke permission and the (V1) trigger
        // field; the escape hatch just below upgrades it to a V2 event.
        preTokenGeneration: groupsClaimMapper,
      },
      // Throwaway pool: let `cdk destroy` take the pool (and its users) with it.
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Upgrade the pre-token trigger to a V2 event so the Lambda may return an
    // ARRAY claim value. V1 events (all that lambdaTriggers.preTokenGeneration
    // configures on its own) carry string claims only, which the gateway's
    // groups-membership check would not match. No L2 prop exists for the
    // trigger version, so set PreTokenGenerationConfig directly.
    const cfnUserPool = userPool.node.defaultChild as cognito.CfnUserPool;
    cfnUserPool.addPropertyOverride('LambdaConfig.PreTokenGenerationConfig', {
      LambdaArn: groupsClaimMapper.functionArn,
      LambdaVersion: 'V2_0',
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
