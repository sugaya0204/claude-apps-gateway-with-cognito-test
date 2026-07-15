#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CognitoStack } from '../lib/cognito-stack';

/**
 * Standalone CDK app entry for the throwaway Cognito user pool (see
 * lib/cognito-stack.ts). Kept separate from bin/app.ts on purpose: the main
 * app requires the very OIDC values this stack produces, so the two can't
 * synth together. Deploy this first, in isolation:
 *
 *   cd cdk
 *   cdk deploy --app "npx ts-node --prefer-ts-exts bin/cognito.ts" \
 *     ClaudeGatewayCognitoStack \
 *     -c cognitoDomainPrefix=<your-globally-unique-prefix>
 *
 * Then read the outputs, fetch the client secret with the printed CLI
 * command, and pass all three into the normal `cdk deploy --all` (which uses
 * bin/app.ts) as -c oidcIssuer / -c oidcClientId / -c oidcClientSecret.
 */
const app = new cdk.App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const domainPrefix = app.node.tryGetContext('cognitoDomainPrefix');
if (!domainPrefix) {
  throw new Error(
    'Missing required context value cognitoDomainPrefix. Pass it with -c, e.g.:\n' +
    '  cdk deploy --app "npx ts-node --prefer-ts-exts bin/cognito.ts" ClaudeGatewayCognitoStack -c cognitoDomainPrefix=acme-claude-gateway\n' +
    'It must be globally unique within the target region.'
  );
}

// The gateway's real callback URL is only known after it's deployed. Start
// with the placeholder, re-deploy this stack with the real value later.
const callbackUrl =
  app.node.tryGetContext('cognitoCallbackUrl') ?? 'https://placeholder.invalid/oauth/callback';
const logoutUrl =
  app.node.tryGetContext('cognitoLogoutUrl') ?? 'https://placeholder.invalid/';
const adminGroupName =
  app.node.tryGetContext('adminGroupName') ?? 'claude-gateway-admins';

new CognitoStack(app, 'ClaudeGatewayCognitoStack', {
  env,
  domainPrefix,
  callbackUrl,
  logoutUrl,
  adminGroupName,
});
