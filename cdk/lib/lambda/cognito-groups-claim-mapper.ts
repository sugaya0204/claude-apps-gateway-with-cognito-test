/**
 * Cognito Pre-Token-Generation (V2) trigger.
 *
 * Copies the signed-in user's Cognito group memberships into a top-level
 * `groups` claim on the ID token, so the closed-source `claude gateway`
 * binary -- which checks a claim named literally `groups` against
 * admin_groups -- sees the same shape Okta gives it. Cognito surfaces group
 * membership only as the reserved `cognito:groups` claim, which the gateway
 * does not read; without this remap, admin authorization never matches.
 *
 * The claim is emitted as an ARRAY (not a comma-joined string), matching the
 * standard OIDC `groups` claim Okta produces. A JSON-array claim value
 * requires a V2 (or V3) trigger event -- V1 events can only set string
 * claims -- which is why the user pool is on the Essentials feature plan and
 * wired via PreTokenGenerationConfig.LambdaVersion=V2_0 (see cognito-stack.ts).
 *
 * This is a pure, side-effect-free transform of the event: it reads
 * request.groupConfiguration.groupsToOverride and writes the ID-token claim.
 * No AWS SDK calls, so there is nothing to bundle beyond the handler itself.
 */

interface PreTokenGenerationV2Event {
  request: {
    groupConfiguration?: {
      groupsToOverride?: string[];
      iamRolesToOverride?: string[];
      preferredRole?: string;
    };
  };
  response: Record<string, unknown>;
}

export const handler = async (
  event: PreTokenGenerationV2Event,
): Promise<PreTokenGenerationV2Event> => {
  const groups = event.request.groupConfiguration?.groupsToOverride ?? [];

  event.response = {
    ...event.response,
    claimsAndScopeOverrideDetails: {
      idTokenGeneration: {
        claimsToAddOrOverride: {
          // Array value -- valid only for a V2/V3 trigger event. This is the
          // one line the whole stack's Essentials-plan + V2 wiring exists for.
          groups,
        },
      },
    },
  };

  return event;
};
