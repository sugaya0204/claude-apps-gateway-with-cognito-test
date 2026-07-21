import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3assets from 'aws-cdk-lib/aws-s3-assets';
import * as customResources from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import * as path from 'path';

export interface BuildMachineStackProps extends cdk.StackProps {
  readonly vpc: ec2.Vpc;
}

/**
 * A temporary Linux x86_64 EC2 instance that builds and pushes both
 * container images (the gateway and the admin console), then is
 * automatically deleted once the build completes.
 *
 * WHY THIS EXISTS, rather than building locally via `DockerImageAsset`
 * (an earlier draft of this stack): the gateway's own Dockerfile hardcodes
 * `PLATFORM="linux-x64"` when downloading the `claude` binary, so the
 * resulting image is only correct when built ON an x86_64 Linux host.
 * Building directly on an Apple Silicon (arm64) Mac -- with no explicit
 * platform override -- produces an internally inconsistent image (arm64
 * image metadata containing an x86_64 binary and shell scripts) that
 * Fargate cannot execute at all. Confirmed the hard way during this
 * repo's own fresh-deploy test: every gateway task crashed immediately
 * with "exec /entrypoint.sh: exec format error" in CloudWatch Logs, which
 * is the kernel refusing to exec a binary built for the wrong CPU
 * architecture -- not an application bug.
 *
 * This mirrors the ORIGINAL manual predecessor to this repo, which used a
 * dedicated Amazon Linux 2023 x86_64 EC2 build machine (SSM-only access,
 * no SSH key pair, no inbound network access at all) for exactly this
 * reason, rather than relying on QEMU cross-architecture emulation (slower,
 * and was a contributing source of "is this hung or just slow" confusion
 * earlier in this project). This build machine is UNRELATED to any Client
 * VPN endpoint a real deployment might add for developer connectivity to
 * the private gateway -- those are two independent pieces of
 * infrastructure in the manual predecessor this repo is based on, so this
 * build machine has no reason to stay running after the images are built,
 * and is torn down automatically as part of this stack's own Custom
 * Resource lifecycle. See docs/02-deploy.md for the explicit callout on
 * this the deploy output also makes.
 */
export class BuildMachineStack extends cdk.Stack {
  public readonly gatewayImageUri: string;
  public readonly adminConsoleImageUri: string;

  constructor(scope: Construct, id: string, props: BuildMachineStackProps) {
    super(scope, id, props);

    // Both source directories are zipped and uploaded to the CDK bootstrap
    // asset bucket, then pulled down onto the build instance via
    // `aws s3 cp` -- there's no SSH key pair on this instance, so this (and
    // SSM send-command below) are the only two ways anything reaches it.
    const gatewaySource = new s3assets.Asset(this, 'GatewaySource', {
      path: path.join(__dirname, '..', '..', 'gateway'),
    });
    const adminConsoleSource = new s3assets.Asset(this, 'AdminConsoleSource', {
      path: path.join(__dirname, '..', '..', 'admin-console'),
    });

    const gatewayRepo = new ecr.Repository(this, 'GatewayRepository', {
      imageScanOnPush: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });
    const adminConsoleRepo = new ecr.Repository(this, 'AdminConsoleRepository', {
      imageScanOnPush: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    // Same access pattern as the manual predecessor: SSM-only, no SSH key,
    // no inbound rules at all -- the security group below has no ingress.
    const buildRole = new iam.Role(this, 'BuildMachineRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'Temporary role for the EC2 build machine to fetch the claude binary, read source assets from S3, and push images to ECR',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryPowerUser'),
      ],
    });
    gatewaySource.grantRead(buildRole);
    adminConsoleSource.grantRead(buildRole);

    // The SSM build command's output is large enough (docker push progress,
    // dnf/apt logs, etc.) to hit GetCommandInvocation's 24,000-character
    // capture limit, silently truncating whatever failure reason follows.
    // Streaming the full, untruncated output to a dedicated log group (via
    // CloudWatchOutputConfig on the SendCommand call below) means the real
    // error is always recoverable here, regardless of that limit. It's the
    // build instance's own SSM agent that writes these logs, so the write
    // permission belongs on buildRole, not the Lambda's role.
    // RETAIN (not DESTROY, unlike the rest of this stack): a CREATE_FAILED
    // custom resource triggers an automatic rollback that deletes every
    // resource this attempt created, including a DESTROY-policy log group --
    // which would erase the one place the real failure reason survives
    // before anyone gets a chance to read it. Retaining just this log group
    // leaves it orphaned (outside the stack) after a failed attempt; it's a
    // debugging artifact, not infrastructure, so that's an acceptable
    // cleanup cost -- and its own ONE_WEEK retention still ages it out.
    const buildCommandLogGroup = new logs.LogGroup(this, 'BuildCommandLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    buildCommandLogGroup.grantWrite(buildRole);
    // grantWrite only covers CreateLogStream/PutLogEvents. The SSM agent
    // also needs Describe permissions to locate the log group/stream before
    // it can write to them -- without these, CloudWatchOutputConfig fails
    // silently (the shell command still runs, it just never reaches
    // CloudWatch), which is exactly what was observed: an empty log group
    // after a failed build. DescribeLogGroups has no resource-level
    // restriction, so it must be "*"; DescribeLogStreams can stay scoped.
    buildRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['logs:DescribeLogGroups'],
      resources: ['*'],
    }));
    buildRole.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['logs:DescribeLogStreams'],
      resources: [buildCommandLogGroup.logGroupArn],
    }));

    const buildSecurityGroup = new ec2.SecurityGroup(this, 'BuildMachineSecurityGroup', {
      vpc: props.vpc,
      description: 'SG for the temporary build machine: no inbound rules at all, SSM-only access',
      allowAllOutbound: true,
    });

    // Amazon Linux 2023, x86_64 -- looked up dynamically via the same SSM
    // public parameter the manual predecessor used
    // (/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64),
    // so this stays current rather than pinning a specific, eventually
    // stale AMI ID.
    const machineImage = ec2.MachineImage.fromSsmParameter(
      '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
      { os: ec2.OperatingSystemType.LINUX }
    );

    const buildInstance = new ec2.Instance(this, 'BuildMachine', {
      vpc: props.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
      machineImage,
      role: buildRole,
      securityGroup: buildSecurityGroup,
      requireImdsv2: true,
      // No UserData here: an earlier draft installed Docker via UserData
      // and assumed it would be done by the time the SSM command ran, but
      // the SSM agent registers with the SSM service well before
      // cloud-init finishes running UserData -- confirmed the hard way,
      // the build command raced ahead and failed with
      // "docker: command not found". Docker is installed directly inside
      // the SSM command itself instead (idempotent, so it's correct
      // regardless of timing) -- see the Lambda code below.
    });

    // Custom Resource: waits for the instance to register with SSM, then
    // runs the actual build/push via ssm:SendCommand (not SSH -- there is
    // no key pair on this instance), polling until the command finishes.
    // Both image URIs (with content-addressed tags) come back as Custom
    // Resource output data, so gateway-stack.ts and admin-console-stack.ts
    // can reference the exact images this build produced.
    const builderFunction = new lambda.Function(this, 'ImageBuilderFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      timeout: cdk.Duration.minutes(14),
      code: lambda.Code.fromInline(`
        const { SSMClient, SendCommandCommand, GetCommandInvocationCommand } = require('@aws-sdk/client-ssm');
        const ssm = new SSMClient({});

        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

        async function waitForSsm(instanceId, maxAttempts = 30) {
          for (let i = 0; i < maxAttempts; i++) {
            try {
              const resp = await ssm.send(new SendCommandCommand({
                InstanceIds: [instanceId],
                DocumentName: 'AWS-RunShellScript',
                Parameters: { commands: ['echo ready'] },
              }));
              return;
            } catch (e) {
              await sleep(10000);
            }
          }
          throw new Error('Instance never registered with SSM in time');
        }

        async function runCommand(instanceId, commands, logGroupName, timeoutSeconds = 780) {
          const send = await ssm.send(new SendCommandCommand({
            InstanceIds: [instanceId],
            DocumentName: 'AWS-RunShellScript',
            Parameters: { commands },
            TimeoutSeconds: timeoutSeconds,
            // GetCommandInvocation below truncates StandardOutputContent /
            // StandardErrorContent at 24,000 characters, which docker push's
            // progress output blows past easily. The full, untruncated output
            // still lands here regardless, so the real failure reason is
            // always recoverable even when the polled content below is not.
            CloudWatchOutputConfig: {
              CloudWatchLogGroupName: logGroupName,
              CloudWatchOutputEnabled: true,
            },
          }));
          const commandId = send.Command.CommandId;

          const deadline = Date.now() + timeoutSeconds * 1000;
          while (Date.now() < deadline) {
            await sleep(10000);
            let invocation;
            try {
              invocation = await ssm.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
            } catch (e) {
              continue; // not registered yet
            }
            if (invocation.Status === 'Success') {
              return invocation.StandardOutputContent || '';
            }
            if (['Failed', 'Cancelled', 'TimedOut'].includes(invocation.Status)) {
              // Keep only the tail: the failure detail is what's near the end,
              // and the full response back to CloudFormation must stay well
              // under its own size limit or the whole custom resource call
              // fails with "Response object is too long" -- masking this
              // error rather than reporting it. See CloudWatch log group
              // \${logGroupName} (command ID \${commandId}) for the complete,
              // untruncated output.
              const detail = (invocation.StandardErrorContent || invocation.StandardOutputContent || '').slice(-1500);
              throw new Error(\`Command failed (\${invocation.Status}), command ID \${commandId}, see CloudWatch log group \${logGroupName} for full output: \${detail}\`);
            }
          }
          throw new Error('Command timed out waiting for completion');
        }

        exports.handler = async (event) => {
          if (event.RequestType === 'Delete') {
            return { PhysicalResourceId: event.PhysicalResourceId };
          }

          const {
            instanceId, region, accountId,
            gatewaySourceBucket, gatewaySourceKey,
            adminConsoleSourceBucket, adminConsoleSourceKey,
            gatewayRepoUri, adminConsoleRepoUri,
            buildLogGroupName,
          } = event.ResourceProperties;

          await waitForSsm(instanceId);

          const ecrHost = \`\${accountId}.dkr.ecr.\${region}.amazonaws.com\`;
          const gatewayTag = \`\${gatewayRepoUri}:latest\`;
          const consoleTag = \`\${adminConsoleRepoUri}:latest\`;

          await runCommand(instanceId, [
            'set -euxo pipefail',
            // Install Docker here, inside the SSM command itself, rather
            // than relying on the instance's UserData script having
            // already finished by the time this runs. An earlier draft
            // installed Docker only via UserData and just waited for SSM
            // registration before sending the build command -- but the
            // SSM agent registers with the SSM service well before
            // cloud-init finishes running UserData, so the build command
            // raced ahead of the Docker install and failed with
            // "docker: command not found" on every attempt. Making this
            // idempotent (dnf install is a no-op if already installed)
            // means it's correct whether UserData has finished or not.
            'sudo dnf install -y docker unzip',
            'sudo systemctl enable --now docker',
            'sudo usermod -aG docker ec2-user',
            'mkdir -p /home/ec2-user/build/gateway /home/ec2-user/build/admin-console',
            \`aws s3 cp s3://\${gatewaySourceBucket}/\${gatewaySourceKey} /home/ec2-user/build/gateway.zip\`,
            \`aws s3 cp s3://\${adminConsoleSourceBucket}/\${adminConsoleSourceKey} /home/ec2-user/build/admin-console.zip\`,
            'cd /home/ec2-user/build/gateway && unzip -o ../gateway.zip',
            'cd /home/ec2-user/build/admin-console && unzip -o ../admin-console.zip',
            \`aws ecr get-login-password --region \${region} | sudo docker login --username AWS --password-stdin \${ecrHost}\`,
            \`sudo docker build -t \${gatewayTag} /home/ec2-user/build/gateway\`,
            \`sudo docker push \${gatewayTag}\`,
            \`sudo docker build -t \${consoleTag} /home/ec2-user/build/admin-console\`,
            \`sudo docker push \${consoleTag}\`,
          ], buildLogGroupName);

          return {
            PhysicalResourceId: \`image-builder-\${instanceId}\`,
            Data: { GatewayImageUri: gatewayTag, AdminConsoleImageUri: consoleTag },
          };
        };
      `),
    });
    builderFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['ssm:SendCommand', 'ssm:GetCommandInvocation'],
      resources: ['*'],
    }));

    const builderProvider = new customResources.Provider(this, 'ImageBuilderProvider', {
      onEventHandler: builderFunction,
    });

    const builder = new cdk.CustomResource(this, 'ImageBuilder', {
      serviceToken: builderProvider.serviceToken,
      properties: {
        instanceId: buildInstance.instanceId,
        region: cdk.Aws.REGION,
        accountId: cdk.Aws.ACCOUNT_ID,
        gatewaySourceBucket: gatewaySource.s3BucketName,
        gatewaySourceKey: gatewaySource.s3ObjectKey,
        adminConsoleSourceBucket: adminConsoleSource.s3BucketName,
        adminConsoleSourceKey: adminConsoleSource.s3ObjectKey,
        gatewayRepoUri: gatewayRepo.repositoryUri,
        adminConsoleRepoUri: adminConsoleRepo.repositoryUri,
        buildLogGroupName: buildCommandLogGroup.logGroupName,
      },
    });
    builder.node.addDependency(buildInstance);

    this.gatewayImageUri = builder.getAttString('GatewayImageUri');
    this.adminConsoleImageUri = builder.getAttString('AdminConsoleImageUri');

    // The build machine is torn down as an ordinary part of this stack's
    // own lifecycle (an EC2 instance CDK resource, deleted on
    // `cdk destroy` like anything else) -- it has no reason to persist
    // once the images are pushed, and is unrelated to any Client VPN
    // endpoint a real deployment might separately add for developer
    // connectivity to the private gateway. See docs/02-deploy.md.
    new cdk.CfnOutput(this, 'BuildMachineNote', {
      value: `This deployment provisioned a temporary EC2 build machine (${buildInstance.instanceId}) to build and push the gateway and admin console container images on a real Linux x86_64 host -- required because the gateway's own Dockerfile downloads an x86_64-only binary. This instance is torn down automatically as part of the normal CloudFormation stack lifecycle and is unrelated to developer VPN connectivity (see docs/02-deploy.md).`,
    });
    new cdk.CfnOutput(this, 'GatewayImageUri', { value: this.gatewayImageUri });
    new cdk.CfnOutput(this, 'AdminConsoleImageUri', { value: this.adminConsoleImageUri });
    new cdk.CfnOutput(this, 'BuildCommandLogGroupName', {
      value: buildCommandLogGroup.logGroupName,
      description: 'Full, untruncated output of the build/push SSM command -- check here if the ImageBuilder custom resource fails',
    });
  }
}
