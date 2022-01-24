# Securely Sharing Application Log Files with Partners

Regulated environments prohibit DevOps teams from directly accessing their compute instances.  This requirement introduces challenges for collecting and sharing application logs with third-parties (e.g., partners and vendors).  The proposed architecture securely automates this workload using fully managed services and without any custom code!

## How do I deploy this code sample

You can deploy the [cached Cloudformation template](Securely-Sharing-Logs.template.json) through the AWS Console. It supports most public regions. See [Creating a stack on the AWS CloudFormation console](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html) for more information.

**Note**:  The first deployment will take 1-2 hours.  This requirement is due to deploying [AWS Managed Microsoft AD](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_microsoft_ad.html) and joining the example resources to the **securely-sharing-logs.blog** domain.  Customers can authenticate into the domain controller as **SHARINGLOGBLOG\Admin** using the password [retrieved from AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html).

## How do I remove this code sample

Using the AWS Console [Delete the LogSharingBlog stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-delete-stack.html).  This will take an hour or so to complete.

## How do I modify the template

The Cloudformation template is generated through [AWS CDK](https://aws.amazon.com/cdk/). AWS Cloud Development Kit (AWS CDK) is an open source software development framework to define your cloud application resources using familiar programming languages.  This code sample is written in Python3 and available in [app.py](app.py).  Developers can either [install CDK](https://docs.aws.amazon.com/cdk/latest/guide/work-with-cdk-python.html) on their workstation, or use the [Docker-based build terminal](docker-deploy).  With Docker, teams get a consistent experience regardless of the local operating system (e.g., Windows versus OSX).

After making the relevant changes run the below commands:

```sh
# Install the AWS CLI
pip3 install awscli --upgrade

# Install the various cdk modules
pip3 install -r ./images/cdk-deploy/requirements.txt

# Optionally: Configure the AWS credentials
# https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
aws configure

# Optionally: Override the target environment
export CDK_DEFAULT_ACCOUNT=111222334
export CDK_DEFAULT_REGION=us-east-2

# Pretty print the Stack changeset difference
cdk diff -a ./app.py

# Method A: Only Generate the template
cdk synth -a ./app.py

# Method B: Generate and deploy the template
cdk deploy -a ./app.py --require-approval never
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This sample is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
