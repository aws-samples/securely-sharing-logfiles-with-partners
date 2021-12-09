#!/usr/bin/python3
import builtins
from os import environ, path
from typing import List
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
  aws_directoryservice as ad,
  aws_ssm as ssm,
  aws_fsx as fsx,
  aws_efs as efs,
  aws_s3 as s3,
  aws_iam as iam,
  aws_datasync as ds,
  aws_ec2 as ec2,
  aws_ssm as ssm,
  aws_secretsmanager as sm,
  aws_transfer as tx,
)  

root_dir = path.dirname(__file__)
DIRECTORY_NAME = "securely-sharing-logs.blog"
DIRECTORY_SHORTNAME = "SHARINGLOGBLOG"

class JoinDomainConstruct(Construct):
  @property
  def mad(self)->ad.CfnMicrosoftAD:
    return self.__mad

  def __init__(self, scope: Construct, id: str, mad:ad.CfnMicrosoftAD, targets:List[str], **kwargs) -> None:
    super().__init__(scope, id, **kwargs)  
    self.__mad = mad

    document_name='Join_SecureLogSharing_Domain_'+self.mad.ref
    self.domain_join_document = ssm.CfnDocument(self,'JoinDomainDocument',
      name= document_name,
      content={
        "schemaVersion": "1.0",
        "description": "Domain Join {}".format(self.mad.ref),
        "runtimeConfig": {
          "aws:domainJoin": {
            "properties": {
              "directoryId": self.mad.ref,
              "directoryName": DIRECTORY_NAME,
              "dnsIpAddresses": self.mad.attr_dns_ip_addresses
            }
          }
        }
      })

    self.association = ssm.CfnAssociation(self,'JoinTagAssociation',
      association_name='joindomain_by_tags_'+self.mad.ref,
      name= document_name,
      targets= [
        ssm.CfnAssociation.TargetProperty(
          key='tag:domain',
          values= targets)
      ])

    self.domain_join_document.add_depends_on(mad)
    self.association.add_depends_on(self.domain_join_document)

class DirectoryServicesConstruct(Construct):
  """
  Represents the Active Directory Construct
  """
  def __init__(self, scope: Construct, id: str, vpc:ec2.IVpc, subnet_group_name:str='Private', **kwargs) -> None:
    super().__init__(scope, id, **kwargs)
    cdk.Tags.of(self).add('Owner',DirectoryServicesConstruct.__name__)

    self.password = sm.Secret(self,'Password',
      description='Domain Admin Password',
      generate_secret_string= sm.SecretStringGenerator())

    self.admin = 'Admin'
    self.mad = ad.CfnMicrosoftAD(self,'ActiveDirectory',
      name=DIRECTORY_NAME,
      password=self.password.secret_value.to_string(),
      short_name=DIRECTORY_SHORTNAME,
      enable_sso=False,
      edition= 'Standard',
      vpc_settings= ad.CfnMicrosoftAD.VpcSettingsProperty(
        vpc_id= vpc.vpc_id,
        subnet_ids= vpc.select_subnets(subnet_group_name=subnet_group_name).subnet_ids
      ))

    JoinDomainConstruct(self,'JoinDomain', mad=self.mad, targets=[self.mad.name, self.mad.short_name])

class EFSConstruct(Construct):
  def __init__(self, scope:Construct, id:str, vpc:ec2.IVpc, subnet_group_name:str='Private')->None:
    super().__init__(scope, id)

    self.security_group = ec2.SecurityGroup(self, 'SecurityGroup',
      vpc=vpc,
      allow_all_outbound=True)

    for port,name in [(2049,'NFS')]:
      self.security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
        connection=ec2.Port.tcp(port),
        description='Allow traffic to %s' % name)

    self.filesystem = efs.FileSystem(self,'LinuxFileSystem',
      vpc = vpc,
      enable_automatic_backups=True,
      file_system_name='efs.%s' % DIRECTORY_NAME,
      security_group= self.security_group,
      vpc_subnets= ec2.SubnetSelection(subnet_group_name=subnet_group_name),
      lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,
      removal_policy= cdk.RemovalPolicy.DESTROY)

    '''
    Configure the DataSync Location.
    '''
    subnets = list(vpc.select_subnets(subnet_group_name=subnet_group_name).subnets)
    self.datasync_location = ds.CfnLocationEFS(self,'EFS-Location',
      efs_filesystem_arn= self.filesystem.file_system_arn,
      ec2_config=ds.CfnLocationEFS.Ec2ConfigProperty(
        security_group_arns=[ DataSyncConstruct.sg_arn(self.security_group) ],
        subnet_arn=DataSyncConstruct.subnet_arn(subnets[0])))


class FSxWindowsConstruct(Construct):
  def __init__(self, scope:Construct, id:str, vpc:ec2.IVpc, directory:DirectoryServicesConstruct, subnet_group_name:str='Private')->None:
    super().__init__(scope, id)

    # https://docs.aws.amazon.com/fsx/latest/WindowsGuide/limit-access-security-groups.html
    self.security_group = ec2.SecurityGroup(self,'SecurityGroup',
      vpc=vpc,
      description='FSX for Windows SecurityGroup',
      allow_all_outbound=True)

    for port, name in [(445,'SMB Clients'), (5985,'Admins')]:
      self.security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
        connection = ec2.Port.tcp(port),
        description='Allow FSx %s' % name)

    subnet_ids = vpc.select_subnets(subnet_group_name=subnet_group_name).subnet_ids
    single_subnet = subnet_ids[0:1]
    preferred_subnet_id = single_subnet[0]

    self.filesystem = fsx.CfnFileSystem(self,'FileSystem',
      subnet_ids = single_subnet,
      file_system_type='WINDOWS',
      security_group_ids=[ self.security_group.security_group_id],
      # HDD min = 2TB / SSD = 32
      storage_type='SSD',
      storage_capacity= 32,
      # tags=[
      #   cdk.CfnTag(key='Name',value='winfs.%s' + DIRECTORY_NAME),
      # ],
      windows_configuration= fsx.CfnFileSystem.WindowsConfigurationProperty(
        weekly_maintenance_start_time='1:11:00', # Mon 6AM (UTC-5)
        # 2^n MiB/s with n between 8 and 2048
        throughput_capacity=8,
        active_directory_id=directory.mad.ref,
        automatic_backup_retention_days=30,
        copy_tags_to_backups=True,
        deployment_type='SINGLE_AZ_2', # MULTI_AZ_1,
        preferred_subnet_id= preferred_subnet_id))

    '''
    Setup FSX Windows
    '''
    self.datasync_location = ds.CfnLocationFSxWindows(self,'FSX-Location',
      fsx_filesystem_arn= "arn:aws:fsx:{region}:{account}:file-system/{id}".format(
        region = cdk.Aws.REGION,
        account = cdk.Aws.ACCOUNT_ID,
        id = self.filesystem.ref),
      user=directory.admin,
      domain=directory.mad.short_name,
      password= directory.password.secret_value.to_string(),
      security_group_arns=[ DataSyncConstruct.sg_arn(self.security_group)])

class SharedLogBucket(Construct):
  def __init__(self, scope: Construct, id: builtins.str, vpc:ec2.IVpc) -> None:
    super().__init__(scope, id)
    self.bucket = s3.Bucket(self,'Bucket', removal_policy=cdk.RemovalPolicy.DESTROY)

    '''
    Configure DataSync Locations
    '''
    self.ds_role = iam.Role(self,'DataSyncRole', 
      assumed_by= iam.ServicePrincipal(service='datasync', region=cdk.Aws.REGION),
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('AmazonS3FullAccess')
      ])

    self.datasync_location = ds.CfnLocationS3(self,'S3-Location',
      s3_bucket_arn= self.bucket.bucket_arn,
      s3_config= ds.CfnLocationS3.S3ConfigProperty(bucket_access_role_arn=self.ds_role.role_arn))

class TransferFamilyConstruct(Construct):
  def __init__(self, scope: Construct, id: builtins.str, vpc:ec2.IVpc, mad:ad.CfnMicrosoftAD, bucket:s3.IBucket) -> None:
    super().__init__(scope, id)

    self.security_group = ec2.SecurityGroup(self,'SecurityGroup',
      vpc=vpc,
      allow_all_outbound=True,
      description='Security Group for the TransferFamilyConstruct')

    '''
    Configure Transfer Family Server
    '''
    # TODO: Should this be VPC or Public endpoint?
    # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html
    self.transfer_server = tx.CfnServer(self,'TransferServer',
      domain='S3',
      endpoint_type= 'VPC',
      endpoint_details= tx.CfnServer.EndpointDetailsProperty(
        vpc_id= vpc.vpc_id,
        security_group_ids=[self.security_group.security_group_id],
        subnet_ids=[x.subnet_id for x in vpc.select_subnets(subnet_group_name='Public').subnets]
      ),
      identity_provider_type='AWS_DIRECTORY_SERVICE',
      identity_provider_details=tx.CfnServer.IdentityProviderDetailsProperty(
        directory_id= mad.ref
      ))

class DataStoresConstruct(Construct):
  def __init__(self, scope: Construct, id: builtins.str, vpc:ec2.IVpc, directory:DirectoryServicesConstruct) -> None:
    super().__init__(scope, id)
    assert not vpc is None, "Missing Vpc"
    assert not directory is None, "Missing Managed AD"
    self.fsx_windows = FSxWindowsConstruct(self,'FSX', vpc=vpc, directory=directory)
    self.efs_linux = EFSConstruct(self,'EFS', vpc=vpc)
    self.shared_log_bucket = SharedLogBucket(self,'LogBucket', vpc=vpc)

class DataSyncConstruct(Construct):
  def __init__(self, scope: Construct, id: builtins.str, data_stores:DataStoresConstruct) -> None:
    super().__init__(scope, id)

    # https://docs.aws.amazon.com/lambda/latest/dg/services-cloudwatchevents-expressions.html
    self.efs_linux_task = ds.CfnTask(self,'EFS-Task',
      source_location_arn= data_stores.efs_linux.datasync_location.ref,
      destination_location_arn= data_stores.shared_log_bucket.datasync_location.ref,
      schedule= ds.CfnTask.TaskScheduleProperty(schedule_expression="rate(1 hour)"))

    self.fsx_win_task = ds.CfnTask(self,'FSX-Task',
      source_location_arn= data_stores.fsx_windows.datasync_location.ref,
      destination_location_arn= data_stores.shared_log_bucket.datasync_location.ref,
      schedule= ds.CfnTask.TaskScheduleProperty(schedule_expression="rate(1 hour)"))

  @staticmethod
  def subnet_arn(subnet:ec2.ISubnet)->str:
    return 'arn:aws:ec2:{region}:{account}:subnet/{id}'.format(
      region = cdk.Aws.REGION,
      account = cdk.Aws.ACCOUNT_ID,
      id = subnet.subnet_id
    )

  @staticmethod
  def sg_arn(security_group:ec2.ISecurityGroup)->str:
    return 'arn:aws:ec2:{region}:{account}:security-group/{id}'.format(
      region = cdk.Aws.REGION,
      account = cdk.Aws.ACCOUNT_ID,
      id = security_group.security_group_id
    )

class AppServersConstruct(Construct):
  def __init__(self, scope: Construct, id: builtins.str, vpc:ec2.IVpc, data_stores:DataStoresConstruct) -> None:
    super().__init__(scope, id)
    
    '''
    Tag all resources to auto-join Managed AD domain.
    '''
    cdk.Tags.of(self).add('domain',DIRECTORY_SHORTNAME)

    '''
    Define the role
    '''
    self.role = iam.Role(self,'Role',
      assumed_by= iam.ServicePrincipal(
        service='ec2',
        region= cdk.Aws.REGION),
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMManagedInstanceCore'),
        iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMDirectoryServiceAccess'),
      ])

    '''
    Define Security Group for the instances
    '''
    self.security_group = ec2.SecurityGroup(self,'SecurityGroup',
      vpc=vpc,
      allow_all_outbound=True,
      description='Security Group for the AppServersConstruct')

    for port, name in [(22,'ssh'), (3389,'rdp')]:
      self.security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
        connection = ec2.Port.tcp(port),
        description='Allow incoming for %s protocol' % name)

    '''
    Create the Windows Server
    '''
    win_ami_param = ssm.StringParameter.value_for_string_parameter(self,
      parameter_name="/aws/service/ami-windows-latest/EC2LaunchV2-Windows_Server-2016-English-Full-Base")

    self.windows_server = ec2.Instance(self,'WindowsServer',
      role=self.role,
      vpc=vpc,
      security_group= self.security_group,
      machine_image= ec2.MachineImage.generic_windows(
        ami_map={
          cdk.Stack.of(self).region: win_ami_param,
        }
      ),
      vpc_subnets= ec2.SubnetSelection(subnet_group_name='Public'),
      instance_type= ec2.InstanceType.of(
        instance_class= ec2.InstanceClass.BURSTABLE3,
        instance_size=ec2.InstanceSize.SMALL),
      allow_all_outbound=True,
      user_data_causes_replacement=True)

    '''
    Create the Linux Server
    '''
    linux_ami_param = ssm.StringParameter.value_for_string_parameter(self,
      parameter_name="/aws/service/ami-amazon-linux-latest/amzn-ami-hvm-x86_64-gp2")

    self.linux_server = ec2.Instance(self,'LinuxServer',
      role=self.role,
      vpc=vpc,
      security_group= self.security_group,
      machine_image= ec2.MachineImage.generic_windows(
        ami_map={
          cdk.Stack.of(self).region:linux_ami_param,
        }
      ),
      vpc_subnets= ec2.SubnetSelection(subnet_group_name='Public'),
      instance_type= ec2.InstanceType.of(
        instance_class= ec2.InstanceClass.BURSTABLE3,
        instance_size=ec2.InstanceSize.SMALL),
      allow_all_outbound=True,
      user_data_causes_replacement=True)

    cdk.Tags.of(self.linux_server).add('domain',DIRECTORY_SHORTNAME)

class LogSharingStack(cdk.Stack):
  '''
  Represents the main deployable unit.
  '''
  def __init__(self, scope:cdk.App, id:str, **kwargs)->None:
    super().__init__(scope,id, **kwargs)
    cdk.Tags.of(self).add(key='purpose', value='logshare-blog')

    '''
    Create the networking layer
    '''
    self.vpc = ec2.Vpc(self,'Vpc',cidr='10.0.0.0/22',
      max_azs=2,
      enable_dns_hostnames=True,
      enable_dns_support=True,
      nat_gateways=1,
      subnet_configuration=[
        ec2.SubnetConfiguration(name='Public',subnet_type=ec2.SubnetType.PUBLIC,cidr_mask=24),
        ec2.SubnetConfiguration(name='Private',subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,cidr_mask=24)
      ])

    '''
    Setup Active Directory
    '''
    self.directory = DirectoryServicesConstruct(self,'DirectoryServices', vpc=self.vpc)

    '''
    Create the data storage tier
    '''
    self.data_stores = DataStoresConstruct(self,'DataStores', vpc=self.vpc, directory=self.directory)

    '''
    Create the AppServers
    '''
    self.app_servers = AppServersConstruct(self,'AppServers', vpc=self.vpc, data_stores=self.data_stores)

    '''
    Setup DataSync
    '''
    self.data_sync = DataSyncConstruct(self,'DataSync', data_stores=self.data_stores)

    '''
    Setup Transfer Family
    '''
    self.transfer_server = TransferFamilyConstruct(self,'TxF', 
      vpc=self.vpc,
      mad=self.directory.mad,
      bucket= self.data_stores.shared_log_bucket.bucket)
    

class LogSharingApp(cdk.App):
  def __init__(self, **kwargs)->None:
    super().__init__(**kwargs)
    
    LogSharingStack(self,'Securely-Sharing-Logs', env=cdk.Environment(
      account=environ.get('CDK_DEFAULT_ACCOUNT'),
      region=environ.get('CDK_DEFAULT_REGION')))

app = LogSharingApp()
app.synth()