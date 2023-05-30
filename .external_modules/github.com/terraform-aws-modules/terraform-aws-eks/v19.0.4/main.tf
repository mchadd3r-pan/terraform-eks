data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  create = var.create && var.putin_khuylo

  cluster_role = try(aws_iam_role.this[0].arn, var.iam_role_arn)

  create_outposts_local_cluster    = length(var.outpost_config) > 0
  enable_cluster_encryption_config = length(var.cluster_encryption_config) > 0 && !local.create_outposts_local_cluster
}

################################################################################
# Cluster
################################################################################

resource "aws_eks_cluster" "this" {
  count = local.create ? 1 : 0

  name                      = var.cluster_name
  role_arn                  = local.cluster_role
  version                   = var.cluster_version
  enabled_cluster_log_types = var.cluster_enabled_log_types

  vpc_config {
    security_group_ids      = compact(distinct(concat(var.cluster_additional_security_group_ids, [local.cluster_security_group_id])))
    subnet_ids              = coalescelist(var.control_plane_subnet_ids, var.subnet_ids)
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
  }

  dynamic "kubernetes_network_config" {
    # Not valid on Outposts
    for_each = local.create_outposts_local_cluster ? [] : [1]

    content {
      ip_family         = var.cluster_ip_family
      service_ipv4_cidr = var.cluster_service_ipv4_cidr
      service_ipv6_cidr = var.cluster_service_ipv6_cidr
    }
  }

  dynamic "outpost_config" {
    for_each = local.create_outposts_local_cluster ? [var.outpost_config] : []

    content {
      control_plane_instance_type = outpost_config.value.control_plane_instance_type
      outpost_arns                = outpost_config.value.outpost_arns
    }
  }

  dynamic "encryption_config" {
    # Not available on Outposts
    for_each = local.enable_cluster_encryption_config ? [var.cluster_encryption_config] : []

    content {
      provider {
        key_arn = var.create_kms_key ? module.kms.key_arn : encryption_config.value.provider_key_arn
      }
      resources = encryption_config.value.resources
    }
  }

  tags = merge(
    var.tags,
    var.cluster_tags,
  )

  timeouts {
    create = lookup(var.cluster_timeouts, "create", null)
    update = lookup(var.cluster_timeouts, "update", null)
    delete = lookup(var.cluster_timeouts, "delete", null)
  }

  depends_on = [
    aws_iam_role_policy_attachment.this,
    aws_security_group_rule.cluster,
    aws_security_group_rule.node,
    aws_cloudwatch_log_group.this
  ]
}

resource "aws_ec2_tag" "cluster_primary_security_group" {
  # This should not affect the name of the cluster primary security group
  # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2006
  # Ref: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2008
  for_each = { for k, v in merge(var.tags, var.cluster_tags) :
    k => v if local.create && k != "Name" && var.create_cluster_primary_security_group_tags && v != null
  }

  resource_id = aws_eks_cluster.this[0].vpc_config[0].cluster_security_group_id
  key         = each.key
  value       = each.value
}

resource "aws_cloudwatch_log_group" "this" {
  count = local.create && var.create_cloudwatch_log_group ? 1 : 0

  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id

  tags = var.tags
  ami = "ami-06bb00841fcd76aa4"
  associate_public_ip_address = false
  availability_zone = "us-west-2a"
  cpu_core_count = 1
  cpu_threads_per_core = 2
  credit_specification = {"cpu_credits": "unlimited"}
  disable_api_termination = false
  ebs_optimized = false
  get_password_data = false
  hibernation = false
  iam_instance_profile = "eks-50c2e63f-4b1e-53e6-7808-2da6cfc7ae82"
  instance_type = "t3.small"
  ipv6_address_count = 0
  metadata_options = {"http_endpoint": "enabled", "http_put_response_hop_limit": "2", "http_tokens": "required"}
  monitoring = true
  private_ip = "10.0.1.37"
  root_block_device = {"delete_on_termination": true, "encrypted": false, "iops": "100", "volume_size": "20", "volume_type": "gp2"}
  secondary_private_ips = ["10.0.1.179", "10.0.1.22", "10.0.1.47"]
  source_dest_check = true
  subnet_id = "subnet-0ca208901b7e30346"
  tenancy = "default"
  user_data_base64 = "TUlNRS1WZXJzaW9uOiAxLjAKQ29udGVudC1UeXBlOiBtdWx0aXBhcnQvbWl4ZWQ7IGJvdW5kYXJ5PSIvLyIKCi0tLy8KQ29udGVudC1UeXBlOiB0ZXh0L3gtc2hlbGxzY3JpcHQ7IGNoYXJzZXQ9InVzLWFzY2lpIgojIS9iaW4vYmFzaApzZXQgLWV4CkI2NF9DTFVTVEVSX0NBPUxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENrMUpTVU12YWtORFFXVmhaMEYzU1VKQlowbENRVVJCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUkVGV1RWSk5kMFZSV1VSV1VWRkVSWGR3Y21SWFNtd0tZMjAxYkdSSFZucE5RalJZUkZSSmVrMUVSWGhQVkVsNlRsUnJNVTFXYjFoRVZFMTZUVVJGZUU1cVNYcE9WR3N4VFZadmQwWlVSVlJOUWtWSFFURlZSUXBCZUUxTFlUTldhVnBZU25WYVdGSnNZM3BEUTBGVFNYZEVVVmxLUzI5YVNXaDJZMDVCVVVWQ1FsRkJSR2RuUlZCQlJFTkRRVkZ2UTJkblJVSkJUbFZPQ2xaSEwwdGlOa1Z6ZVRKVFVVVXhPV1o0V25JMFJrUkZNRVZNUWtSeFoybHJSMFZhWVVONWIydFZWMjAyVkVKQ1oxTkhOM05aWW5OMVJGUm5lVEJIV0VvS2FuVk1lRll4UXpWd1R6QkJZM1IzT0ZSWVFYVnZhMlJDY0V4bU0zYzNSRUpZVmk5dU4xUmlNalp4ZUd0cmMybGpUR1JuVURGVmNGVldhREF5TVdGT2JncHZaMDFoV2tSNVYzcFBkRVJtZDNoMGNHUkVVWEJ3TTI5TVIxZHhibmt3YWxOM1NXcEdUek4xZFU1MmJuaEtNSEExVDFSQ1ZYSTNjMlZSYmxoWFJYZElDalZQUjBSaWQyUktlVzV4U2paWFMxVTNWM2MzVUVnclVGRTBkRVZWYVdsamFFTXpXRmxwWkdJMWNIZHdkV1Z5Wm5ScFoyMTFPRkozTmxsaU9GbERWR2tLYVZZMWNFWnhTa0l6SzB3clJ6STFNeXR2YjNSVmJtVktjMWRxU0RKd1owNTRhbmx3ZFRaalMzb3ZiMlZyTVRsTlNUVkRVRVV6VDBaYVYzVnpOWHBIS3dwbGFVeExhazk0YTI4NGFHeFphV2xrV1RCRlEwRjNSVUZCWVU1YVRVWmpkMFJuV1VSV1VqQlFRVkZJTDBKQlVVUkJaMHRyVFVFNFIwRXhWV1JGZDBWQ0NpOTNVVVpOUVUxQ1FXWTRkMGhSV1VSV1VqQlBRa0paUlVaS2VEVlllbFJtVXpWWUszVnJkazFDZUdNM1IwNTNNRnB6V2xoTlFsVkhRVEZWWkVWUlVVOEtUVUY1UTBOdGRERlpiVlo1WW0xV01GcFlUWGRFVVZsS1MyOWFTV2gyWTA1QlVVVk1RbEZCUkdkblJVSkJSems0VEVSWFNHcFNPRGhRU0N0R2VrbE1jQXBCUzAxNlV5dHZVa2RUZVRkQmRHVjNSbk5SVUVaVlRESm5UamwyZDI1d05HRklObWRXTTFkWk1VZExhV28yZFdGNmRXZFZaMHRtTTA5aEsxZFRMMWR5Q21Sb1oxbzBRMEZUZVhodGNXNDNaV2x1WkRGamR6YzJXVGhtTXpCNGMwRnFVR1ZVUTBobGFVeFRNSFV6UTAxQ1kxQkRhek5VU0hOVk1tcEhiR2NyTDAwS1NtdGxRM1V2T1ZkNFdsSllXakJGVG5VME1FTkJkalJOZUhVclNXdDJXbnBaT0VSWGJrZG5OV1J2ZDI5d1owSkhNekpJVm5kd1QxTktSRTVMVTBoTlZncEliMlZ0ZURNelUwazJXVXhMT1hCalZHMXFOM1ZDY1UweFpIVkxPR05VU1dscmRIaG9WUzkzVkRFeE5EbGtUVEpETm5oQ1Jsb3pSR0l4U1c4NGMyeE1Da2RVVTJoRlZVaHlVM1Y1ZUdkUUwyNDBTRTVpVmt0UVlVWmplSElyUWxKWVNFeFlVRVZRV0hKa04yRndOVkJGYVhGemJrRnlUaTlxUmtFd1ZtbGxObFFLZEVnMFBRb3RMUzB0TFVWT1JDQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENnPT0KQVBJX1NFUlZFUl9VUkw9aHR0cHM6Ly8xOEJBRjU5MjAzMkRBMDU5MUYzRjFDMkY4RjMzOEIxRS5ncjcudXMtd2VzdC0yLmVrcy5hbWF6b25hd3MuY29tCks4U19DTFVTVEVSX0ROU19JUD0xNzIuMjAuMC4xMAovZXRjL2Vrcy9ib290c3RyYXAuc2ggeW9yLWVrcy1wWG9rM2ZqSiAtLWt1YmVsZXQtZXh0cmEtYXJncyAnLS1ub2RlLWxhYmVscz1la3MuYW1hem9uYXdzLmNvbS9zb3VyY2VMYXVuY2hUZW1wbGF0ZVZlcnNpb249MSxla3MuYW1hem9uYXdzLmNvbS9ub2RlZ3JvdXAtaW1hZ2U9YW1pLTA2YmIwMDg0MWZjZDc2YWE0LGVrcy5hbWF6b25hd3MuY29tL2NhcGFjaXR5VHlwZT1PTl9ERU1BTkQsZWtzLmFtYXpvbmF3cy5jb20vbm9kZWdyb3VwPW5vZGUtZ3JvdXAtMi0yMDIzMDEyMDAwMDUyNjEyMzAwMDAwMDAxNSxla3MuYW1hem9uYXdzLmNvbS9zb3VyY2VMYXVuY2hUZW1wbGF0ZUlkPWx0LTBiOWNlNzZlNGJkNGYyNjVhIC0tbWF4LXBvZHM9MTEnIC0tYjY0LWNsdXN0ZXItY2EgJEI2NF9DTFVTVEVSX0NBIC0tYXBpc2VydmVyLWVuZHBvaW50ICRBUElfU0VSVkVSX1VSTCAtLWRucy1jbHVzdGVyLWlwICRLOFNfQ0xVU1RFUl9ETlNfSVAgLS11c2UtbWF4LXBvZHMgZmFsc2UKCi0tLy8tLQ=="
  volume_tags = {"Name": "node-group-2", "eks:cluster-name": "yor-eks-pXok3fjJ", "eks:nodegroup-name": "node-group-2-20230120000526123000000015", "git_commit": "345b01cc484053194600249b593405121eaf12ee", "git_file": "eks-cluster.tf", "git_last_modified_at": "2022-12-19 18:53:12", "git_last_modified_by": "brianmmcclain@gmail.com", "git_modifiers": "26+topfunky/alan.szlosek/brianmmcclain/im2nguyen", "git_org": "mchadd3r-pan", "git_repo": "terraform-eks", "yor_trace": "fc9c869b-7ce3-4d93-bbf5-e80c08ffe9da"}
  vpc_security_group_ids = ["sg-0d592e0d1583cbd2f"]
}


################################################################################
# KMS Key
################################################################################

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "1.1.0" # Note - be mindful of Terraform/provider version compatibility between modules

  create = local.create && var.create_kms_key && local.enable_cluster_encryption_config # not valid on Outposts

  description             = coalesce(var.kms_key_description, "${var.cluster_name} cluster encryption key")
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.enable_kms_key_rotation

  # Policy
  enable_default_policy     = var.kms_key_enable_default_policy
  key_owners                = var.kms_key_owners
  key_administrators        = coalescelist(var.kms_key_administrators, [data.aws_caller_identity.current.arn])
  key_users                 = concat([local.cluster_role], var.kms_key_users)
  key_service_users         = var.kms_key_service_users
  source_policy_documents   = var.kms_key_source_policy_documents
  override_policy_documents = var.kms_key_override_policy_documents

  # Aliases
  aliases = var.kms_key_aliases
  computed_aliases = {
    # Computed since users can pass in computed values for cluster name such as random provider resources
    cluster = { name = "eks/${var.cluster_name}" }
  }

  tags = var.tags
}

################################################################################
# Cluster Security Group
# Defaults follow https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html
################################################################################

locals {
  cluster_sg_name   = coalesce(var.cluster_security_group_name, "${var.cluster_name}-cluster")
  create_cluster_sg = local.create && var.create_cluster_security_group

  cluster_security_group_id = local.create_cluster_sg ? aws_security_group.cluster[0].id : var.cluster_security_group_id

  # Do not add rules to node security group if the module is not creating it
  cluster_security_group_rules = { for k, v in {
    ingress_nodes_443 = {
      description                = "Node groups to cluster API"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "ingress"
      source_node_security_group = true
    }
  } : k => v if local.create_node_sg }
}

resource "aws_security_group" "cluster" {
  count = local.create_cluster_sg ? 1 : 0

  name        = var.cluster_security_group_use_name_prefix ? null : local.cluster_sg_name
  name_prefix = var.cluster_security_group_use_name_prefix ? "${local.cluster_sg_name}${var.prefix_separator}" : null
  description = var.cluster_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    { "Name" = local.cluster_sg_name },
    var.cluster_security_group_tags
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "cluster" {
  for_each = { for k, v in merge(
    local.cluster_security_group_rules,
    var.cluster_security_group_additional_rules
  ) : k => v if local.create_cluster_sg }

  # Required
  security_group_id = aws_security_group.cluster[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = lookup(each.value, "description", null)
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = try(each.value.source_node_security_group, false) ? local.node_security_group_id : lookup(each.value, "source_security_group_id", null)
}

################################################################################
# IRSA
# Note - this is different from EKS identity provider
################################################################################

data "tls_certificate" "this" {
  # Not available on outposts
  count = local.create && var.enable_irsa && !local.create_outposts_local_cluster ? 1 : 0

  url = aws_eks_cluster.this[0].identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc_provider" {
  # Not available on outposts
  count = local.create && var.enable_irsa && !local.create_outposts_local_cluster ? 1 : 0

  client_id_list  = distinct(compact(concat(["sts.${local.dns_suffix}"], var.openid_connect_audiences)))
  thumbprint_list = concat(data.tls_certificate.this[0].certificates[*].sha1_fingerprint, var.custom_oidc_thumbprints)
  url             = aws_eks_cluster.this[0].identity[0].oidc[0].issuer

  tags = merge(
    { Name = "${var.cluster_name}-eks-irsa" },
    var.tags
  )
}

################################################################################
# IAM Role
################################################################################

locals {
  create_iam_role        = local.create && var.create_iam_role
  iam_role_name          = coalesce(var.iam_role_name, "${var.cluster_name}-cluster")
  iam_role_policy_prefix = "arn:${data.aws_partition.current.partition}:iam::aws:policy"

  cluster_encryption_policy_name = coalesce(var.cluster_encryption_policy_name, "${local.iam_role_name}-ClusterEncryption")

  # TODO - hopefully this can be removed once the AWS endpoint is named properly in China
  # https://github.com/terraform-aws-modules/terraform-aws-eks/issues/1904
  dns_suffix = coalesce(var.cluster_iam_role_dns_suffix, data.aws_partition.current.dns_suffix)
}

data "aws_iam_policy_document" "assume_role_policy" {
  count = local.create && var.create_iam_role ? 1 : 0

  statement {
    sid     = "EKSClusterAssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.${local.dns_suffix}"]
    }

    dynamic "principals" {
      for_each = local.create_outposts_local_cluster ? [1] : []

      content {
        type = "Service"
        identifiers = [
          "ec2.${local.dns_suffix}",
        ]
      }
    }
  }
}

resource "aws_iam_role" "this" {
  count = local.create_iam_role ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}${var.prefix_separator}" : null
  path        = var.iam_role_path
  description = var.iam_role_description

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy[0].json
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = true

  # https://github.com/terraform-aws-modules/terraform-aws-eks/issues/920
  # Resources running on the cluster are still generaring logs when destroying the module resources
  # which results in the log group being re-created even after Terraform destroys it. Removing the
  # ability for the cluster role to create the log group prevents this log group from being re-created
  # outside of Terraform due to services still generating logs during destroy process
  dynamic "inline_policy" {
    for_each = var.create_cloudwatch_log_group ? [1] : []
    content {
      name = local.iam_role_name

      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action   = ["logs:CreateLogGroup"]
            Effect   = "Deny"
            Resource = "*"
          },
        ]
      })
    }
  }

  tags = merge(var.tags, var.iam_role_tags)
}

# Policies attached ref https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html
resource "aws_iam_role_policy_attachment" "this" {
  for_each = { for k, v in {
    AmazonEKSClusterPolicy         = local.create_outposts_local_cluster ? "${local.iam_role_policy_prefix}/AmazonEKSLocalOutpostClusterPolicy" : "${local.iam_role_policy_prefix}/AmazonEKSClusterPolicy",
    AmazonEKSVPCResourceController = "${local.iam_role_policy_prefix}/AmazonEKSVPCResourceController",
  } : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_role_policy_attachment" "additional" {
  for_each = { for k, v in var.iam_role_additional_policies : k => v if local.create_iam_role }

  policy_arn = each.value
  role       = aws_iam_role.this[0].name
}

# Using separate attachment due to `The "for_each" value depends on resource attributes that cannot be determined until apply`
resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  # Encryption config not available on Outposts
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  policy_arn = aws_iam_policy.cluster_encryption[0].arn
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_policy" "cluster_encryption" {
  # Encryption config not available on Outposts
  count = local.create_iam_role && var.attach_cluster_encryption_policy && local.enable_cluster_encryption_config ? 1 : 0

  name        = var.cluster_encryption_policy_use_name_prefix ? null : local.cluster_encryption_policy_name
  name_prefix = var.cluster_encryption_policy_use_name_prefix ? local.cluster_encryption_policy_name : null
  description = var.cluster_encryption_policy_description
  path        = var.cluster_encryption_policy_path

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey",
        ]
        Effect   = "Allow"
        Resource = var.create_kms_key ? module.kms.key_arn : var.cluster_encryption_config.provider_key_arn
      },
    ]
  })

  tags = merge(var.tags, var.cluster_encryption_policy_tags)
}

################################################################################
# EKS Addons
################################################################################

resource "aws_eks_addon" "this" {
  # Not supported on outposts
  for_each = { for k, v in var.cluster_addons : k => v if local.create && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this[0].name
  addon_name   = try(each.value.name, each.key)

  addon_version            = try(each.value.addon_version, data.aws_eks_addon_version.this[each.key].version)
  preserve                 = try(each.value.preserve, null)
  resolve_conflicts        = try(each.value.resolve_conflicts, "OVERWRITE")
  service_account_role_arn = try(each.value.service_account_role_arn, null)

  timeouts {
    create = try(each.value.timeouts.create, var.cluster_addons_timeouts.create, null)
    update = try(each.value.timeouts.update, var.cluster_addons_timeouts.update, null)
    delete = try(each.value.timeouts.delete, var.cluster_addons_timeouts.delete, null)
  }

  depends_on = [
    module.fargate_profile,
    module.eks_managed_node_group,
    module.self_managed_node_group,
  ]

  tags = var.tags
}

data "aws_eks_addon_version" "this" {
  for_each = { for k, v in var.cluster_addons : k => v if local.create && !local.create_outposts_local_cluster }

  addon_name         = try(each.value.name, each.key)
  kubernetes_version = coalesce(var.cluster_version, aws_eks_cluster.this[0].version)
  most_recent        = try(each.value.most_recent, null)
}

################################################################################
# EKS Identity Provider
# Note - this is different from IRSA
################################################################################

resource "aws_eks_identity_provider_config" "this" {
  for_each = { for k, v in var.cluster_identity_providers : k => v if local.create && !local.create_outposts_local_cluster }

  cluster_name = aws_eks_cluster.this[0].name

  oidc {
    client_id                     = each.value.client_id
    groups_claim                  = lookup(each.value, "groups_claim", null)
    groups_prefix                 = lookup(each.value, "groups_prefix", null)
    identity_provider_config_name = try(each.value.identity_provider_config_name, each.key)
    issuer_url                    = try(each.value.issuer_url, aws_eks_cluster.this[0].identity[0].oidc[0].issuer)
    required_claims               = lookup(each.value, "required_claims", null)
    username_claim                = lookup(each.value, "username_claim", null)
    username_prefix               = lookup(each.value, "username_prefix", null)
  }

  tags = var.tags
}

################################################################################
# aws-auth configmap
################################################################################

locals {
  node_iam_role_arns_non_windows = distinct(
    compact(
      concat(
        [for group in module.eks_managed_node_group : group.iam_role_arn],
        [for group in module.self_managed_node_group : group.iam_role_arn if group.platform != "windows"],
        var.aws_auth_node_iam_role_arns_non_windows,
      )
    )
  )

  node_iam_role_arns_windows = distinct(
    compact(
      concat(
        [for group in module.self_managed_node_group : group.iam_role_arn if group.platform == "windows"],
        var.aws_auth_node_iam_role_arns_windows,
      )
    )
  )

  fargate_profile_pod_execution_role_arns = distinct(
    compact(
      concat(
        [for group in module.fargate_profile : group.fargate_profile_pod_execution_role_arn],
        var.aws_auth_fargate_profile_pod_execution_role_arns,
      )
    )
  )

  aws_auth_configmap_data = {
    mapRoles = yamlencode(concat(
      [for role_arn in local.node_iam_role_arns_non_windows : {
        rolearn  = role_arn
        username = "system:node:{{EC2PrivateDNSName}}"
        groups = [
          "system:bootstrappers",
          "system:nodes",
        ]
        }
      ],
      [for role_arn in local.node_iam_role_arns_windows : {
        rolearn  = role_arn
        username = "system:node:{{EC2PrivateDNSName}}"
        groups = [
          "eks:kube-proxy-windows",
          "system:bootstrappers",
          "system:nodes",
        ]
        }
      ],
      # Fargate profile
      [for role_arn in local.fargate_profile_pod_execution_role_arns : {
        rolearn  = role_arn
        username = "system:node:{{SessionName}}"
        groups = [
          "system:bootstrappers",
          "system:nodes",
          "system:node-proxier",
        ]
        }
      ],
      var.aws_auth_roles
    ))
    mapUsers    = yamlencode(var.aws_auth_users)
    mapAccounts = yamlencode(var.aws_auth_accounts)
  }
}

resource "kubernetes_config_map" "aws_auth" {
  count = var.create && var.create_aws_auth_configmap ? 1 : 0

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = local.aws_auth_configmap_data

  lifecycle {
    # We are ignoring the data here since we will manage it with the resource below
    # This is only intended to be used in scenarios where the configmap does not exist
    ignore_changes = [data]
  }
}

resource "kubernetes_config_map_v1_data" "aws_auth" {
  count = var.create && var.manage_aws_auth_configmap ? 1 : 0

  force = true

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = local.aws_auth_configmap_data

  depends_on = [
    # Required for instances where the configmap does not exist yet to avoid race condition
    kubernetes_config_map.aws_auth,
  ]
}
