module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.0.4"

  cluster_name    = local.cluster_name
  cluster_version = "1.24"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"

  }

  eks_managed_node_groups = {
    one = {
      name = "node-group-1"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 3
      desired_size = 2
    }

    two = {
      name = "node-group-2"

      instance_types = ["t3.small"]

      min_size     = 1
      max_size     = 2
      desired_size = 1
    }
  }
  tags = {
    git_commit           = "345b01cc484053194600249b593405121eaf12ee"
    git_file             = "eks-cluster.tf"
    git_last_modified_at = "2022-12-19 18:53:12"
    git_last_modified_by = "brianmmcclain@gmail.com"
    git_modifiers        = "26+topfunky/alan.szlosek/brianmmcclain/im2nguyen"
    git_org              = "mchadd3r-pan"
    git_repo             = "terraform-eks"
    yor_trace            = "fc9c869b-7ce3-4d93-bbf5-e80c08ffe9da"
  }
}
