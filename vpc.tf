module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.2"

  name = "education-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
  }
  tags = {
    git_commit           = "af9294ca38741185c566b94c9b81a99241e2ba71"
    git_file             = "vpc.tf"
    git_last_modified_at = "2022-07-29 18:51:59"
    git_last_modified_by = "alan.szlosek@hashicorp.com"
    git_modifiers        = "alan.szlosek/im2nguyen"
    git_org              = "mchadd3r-pan"
    git_repo             = "terraform-eks"
    yor_trace            = "7603c140-610d-4b33-9f4e-b11b8280632b"
  }
}
