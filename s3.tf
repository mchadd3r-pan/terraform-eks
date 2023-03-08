resource "aws_s3_bucket" "b" {
  bucket = "terraform-created-58058"

  tags = {
    Name                 = "bucket for eks"
    Environment          = "Dev"
    git_commit           = "069ba515e71424772aeb3e2b46ac61fb6ea9ac79"
    git_file             = "s3.tf"
    git_last_modified_at = "2023-01-30 19:36:50"
    git_last_modified_by = "matthew.chadder@gmail.com"
    git_modifiers        = "matthew.chadder"
    git_org              = "mchadd3r-pan"
    git_repo             = "terraform-eks"
    yor_trace            = "223d30f9-f879-4873-bc52-ac7bb8c05aec"
  }
}

resource "aws_s3_bucket" "b_log_bucket" {
  bucket = "b-log-bucket"
  tags = {
    git_commit           = "069ba515e71424772aeb3e2b46ac61fb6ea9ac79"
    git_file             = "s3.tf"
    git_last_modified_at = "2023-01-30 19:36:50"
    git_last_modified_by = "matthew.chadder@gmail.com"
    git_modifiers        = "matthew.chadder"
    git_org              = "mchadd3r-pan"
    git_repo             = "terraform-eks"
    yor_trace            = "b2a5b986-c018-4bb9-b9a1-98fb549a9d12"
    git_release          = "initial release"
  }
}

resource "aws_s3_bucket" "b_alternate" {
  bucket = "b-alternate-bucket"
  tags = {
    git_commit           = "fc62b805a37f1a442c4d2f9e2990c42f78902b2d"
    git_file             = "s3.tf"
    git_last_modified_at = "2023-03-08 18:11:44"
    git_last_modified_by = "matthew.chadder@gmail.com"
    git_modifiers        = "matthew.chadder"
    git_org              = "mchadd3r-pan"
    git_repo             = "terraform-eks"
    yor_trace            = "b2a5b986-c018-4bb9-b9a1-98fb549a9d12"
    git_release          = "initial release"
  }
}

resource "aws_s3_bucket_logging" "b" {
  bucket = aws_s3_bucket.b.id

  target_bucket = aws_s3_bucket.b_log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.b.id
  acl    = "private"
}