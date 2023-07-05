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


resource "aws_s3_bucket_versioning" "b" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "destination" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  name = "aws-iam-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_replication_configuration" "b" {
  depends_on = [aws_s3_bucket_versioning.b]
  role   = aws_iam_role.b.arn
  bucket = aws_s3_bucket.b.id
  rule {
    id = "foobar"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.destination.arn
      storage_class = "STANDARD"
    }
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
  }
}


resource "aws_s3_bucket_versioning" "b_log_bucket" {
  bucket = aws_s3_bucket.b_log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "destination" {
  bucket = aws_s3_bucket.b_log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication" {
  name = "aws-iam-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_replication_configuration" "b_log_bucket" {
  depends_on = [aws_s3_bucket_versioning.b_log_bucket]
  role   = aws_iam_role.b_log_bucket.arn
  bucket = aws_s3_bucket.b_log_bucket.id
  rule {
    id = "foobar"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.destination.arn
      storage_class = "STANDARD"
    }
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