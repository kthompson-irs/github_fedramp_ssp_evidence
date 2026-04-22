resource "aws_s3_bucket" "ps04" {
  bucket = "ps04-evidence-bucket"

  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.ps04.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "lock" {
  bucket = aws_s3_bucket.ps04.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      days  = 90
    }
  }
}
