# Configure the AWS Provider
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Input Variables
variable "region" {
  description = "The AWS region to deploy resources to"
  type        = string
  default     = "us-east-2" # Change this to your desired region
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "A list of CIDR blocks for the public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"] # Example subnets
}

variable "private_subnet_cidrs" {
  description = "A list of CIDR blocks for the private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "instance_type" {
  description = "The EC2 instance type to use"
  type        = string
  default     = "t3.medium" #  Consider t3.medium or larger
}

variable "key_name" {
  description = "The name of the SSH key pair to use for EC2 access"
  type        = string
  default     = "" # Change this to your key pair.  If empty, you will not be able to SSH in.
}

variable "ami_id" {
  description = "The ID of the AMI to use for the EC2 instance"
  type        = string
  default     = "ami-097261bd06e355492" #  Ubuntu 16.04 in us-east-2.
}

variable "app_port" {
  description = "The port that the crAPI application will listen on"
  type        = number
  default     = 8080
}

variable "mongo_backup_bucket_name" {
  description = "Name of the S3 bucket for MongoDB backups"
  type        = string
  default     = "crapi-mongo-backups_8675309" # Change this to a unique bucket name
}

variable "guardduty_s3_bucket_name" {
  description = "Name of the S3 bucket for GuardDuty logs"
  type        = string
  default     = "crapi-guardduty-logs_8675309" # Change this to a unique bucket name
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"] # Changed to focal
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Create VPC
resource "aws_vpc" "crAPI_vpc" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "crAPI-VPC"
  }
}

# Create Public Subnets
resource "aws_subnet" "crAPI_public_subnets" {
  count = length(var.public_subnet_cidrs)
  vpc_id     = aws_vpc.crAPI_vpc.id
  cidr_block = var.public_subnet_cidrs[count.index]
  availability_zone = "us-east-2${count.index + 1}" #  Make sure this matches the number of subnets
  tags = {
    Name = "crAPI-Public-Subnet-${count.index + 1}"
  }
}

# Create Private Subnets
resource "aws_subnet" "crAPI_private_subnets" {
  count = length(var.private_subnet_cidrs)
  vpc_id     = aws_vpc.crAPI_vpc.id
  cidr_block = var.private_subnet_cidrs[count.index]
  availability_zone = "us-east-2${count.index + 1}" #  Make sure this matches the number of subnets
  tags = {
    Name = "crAPI-Private-Subnet-${count.index + 1}"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "crAPI_igw" {
  vpc_id = aws_vpc.crAPI_vpc.id
  tags = {
    Name = "crAPI-IGW"
  }
}

# Create Public Route Table
resource "aws_route_table" "crAPI_public_rt" {
  vpc_id = aws_vpc.crAPI_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.crAPI_igw.id
  }
  tags = {
    Name = "crAPI-Public-RT"
  }
}

# Associate Public Subnets with Public Route Table
resource "aws_route_table_association" "crAPI_public_rta" {
  count = length(aws_subnet.crAPI_public_subnets)
  subnet_id      = aws_subnet.crAPI_public_subnets[count.index].id
  route_table_id = aws_route_table.crAPI_public_rt.id
}

# Create Security Group for EC2 Instance
resource "aws_security_group" "crAPI_sg" {
  name        = "crAPI-SG"
  description = "Security group for crAPI instance"
  vpc_id      = aws_vpc.crAPI_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #  WARNING:  This is open to the world.  Restrict as needed.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "crAPI-SG"
  }
}

# Create EC2 Instance
resource "aws_instance" "crAPI_instance" {
  ami           = var.ami_id #  Use the variable
  instance_type = var.instance_type
  subnet_id     = aws_subnet.crAPI_public_subnets[0].id #  Place in a public subnet
  security_groups = [aws_security_group.crAPI_sg.id]
  key_name      = var.key_name #  Use the key name variable
  user_data = templatefile("crAPI_setup.sh", {
        app_port = var.app_port,
        mongo_backup_bucket = var.mongo_backup_bucket_name
    }) # Use a template for user data
  iam_instance_profile = aws_instance_profile.ec2_s3_backup_profile.name # Attach the instance profile

  tags = {
    Name = "crAPI-Instance"
  }
  #  Important:  If you do not specify a key_name, you will not be able to SSH into the instance.
}

# Create S3 Bucket for MongoDB Backups
resource "aws_s3_bucket" "mongo_backup_bucket" {
  bucket = var.mongo_backup_bucket_name
  acl    = "public-read" # WARNING: This makes the bucket contents publicly readable.

  policy = jsonencode({ # Make bucket listable
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PublicRead"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.mongo_backup_bucket_name}",
          "arn:aws:s3:::${var.mongo_backup_bucket_name}/*"
        ]
      }
    ]
  })

  tags = {
    Name = "MongoDB Backup Bucket"
  }
}

# Create IAM role and policy for EC2 to access S3
resource "aws_iam_role" "ec2_s3_backup_role" {
  name = "ec2-s3-backup-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      },
    ]
  })
}

resource "aws_iam_role_policy" "ec2_s3_backup_policy" {
  name = "ec2-s3-backup-policy"
  role = aws_iam_role.ec2_s3_backup_role.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ],
        Effect = "Allow"
        Resource = [
          "arn:aws:s3:::${var.mongo_backup_bucket_name}",
          "arn:aws:s3:::${var.mongo_backup_bucket_name}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_s3_backup_profile" {
  name = "ec2-s3-backup-profile"
  role = aws_iam_role.ec2_s3_backup_role.name
}

# Modify EC2 Instance to use the IAM role.
resource "aws_instance" "crAPI_instance_IAM" {
  ami           = var.ami_id #  Use the variable
  instance_type = var.instance_type
  subnet_id     = aws_subnet.crAPI_public_subnets[0].id #  Place in a public subnet
  security_groups = [aws_security_group.crAPI_sg.id]
  key_name      = var.key_name #  Use the key name variable
  user_data = templatefile("crAPI_setup.sh", {
        app_port = var.app_port,
        mongo_backup_bucket = var.mongo_backup_bucket_name
    }) # Use a template for user data
  iam_instance_profile = aws_instance_profile.ec2_s3_backup_profile.name # Attach the instance profile

  tags = {
    Name = "crAPI-Instance"
  }
  #  Important:  If you do not specify a key_name, you will not be able to SSH into the instance.
}

# Create S3 Bucket for GuardDuty Logs
resource "aws_s3_bucket" "guardduty_log_bucket" {
  bucket = var.guardduty_s3_bucket_name
  acl    = "private" # Ensure the log bucket is NOT publicly accessible

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow",
        Principal = {
          Service = "logs.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "arn:aws:s3:::${var.guardduty_s3_bucket_name}/*",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow",
        Principal = {
          Service = "logs.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "arn:aws:s3:::${var.guardduty_s3_bucket_name}",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name = "GuardDuty Log Bucket"
  }
}

## - one stab at GuardDuty
# Enable GuardDuty and configure S3 logging
#resource "aws_guardduty_detector" "guardduty" {
#  enable = true
#  s3_data_source {
#    bucket_arn = aws_s3_bucket.guardduty_log_bucket.arn
#    #  No policy needed, bucket policy handles this
#    }
#}

resource "aws_s3_bucket" "guardduty_logs" {
  bucket = "guardduty-logs-8675309Wizz" # Ensure bucket name is globally unique
  #  ACL should be private and NOT public-read.  Using 'private'
  acl    = "private"
}

# Create an S3 bucket policy to allow GuardDuty to write logs
resource "aws_s3_bucket_policy" "guardduty_logs_policy" {
  bucket = aws_s3_bucket.guardduty_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.guardduty_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:GetBucketLocation"
        Resource  = "${aws_s3_bucket.guardduty_logs.arn}"
      }
    ]
  })
}

# Enable GuardDuty and configure it to use the S3 bucket for logs
resource "aws_guardduty_detector" "guardduty" {
  enable = true #  Enable GuardDuty

  # Configure S3 export options.
 # s3_export_options {
  #  bucket_arn = aws_s3_bucket.guardduty_logs.arn
    #  No KMS key specified, so S3 will use AES256.
    #  If you want to use a KMS key, add:
    #  kms_key_arn = "arn:aws:kms:your-region:your-account-id:key/your-key-id"
   # }
}



  # Optional: Enable server-side encryption.  Recommended for security.
  #server_side_encryption_configuration {
  #  rule {
  #    apply_server_side_encryption_by_default {
  #      sse_algorithm = "AES256" # Or "aws:kms" if you want to use KMS
  #    }
  #  }
  #}


# Output the public IP of the instance
output "crAPI_public_ip" {
  value = aws_instance.crAPI_instance.public_ip
}

output "crAPI_instance_id" {
  value = aws_instance.crAPI_instance.id
}

output "mongo_backup_bucket_name" {
  value = aws_s3_bucket.mongo_backup_bucket.id
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.guardduty.id
}

output "guardduty_log_bucket_name" {
  value = aws_s3_bucket.guardduty_log_bucket.id
}
