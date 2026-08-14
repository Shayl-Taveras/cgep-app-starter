terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-da40cebe"
    key          = "layer1/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}
