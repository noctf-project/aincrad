variable "repository" {}

group "default" {
  targets = ["services"]
}

target "base" {
  dockerfile = "docker/rust.Dockerfile"
  context    = "."
}
target "services" {
  inherits = ["base"]
  matrix = {
    svc = ["cardinal"]
  }
  name = svc

  target = "${svc}"
  tags = ["${repository}/aincrad-${svc}:latest"]
}
