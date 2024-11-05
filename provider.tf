terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

/* Configuramos el  AWS Provider en la zona donde vamos a trabajar
   y añadimos los tags comunes a todos los recursos para no hacerlo manualmente.
   Esta configuracion  no aplica al alb 
*/
provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Env   = "Dev"
      Owner = "Ops"
    }
  }
}