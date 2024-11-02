//Variable para almacenar tags comunes en todo el proyecto


//variables para los valores cidr de vpc y subnets 
variable "vpc_cidr" {
  description = "cidr del vpc"
  type        = string
  default     = "10.0.0.0/16"

}
variable "subnet_public1_cidr" {
  description = "cidr de la subnet publica 1"
  type        = string
  default     = "10.0.1.0/24"

}
variable "subnet_public2_cidr" {
  description = "cidr de la subnet publica 2"
  type        = string
  default     = "10.0.2.0/24"

}
variable "subnet_private1_cidr" {
  description = "cidr de la subnet privada 1"
  type        = string
  default     = "10.0.3.0/24"

}
variable "subnet_private2_cidr" {
  description = "cidr de la subnet privada 2"
  type        = string
  default     = "10.0.4.0/24"

}