//Almacenamos el terraform.tfstate en un bucket de S3

terraform {
  backend "s3" {
    bucket = "terraform-state-raquel-patino-lab4"
    key = "global/s3/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table ="lab4-raquel-lock"
    encrypt = true
  }
}




//Creamos el vpc
resource "aws_vpc" "terraform_vpc" {
    cidr_block = var.vpc_cidr
    instance_tenancy = "default"
    enable_dns_hostnames    = true
    tags = {
        Name = "terraform-VPC"
       
    }
}


//Creamos las subredes publicas
resource "aws_subnet" "subnet-public1" {
  vpc_id            =  aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_public1_cidr
  availability_zone = "us-east-1a"  
  tags = {
    Name = "Subnet-public1"
  }
}

resource "aws_subnet" "subnet-public2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_public2_cidr
  availability_zone = "us-east-1b"  
  tags = {
    Name = "Subnet-public2"
  }
}

resource "aws_subnet" "subnet-private1" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private1_cidr
  availability_zone = "us-east-1a"  
  tags = {
    Name = "Subnet-private1"
  }
}

resource "aws_subnet" "subnet-private2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private2_cidr
  availability_zone = "us-east-1b"  
  tags = {
    Name = "Subnet-private2"
  }
}

//Internet Gateway
resource "aws_internet_gateway" "terraform_igw" {
  vpc_id = aws_vpc.terraform_vpc.id
   tags = {
        Name = "terraform-igw"
        
    }
}
//Elstic ips para los nat gateway
resource "aws_eip" "nat-eip1" {
    domain   = "vpc"
      tags = {
    Name = "eip1"
  }
}
resource "aws_eip" "nat-eip2" {
    domain   = "vpc"
      tags = {
    Name = "eip2"
  }
}
//Nat Gateways para que las instancias puedan salir a internet. Cada Nat va en una az pública
resource "aws_nat_gateway" "nat1" {
  allocation_id = aws_eip.nat-eip1.id
  subnet_id     = aws_subnet.subnet-public1.id

  tags = {
    Name = "nat1"
  }
}

resource "aws_nat_gateway" "nat2" {
  allocation_id = aws_eip.nat-eip2.id
  subnet_id     = aws_subnet.subnet-public2.id

  tags = {
    Name = "nat2"
  }
}

//Route table para las subredes públicas hacia el internet gateway


resource "aws_route_table" "public-rt" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform_igw.id
  }

  tags = {
    Name = "public-rt"
  }
}

//Route table para las subredes privadas hacia el nat  gateway, una rt por cada nat. 

resource "aws_route_table" "private-rt1" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat1.id
  }

  tags = {
    Name = "private-rt1"
  }
}

resource "aws_route_table" "private-rt2" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat2.id
  }

  tags = {
    Name = "private-rt2"
  }
}
//Asociacion de cada subnet con su correspondiente route table 
resource "aws_route_table_association" "subnet_public1_association" {
  subnet_id      = aws_subnet.subnet-public1.id
  route_table_id = aws_route_table.public-rt.id
}

resource "aws_route_table_association" "subnet_public2_association" {
  subnet_id      = aws_subnet.subnet-public2.id
  route_table_id = aws_route_table.public-rt.id
}

resource "aws_route_table_association" "subnet_private1_association" {
  subnet_id      = aws_subnet.subnet-private1.id
  route_table_id = aws_route_table.private-rt1.id
}

resource "aws_route_table_association" "subnet_private2_association" {
  subnet_id      = aws_subnet.subnet-private2.id
  route_table_id = aws_route_table.private-rt2.id
}
//Creacion de rol  ssm para las instancias EC2

resource "aws_iam_role" "ssm_role" {
  name = "SSMRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
  tags = {
    Name="ssm_role"
  }
}
//se adjunta el rol a la politica
resource "aws_iam_role_policy_attachment" "ssm_attach" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

}


resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "SSMInstanceProfile"
  role = aws_iam_role.ssm_role.name
}

//security group de las EC2
resource "aws_security_group" "EC2_security_group" {
  name = "ec2_security_group"
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.ALB_security_group.id]
   //cidr_blocks = ["0.0.0.0/0"]
     
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  vpc_id = aws_vpc.terraform_vpc.id
}

/*
//creacion de certificado autofirmado para trafico https 

# Genera el certificado y la clave
resource "null_resource" "generate_self_signed_cert" {
  provisioner "local-exec" {
    command = "./generate_cert.sh"
  }

  //solo se ejecuta el script si el archivo no existe previamente
  triggers = {
    cert_exists = fileexists("my-selfsigned.crt") ? "exists" : "${timestamp()}"
  }
}
*/ 
data "local_file" "cert_file" {
  filename = "my-selfsigned.crt"
}

data "local_file" "key_file" {
  filename = "my-selfsigned.key"
}




//Carga del certificado en IAM 
resource "aws_iam_server_certificate" "selfsigned_cert" {
  name_prefix     = "my-selfsigned-cert-"
  certificate_body = data.local_file.cert_file.content
  private_key      = data.local_file.key_file.content
}



//security group del ALB para trafico hhtp

resource "aws_security_group" "ALB_security_group" {
  name = "alb security group"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  vpc_id = aws_vpc.terraform_vpc.id
}



//security group del EFS, permite acceso solo desde las instancias del asg
resource "aws_security_group" "EFS_security_group" {
  name   = "efs_security_group"
  vpc_id = aws_vpc.terraform_vpc.id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    security_groups = [aws_security_group.EC2_security_group.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}




//application load blancer lo desplegamos en las dos subredes publicas

resource "aws_lb" "terraform_alb" {
  name               = "terrafom-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ALB_security_group.id]
  subnets            = [aws_subnet.subnet-public1.id,aws_subnet.subnet-public2.id]
}

//listener para el load balancer en el puerto 80
resource "aws_lb_listener" "alb_listener_http" {
  load_balancer_arn = aws_lb.terraform_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.terrafom_target_group.arn
  }
}

// Listener HTTPS en el ALB usando el certificado de IAM
resource "aws_lb_listener" "alb_listener_https" {
  load_balancer_arn = aws_lb.terraform_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" 
  certificate_arn   = aws_iam_server_certificate.selfsigned_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.terrafom_target_group.arn
  }
}

// target group
resource "aws_lb_target_group" "terrafom_target_group" {
   name     = "learn-asg-terramino"
   port     = 80
   protocol = "HTTP"
   vpc_id   = aws_vpc.terraform_vpc.id
      health_check {
     path                = "/"
     interval            = 30
     timeout             = 5
     healthy_threshold   = 2
     unhealthy_threshold = 2
     matcher             = "200"
   }
 }

//auto scaling group
resource "aws_autoscaling_group" "terraform_asg" {
  min_size             = 1
  max_size             = 2
  desired_capacity     = 1
  launch_template {
    id      = aws_launch_template.terraform_launch_template.id
    version = "$Latest"
  }
  vpc_zone_identifier  =[aws_subnet.subnet-private1.id,aws_subnet.subnet-private2.id]
  target_group_arns    = [aws_lb_target_group.terrafom_target_group.arn]
}

//launch template
resource "aws_launch_template" "terraform_launch_template" {
  name_prefix   = "terraform-launch-template-"
  description   = "Launch template para instancias en subred privada"
  image_id      = "ami-06b21ccaeff8cd686" 
  instance_type = "t2.micro"

  network_interfaces {
    associate_public_ip_address = false 
      security_groups =  [aws_security_group.EC2_security_group.id]
  }
  
 //asignamos el rol ssm
  iam_instance_profile {
    name = aws_iam_instance_profile.ssm_instance_profile.name
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "asg-instance"
    }
  }
    user_data =base64encode( <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<html><body><h1>Hola Mundo desde Apache en AWS!</h1></body></html>" > /var/www/html/index.html
              EOF
              )
}


//  EFS
resource "aws_efs_file_system" "terrafom_efs" {
  tags = {
    Name = "terraform-efs"
  }
}
# Mount targets para cada subred privada
resource "aws_efs_mount_target" "example_efs_mount_target_private1" {
  file_system_id = aws_efs_file_system.terrafom_efs.id
  subnet_id      = aws_subnet.subnet-private1.id
  security_groups = [aws_security_group.EFS_security_group.id]
}

resource "aws_efs_mount_target" "example_efs_mount_target_private2" {
  file_system_id = aws_efs_file_system.terrafom_efs.id
  subnet_id      = aws_subnet.subnet-private2.id
  security_groups = [aws_security_group.EFS_security_group.id]
}







/****************************
resource "aws_instance" "private_ec2_pruebas" {
  ami           = "ami-06b21ccaeff8cd686" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.subnet-private1.id
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Name = "PrivateInstance1"
  }
}

*/