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
   // enable_dns_support   = true 
  
    tags = {
        Name = "terraform-VPC"
       
    }
}


// Subredes publicas
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
//Subredes privadas para las EC2
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

//Subredes privadas para la BD
resource "aws_subnet" "subnet-private3" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private3_cidr
  availability_zone = "us-east-1a"  
  tags = {
    Name = "Subnet-private3"
  }
}

resource "aws_subnet" "subnet-private4" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private4_cidr
  availability_zone = "us-east-1b"  
  tags = {
    Name = "Subnet-private4"
  }
}
//subredes privadas para elasticache
resource "aws_subnet" "subnet-private5" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private5_cidr
  availability_zone = "us-east-1a"  
  tags = {
    Name = "Subnet-private5"
  }
}

resource "aws_subnet" "subnet-private6" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_private6_cidr
  availability_zone = "us-east-1b"  
  tags = {
    Name = "Subnet-private6"
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
//le añadimos el acceso a secrets manager
resource "aws_iam_role_policy" "ssm_secrets_access_policy" {
  name = "ssm-secrets-access-policy"
  role = aws_iam_role.ssm_role.name

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": aws_secretsmanager_secret.db_secret_pass.arn
      }
    ]
  })
}

# Política de IAM para permitir acceso de lectura/escritura en el bucket de S3
resource "aws_iam_policy" "wordpress_s3_policy" {
  name        = "WordPressS3Policy"
  description = "Permite a las instancias de EC2 acceder al bucket de S3 de WordPress para almacenar medios"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        Resource = ["${aws_s3_bucket.media_bucket.arn}/*"]
      },
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",     
          "s3:ListBucketMultipartUploads"  
        ],
        Resource = "${aws_s3_bucket.media_bucket.arn}"
      }
    ]
  })
}

# Adjuntar la política al rol de IAM ya existente de las instancias EC2
resource "aws_iam_role_policy_attachment" "attach_wordpress_s3_policy" {
  role       = aws_iam_role.ssm_role.name  
  policy_arn = aws_iam_policy.wordpress_s3_policy.arn
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
//creacion de certificado autofirmado para trafico https . una vez creado lo dejamos comentado para que no lo genere nuevamente

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
  //bloque de codigo para evitar que intente borrar el certificado al hacer modificaciones, solo es necesario si no se hace un apply desde cero 
    /*lifecycle {
    prevent_destroy = true
     ignore_changes  = all
  }*/
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
  /* con fines de pruebas, no se utiliza en version defininta
    ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
*/
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  vpc_id = aws_vpc.terraform_vpc.id
}

//Security group de la base de datos 
resource "aws_security_group" "rds_sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.terraform_vpc.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.EC2_security_group.id]  # Security Group de EC2
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

//security group de la cache 

# Grupo de seguridad para ElastiCache
resource "aws_security_group" "elasticache_sg" {
  name   = "elasticache_sg"
  vpc_id = aws_vpc.terraform_vpc.id

  # Permitir acceso solo desde el grupo de seguridad de EC2 en el puerto de Redis
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.EC2_security_group.id] 
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elasticache_security_group"
  }
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

//Distribucion de cloudfront 

resource "aws_cloudfront_distribution" "cloudfront_lab_4" {
  origin {
    domain_name = aws_lb.terraform_alb.dns_name     # Dominio del ALB como único origen
    origin_id   = "ALBOrigin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2", "TLSv1.1"]  # Protocolos SSL requeridos
    }
  }

  # Configuración del comportamiento de caché predeterminado para servir contenido desde el ALB
  default_cache_behavior {
    target_origin_id       = "ALBOrigin"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }
    min_ttl                = 0
    default_ttl            = 3600   # 1 hora
    max_ttl                = 86400  # 24 horas
  }

  enabled             = true
  comment             = "CloudFront distribution for WordPress site with ALB for lab 4"
  default_root_object = "index.php"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true   # Usar el certificado predeterminado de CloudFront
    ssl_support_method             = "sni-only"
  }

  tags = {
    Name = "cloudfront-lab-4"
  }
}



//Bucket S3 para las imagenes de wordpress
resource "aws_s3_bucket" "media_bucket" {
  bucket = "raquel-patinho-wordpress-media"  

  tags = {
    Name        = "WordPress Media Bucket"
    
  }
}

// Configurar el bloqueo de acceso público
resource "aws_s3_bucket_public_access_block" "media_bucket_block" {
  bucket                  = aws_s3_bucket.media_bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

/* Crear una identidad de acceso de origen para CloudFront
resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "Access for S3 from CloudFront"
}*/

// Política del bucket 
resource "aws_s3_bucket_policy" "media_bucket_policy" {
  bucket = aws_s3_bucket.media_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = "*",
        /*{
          
          AWS = aws_cloudfront_origin_access_identity.oai.iam_arn  # Identidad de acceso de CloudFront
        }*/
        Action   = "s3:GetObject",
        Resource = [
          "${aws_s3_bucket.media_bucket.arn}",      
          "${aws_s3_bucket.media_bucket.arn}/*"     
        ]
      }
    ]
  })
}

resource "aws_lb" "terraform_alb" {
  name               = "terrafom-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ALB_security_group.id]
  subnets            = [aws_subnet.subnet-public1.id,aws_subnet.subnet-public2.id]
}

/*//listener para el load balancer en el puerto 80 para pruebas, no se utiliza en la version definitiva
resource "aws_lb_listener" "alb_listener_http" {
  load_balancer_arn = aws_lb.terraform_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.terrafom_target_group.arn
  }
}*/

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
     //path                ="/health/healthcheck.html" 
     path                ="/health/healthcheck.html" 
     interval            = 30
     timeout             = 5
     healthy_threshold   = 2
     unhealthy_threshold = 2
     matcher             = "200"
   }
 }

//auto scaling group
resource "aws_autoscaling_group" "terraform_asg" {
  min_size             =1
  max_size             = 1
  desired_capacity     = 1
  launch_template {
    id      = aws_launch_template.terraform_launch_template.id
    version = "$Latest"
  }
  vpc_zone_identifier  =[aws_subnet.subnet-private1.id,aws_subnet.subnet-private2.id]
  target_group_arns    = [aws_lb_target_group.terrafom_target_group.arn]
  # Asegura que el ASG espere a que el secreto y la base de datos estén creados
  depends_on = [
    aws_secretsmanager_secret.db_secret_pass,
    aws_db_instance.postgres
  ]
}

//launch template
resource "aws_launch_template" "terraform_launch_template" {
  name_prefix   = "terraform-launch-template-"
  description   = "Launch template para instancias en subred privada"
  image_id      = "ami-01d333616dd809baa"
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
  # Asegura que el Launch Template espere al secreto y la base de datos
  depends_on = [
    aws_secretsmanager_secret.db_secret_pass,
    aws_db_instance.postgres
  ]

    user_data = base64encode(file("user_data.sh"))
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



//Subnet group para la base de datos 
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "drupal-db-subnet-group"
  description = "Subnet group para PostgreSQL RDS"
  subnet_ids = [aws_subnet.subnet-private3.id,aws_subnet.subnet-private4.id]  # Pasamos subredes privadas en distintas zonas

  tags = {
    Name = "drupal-db-subnet-group"
  }
}
//Recurdo de base de datos 
resource "aws_db_instance" "postgres" {
  identifier              = "drupal-postgresql-db"
  engine                  = "postgres"
  engine_version          = "14"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  db_name                 = "drupaldb"
  username                = "drupaladmin"
  password = ":jncrqs!"
  db_subnet_group_name    = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  backup_retention_period = 7
  backup_window = "03:00-04:00"
  multi_az                = true 
  skip_final_snapshot     = true  

  tags = {
    Name = "drupal-postgresql-db"
  }
}




//Alamacenamos la contraseña en secrets manager
resource "aws_secretsmanager_secret" "db_secret_pass" {
  name        = "drupal-db-pass"
  description = "Constaseña  de la base de datos PostgreSQL para Drupal"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_secret_version" {
  secret_id = aws_secretsmanager_secret.db_secret_pass.id
  secret_string = jsonencode({
    username = "drupaladmin"
    //password = random_password.db_password.result  # Misma contraseña que en el módulo RDS
    password = ":jncrqs!"
    host     = aws_db_instance.postgres.address
    port     = aws_db_instance.postgres.port
    dbname   = aws_db_instance.postgres.db_name
  })
}


// ElastiCache Redis
resource "aws_elasticache_cluster" "redis_cluster" {
  cluster_id           = "redis-cluster"
  engine               = "redis"
  node_type            = "cache.t3.micro"  # Cambia el tipo de nodo según tus necesidades
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  subnet_group_name = aws_elasticache_subnet_group.elasticache_subnet_group.name
  security_group_ids = [aws_security_group.elasticache_sg.id]

  tags = {
    Name = "redis-cluster"
  }
}



// Subnet Group para ElastiCache
resource "aws_elasticache_subnet_group" "elasticache_subnet_group" {
  name       = "elasticache-subnet-group"
  subnet_ids = [aws_subnet.subnet-private5.id,aws_subnet.subnet-private6.id ]//falta crear las subnets 

  tags = {
    Name = "elasticache_subnet_group"
  }
}

//Route 53
resource "aws_route53_zone" "internal_zone" {
  name = "internal.lab4.com"  
  vpc {
    vpc_id = aws_vpc.terraform_vpc.id   
  }
 

  tags = {
    
    Name = "internal_zone"
   
  }
}

// Registro para el ALB
resource "aws_route53_record" "alb_record" {
  zone_id = aws_route53_zone.internal_zone.zone_id
  name    = "alb.internal.lab4.com"  # Subdominio para el ALB
  type    = "A"
  alias {
    name                   = aws_lb.terraform_alb.dns_name    # Nombre del ALB
    zone_id                = aws_lb.terraform_alb.zone_id      # Zona del ALB
    evaluate_target_health = true
  }


}

//Registro para Redis
resource "aws_route53_record" "redis_record" {
  zone_id = aws_route53_zone.internal_zone.zone_id
  name    = "redis.internal.lab4.com"  # Subdominio para Redis
  type    = "CNAME"
  ttl     = 30
  records = [aws_elasticache_cluster.redis_cluster.cache_nodes[0].address]  # Dirección del nodo Redis


}


//Registro para la base de datos RDS 
resource "aws_route53_record" "rds_record" {
  zone_id = aws_route53_zone.internal_zone.zone_id
  name    = "rds.internal.lab4.com"  # Subdominio para la base de datos RDS
  type    = "CNAME"
  ttl     = 30
  records = [aws_db_instance.postgres.address]

}

//Dashboard para cloudwatch
resource "aws_cloudwatch_dashboard" "dashboard" {
  dashboard_name = "cloudwatch-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        "type": "metric",
        "x": 0,
        "y": 0,
        "width": 6,
        "height": 6,
        "properties": {
          "metrics": [
            [ "AWS/EC2", "CPUUtilization", "InstanceId", "mi-instance-id" ]
          ],
          "title": "CPU Utilization",
          "stat": "Average",
          "period": 300,
          "region": "us-west-2"
        }
      },
      {
        "type": "metric",
        "x": 6,
        "y": 0,
        "width": 6,
        "height": 6,
        "properties": {
          "metrics": [
            [ "AWS/EC2", "StatusCheckFailed", "InstanceId", "mi-instance-id" ]
          ],
          "title": "Instance Status",
          "stat": "Sum",
          "period": 300,
          "region": "us-west-2"
        }
      },
      {
        "type": "metric",
        "x": 0,
        "y": 6,
        "width": 12,
        "height": 6,
        "properties": {
          "metrics": [
            [ "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", "mi-load-balancer" ]
          ],
          "title": "Latency",
          "stat": "Average",
          "period": 60,
          "region": "us-west-2"
        }
      }
    ]
  })
}


