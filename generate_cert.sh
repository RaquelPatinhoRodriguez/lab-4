#!/bin/bash

# Genera la clave privada
openssl genrsa -out my-selfsigned.key 2048



  # Crear el certificado autofirmado
 

openssl req -new -x509 -key my-selfsigned.key -out my-selfsigned.crt -days 365 -subj "C=US,ST=State,L=City,O=Organization,OU=Department,CN=example.com"
