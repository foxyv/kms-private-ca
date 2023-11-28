# AWS KMS Secured Certificate Authority

This repository contains the code for a Certificate Authority (CA) that uses AWS KMS to secure the private key.

## Why?

Creating a certificate authority is easy. Creating a secure certificate authority is hard. Private certificate
authorities are very expensive. This project aims to make it easy to create a secure private certificate authority for
pennies.

## How?

Certificate Authority private keys are encrypted using keys managed by AWS KMS. Instead of trying to keep a plaintext
private key safe in a vault somewhere we can encrypt them and store them in a database. Then, only users with access to
the KMS master key can decrypt the private key and sign certificates.

## Note

This project is still in development. It is not ready for production use.

## Project Wobbegong

Project Wobbegong is an open source project similar to Apache. It is a collection of open source projects that are
freely usable by anyone under the MIT license.