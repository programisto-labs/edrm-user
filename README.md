# EDRM User mangement module

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Routes](#routes)


## Description
This module is a user, role and permission management. It provides all the login implementation including JWT to enable the endurance core auth lib to work. 

## Features
- Register and login users
- Register, use, list and revoke passkeys
- Get profile informations
- Assign role to user
- Manage roles and permissions

## Installation

   ```bash
   npm install edrm-user
   ```

## Environment Variables
Not linked to the module but to auth lib from endurance core :
- JWT_SECRET
- JWT_REFRESH_SECRET

Passkeys are enabled with `LOGIN_PASSKEY_ACTIVATED=true` and require:
- `PASSKEY_RP_ID`: relying-party domain without a protocol, for example `example.com`
- `PASSKEY_ORIGIN`: exact frontend origin, for example `https://app.example.com`
- `PASSKEY_RP_NAME` (optional): name shown by the authenticator; defaults to `Endurance`

`PASSKEY_ORIGIN` must use HTTPS, except for `http://localhost` during local development.


## Routes
- /user/register (POST) : Register a user
- /user/login (POST) : Authenticate a user
- /user/passkeys/register/options (POST) : Start passkey enrollment (authenticated)
- /user/passkeys/register/verify (POST) : Complete passkey enrollment (authenticated)
- /user/login/passkey/options (POST) : Start passkey login with `{ "email": "..." }`
- /user/login/passkey/verify (POST) : Complete passkey login and receive JWT tokens
- /user/passkeys (GET) : List the current user's passkeys (authenticated)
- /user/passkeys/:credentialId (DELETE) : Revoke a passkey (authenticated)
- /user/profile (GET) : Get profile information of current user
- /user/profile (PATCH) : Update the current user profile
- /user/profile (DELETE) : Delete the current user profile
- /user/assign-role (POST) : Assign a role to a user
- /role (Default Rest CRUD) : Manage roles
- /role/:role-id/assign-permision : Assign a permission a specific role
- /permission (Default Rest CRUD) : Manage permissions

