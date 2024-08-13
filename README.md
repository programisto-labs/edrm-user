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


## Routes
- /user/register (POST) : Register a user
- /user/login (POST) : Authenticate a user
- /user/profile (GET) : Get profile information of current user
- /user/profile (PATCH) : Update the current user profile
- /user/profile (DELETE) : Delete the current user profile
- /user/assign-role (POST) : Assign a role to a user
- /role (Default Rest CRUD) : Manage roles
- /role/:role-id/assign-permision : Assign a permission a specific role
- /permission (Default Rest CRUD) : Manage permissions

