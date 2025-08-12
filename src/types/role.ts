import { PermissionType } from './permission';

export type RoleType = {
  id: string;
  name: string;
  permissions?: PermissionType[];
};

// Type pour l'API - sans les IDs techniques
export type RoleApiType = {
  name: string;
  permissions?: Omit<PermissionType, 'id'>[];
};
