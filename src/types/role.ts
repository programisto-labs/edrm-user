import { PermissionType } from './permission';

export type RoleType = {
  id: string;
  name: string;
  permissions?: PermissionType[];
};
