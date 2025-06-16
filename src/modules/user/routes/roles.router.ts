import Role from '../models/role.model.js';
import { EnduranceRouter, EnduranceAuthMiddleware, type SecurityOptions, EnduranceRequest } from '@programisto/endurance-core';

class RoleRouter extends EnduranceRouter {
  constructor() {
    super(EnduranceAuthMiddleware.getInstance());
  }

  setupRoutes(): void {
    const securityOptions: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageRoles']
    };

    this.post('/:roleId/assign-permissions', securityOptions, async (req: EnduranceRequest, res: any) => {
      const { roleId } = req.params;
      const { permissions } = req.body;

      const role = await Role.findById(roleId);
      if (!role) {
        return res.status(404).json({ message: 'Role not found' });
      }

      role.permissions = permissions;
      await role.save();

      res.json({ message: 'Permissions assigned successfully', role });
    });
  }
}

const router = new RoleRouter();

export default router;
