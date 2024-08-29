import Role from '../models/role.model';
import { checkUserPermissions } from '../middlewares/auth.middleware';
import auth from 'endurance-core/lib/auth';
import router from 'endurance-core/lib/router';

const checkSuperAdmin = checkUserPermissions([], true); // Utilisation du middleware

router.autoWire(Role, 'Role');

router.post('/:roleId/assign-permissions', checkSuperAdmin, auth.asyncHandler(async (req, res) => {
  const { roleId } = req.params;
  const { permissions } = req.body;

  const role = await Role.findById(roleId);
  if (!role) {
    return res.status(404).json({ message: 'Role not found' });
  }

  role.permissions = permissions;
  await role.save();

  res.json({ message: 'Permissions assigned successfully', role });
}));

export default router;