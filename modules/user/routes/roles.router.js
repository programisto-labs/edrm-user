import Role from '../models/role.model.js';
import { accessControl } from 'endurance-core/dist/auth.js';
import routerBase from 'endurance-core/dist/router.js';

const checkSuperAdmin = accessControl.checkUserPermissions([], true);
const router = routerBase({ requireDb: true });
router.autoWire(Role, 'Role', checkSuperAdmin);

router.post('/:roleId/assign-permissions', checkSuperAdmin, async (req, res) => {
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

export default router;