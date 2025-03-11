import Permission from '../models/permission.model.js';
import { accessControl } from 'endurance-core/dist/auth.js';
import routerBase from 'endurance-core/dist/router.js';

const checkSuperAdmin = accessControl.checkUserPermissions([], true);
const router = routerBase({ requireDb: true });

router.autoWire(Permission, 'Permission', checkSuperAdmin);

export default router;
