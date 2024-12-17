import Permission from '../models/permission.model.js';
import auth from 'endurance-core/lib/auth.js';
import routerBase from 'endurance-core/lib/router.js';

const checkSuperAdmin = auth.checkUserPermissions([], true); 
const router = routerBase({requireDb: true});

router.autoWire(Permission, 'Permission', checkSuperAdmin);

export default router;
