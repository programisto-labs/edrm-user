import Permission from '../models/permission.model.js';
import { checkUserPermissions } from '../middlewares/auth.middleware.js';
import routerBase from 'endurance-core/lib/router.js';

const checkSuperAdmin = checkUserPermissions([], true); 
const router = routerBase({requireDb: true});

router.autoWire(Permission, 'Permission', checkSuperAdmin);

export default router;
