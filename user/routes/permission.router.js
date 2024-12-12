import Permission from '../models/permission.model.js';
import { checkUserPermissions } from '../middlewares/auth.middleware.js';
import router from 'endurance-core/lib/router.js';

const checkSuperAdmin = checkUserPermissions([], true); 

router.autoWire(Permission, 'Permission');

export default router;
