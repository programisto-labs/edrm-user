import Permission from '../models/permission.model';
import { checkUserPermissions } from '../middlewares/auth.middleware';
import router from 'endurance-core/lib/router';

const checkSuperAdmin = checkUserPermissions([], true); 

router.autoWire(Permission, 'Permission');

export default router;
