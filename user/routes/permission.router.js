const Permission = require('../models/permission.model');
const { checkUserPermissions } = require('../middlewares/auth.middleware');
const router = require('endurance-core/lib/router')();

const checkSuperAdmin = checkUserPermissions([], true); 

router.autoWire(Permission, 'Permission');

module.exports = router;
