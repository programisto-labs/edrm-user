import Permission from '../models/permission.model.js';
import { EnduranceRouter, EnduranceAuthMiddleware, type SecurityOptions } from 'endurance-core';


class PermissionRouter extends EnduranceRouter {
    constructor() {
        super(EnduranceAuthMiddleware.getInstance());
    }

    setupRoutes(): void {
        const securityOptions: SecurityOptions = {
            requireAuth: true,
            permissions: ['managePermissions']
        };

        // Setup CRUD routes with security
        this.get('/', securityOptions, async (req: any, res: any) => {
            const permissions = await Permission.find();
            res.json(permissions);
        });

        this.post('/', securityOptions, async (req: any, res: any) => {
            const permission = new Permission(req.body);
            await permission.save();
            res.json(permission);
        });
    }
}

const router = new PermissionRouter();
router.setupRoutes();

export default router;
