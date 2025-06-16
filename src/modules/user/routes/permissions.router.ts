import Permission from '../models/permission.model.js';
import { EnduranceRouter, EnduranceAuthMiddleware, type SecurityOptions, EnduranceRequest } from '@programisto/endurance-core';

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
        this.get('/', securityOptions, async (req: EnduranceRequest, res: any) => {
            const permissions = await Permission.find();
            res.json(permissions);
        });

        this.post('/', securityOptions, async (req: EnduranceRequest, res: any) => {
            const permission = new Permission(req.body);
            await permission.save();
            res.json(permission);
        });
    }
}

const router = new PermissionRouter();

export default router;
