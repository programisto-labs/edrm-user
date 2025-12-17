import Permission from '../models/permission.model.js';
import { EnduranceRouter, EnduranceAuthMiddleware, type SecurityOptions, EnduranceRequest } from '@programisto/endurance';

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
        /**
         * @swagger
         * /permissions:
         *   get:
         *     summary: Lister les permissions
         *     description: Retourne la liste complète des permissions disponibles. Permission managePermissions requise.
         *     tags: [Permissions]
         *     security:
         *       - bearerAuth: []
         *     responses:
         *       200:
         *         description: Liste des permissions
         *       401:
         *         description: Non authentifié
         *       403:
         *         description: Permissions insuffisantes
         *       500:
         *         description: Erreur serveur
         */
        this.get('/', securityOptions, async (req: EnduranceRequest, res: any) => {
            const permissions = await Permission.find();
            res.json(permissions);
        });

        /**
         * @swagger
         * /permissions:
         *   post:
         *     summary: Créer une permission
         *     description: Crée une nouvelle permission. Permission managePermissions requise.
         *     tags: [Permissions]
         *     security:
         *       - bearerAuth: []
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             description: Données de la permission
         *     responses:
         *       200:
         *         description: Permission créée
         *       401:
         *         description: Non authentifié
         *       403:
         *         description: Permissions insuffisantes
         *       500:
         *         description: Erreur serveur
         */
        this.post('/', securityOptions, async (req: EnduranceRequest, res: any) => {
            const permission = new Permission(req.body);
            await permission.save();
            res.json(permission);
        });
    }
}

const router = new PermissionRouter();

export default router;
