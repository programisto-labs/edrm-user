import Role from '../models/role.model.js';
import { EnduranceRouter, EnduranceAuthMiddleware, type SecurityOptions, EnduranceRequest } from '@programisto/endurance';

class RoleRouter extends EnduranceRouter {
  constructor() {
    super(EnduranceAuthMiddleware.getInstance());
  }

  setupRoutes(): void {
    const securityOptions: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageRoles']
    };

    /**
     * @swagger
     * /roles/{roleId}/assign-permissions:
     *   post:
     *     summary: Assigner des permissions à un rôle
     *     description: Remplace la liste des permissions d'un rôle existant. Nécessite la permission manageRoles.
     *     tags: [Rôles]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: roleId
     *         required: true
     *         schema:
     *           type: string
     *         description: Identifiant du rôle
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               permissions:
     *                 type: array
     *                 items:
     *                   type: string
     *     responses:
     *       200:
     *         description: Permissions mises à jour
     *       401:
     *         description: Non authentifié
     *       403:
     *         description: Permissions insuffisantes
     *       404:
     *         description: Rôle introuvable
     *       500:
     *         description: Erreur serveur
     */
    this.post('/:roleId/assign-permissions', securityOptions, async (req: EnduranceRequest, res: any) => {
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
  }
}

const router = new RoleRouter();

export default router;
