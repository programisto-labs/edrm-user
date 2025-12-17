import { EnduranceRouter, EnduranceRequest, Response, NextFunction, type SecurityOptions, enduranceEmitter as emitter, enduranceEventTypes as eventTypes, EnduranceAuthMiddleware, EnduranceDocumentType } from '@programisto/endurance';
// new endurance import
import User from '../models/user.model.js';
import Role from '../models/role.model.js';
import crypto from 'crypto';

// Fonction utilitaire pour le hachage MD5 simple
const simpleHash = (str: string, salt: string): string => {
  return crypto.createHash('md5').update(str + salt).digest('hex');
};

interface UserDocument extends EnduranceDocumentType<typeof User> {
  email: string;
  firstname: string;
  lastname: string;
  name: string;
  roles: any[];
  xpHistory: any[];
  completedQuests: any[];
  badges: any[];
  getLevel: () => number;
  getXPforNextLevel: () => number;
  createdAt: Date;
  updatedAt: Date;
}

class UserRouter extends EnduranceRouter {
  constructor() {
    super(EnduranceAuthMiddleware.getInstance());
  }

  setupRoutes(): void {
    const publicRoutes: SecurityOptions = {
      requireAuth: false
    };

    const authenticatedRoutes: SecurityOptions = {
      requireAuth: true
    };

    // Routes publiques
    /**
     * @swagger
     * /auth-methods:
     *   get:
     *     summary: Lister les méthodes d'authentification disponibles
     *     description: Renvoie les méthodes d'authentification activées côté serveur (local, Azure).
     *     tags: [Auth]
     *     responses:
     *       200:
     *         description: Méthodes disponibles retournées
     *       500:
     *         description: Erreur serveur
     */
    this.get('/auth-methods', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const authMethods = {
        local: process.env.LOGIN_LOCAL_ACTIVATED === 'true',
        azure: process.env.LOGIN_AZURE_ACTIVATED === 'true'
      };
      res.json({ authMethods });
    });

    /**
     * @swagger
     * /find:
     *   get:
     *     summary: Trouver un utilisateur par email
     *     description: Recherche un utilisateur via son email et retourne son document.
     *     tags: [Utilisateurs]
     *     parameters:
     *       - in: query
     *         name: email
     *         schema:
     *           type: string
     *         required: true
     *         description: Email de l'utilisateur recherché
     *     responses:
     *       200:
     *         description: Utilisateur trouvé
     *       404:
     *         description: Utilisateur introuvable
     *       500:
     *         description: Erreur serveur
     */
    this.get('/find', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const { email } = req.query;
      const user = await User.findOne({ email });
      res.json(user);
    });

    /**
     * @swagger
     * /register:
     *   post:
     *     summary: Créer un nouvel utilisateur
     *     description: Enregistre un utilisateur et déclenche l'événement userRegistered.
     *     tags: [Utilisateurs]
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             description: Corps du nouvel utilisateur
     *     responses:
     *       201:
     *         description: Utilisateur créé
     *       400:
     *         description: Requête invalide
     *       500:
     *         description: Erreur serveur
     */
    this.post('/register', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const user = new User(req.body);
      await user.save();
      emitter.emit(eventTypes.userRegistered, user);
      res.status(201).json({ message: 'User registered successfully' });
    });

    // Routes authentifiées
    /**
     * @swagger
     * /check-auth:
     *   get:
     *     summary: Vérifier l'authentification
     *     description: Vérifie que l'utilisateur est authentifié et renvoie ok si c'est le cas.
     *     tags: [Auth]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: Authentification valide
     *       401:
     *         description: Non authentifié
     */
    this.get('/check-auth', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {
      res.json({ result: 'ok' });
    });

    if (process.env.LOGIN_LOCAL_ACTIVATED === 'true') {
      /**
       * @swagger
       * /login/local:
       *   post:
       *     summary: Connexion locale
       *     description: Authentifie l'utilisateur via la stratégie locale et génère les tokens.
       *     tags: [Auth]
       *     requestBody:
       *       required: true
       *       content:
       *         application/json:
       *           schema:
       *             type: object
       *             description: Identifiants de connexion
       *     responses:
       *       200:
       *         description: Connexion réussie
       *       401:
       *         description: Identifiants invalides
       *       500:
       *         description: Erreur serveur
       */
      this.post('/login/local', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          if (!this.authMiddleware?.auth) {
            throw new Error('Auth middleware not initialized');
          }
          await this.authMiddleware.auth.authenticateLocalAndGenerateTokens(req, res, next);
          emitter.emit(eventTypes.userLoggedIn, req.user);
          res.json({ message: 'User logged in successfully' });
        } catch (error) {
          next(error);
        }
      });

      /**
       * @swagger
       * /request-password-reset:
       *   post:
       *     summary: Demander une réinitialisation de mot de passe
       *     description: Génère un token de réinitialisation pour l'utilisateur correspondant à l'email.
       *     tags: [Auth]
       *     requestBody:
       *       required: true
       *       content:
       *         application/json:
       *           schema:
       *             type: object
       *             properties:
       *               email:
       *                 type: string
       *     responses:
       *       200:
       *         description: Token généré
       *       404:
       *         description: Utilisateur introuvable
       *       500:
       *         description: Erreur serveur
       */
      this.post('/request-password-reset', publicRoutes, async (req: EnduranceRequest, res: Response) => {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
          res.status(404).json({ message: 'User not found' });
          return;
        }

        const resetToken = crypto.randomBytes(40).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpiration = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
        await user.save();

        emitter.emit('passwordResetRequested', { user, resetToken });

        res.json({ message: 'Password reset token generated', resetToken });
      });

      /**
       * @swagger
       * /reset-password:
       *   post:
       *     summary: Réinitialiser le mot de passe
       *     description: Applique un nouveau mot de passe à partir d'un token de réinitialisation valide.
       *     tags: [Auth]
       *     requestBody:
       *       required: true
       *       content:
       *         application/json:
       *           schema:
       *             type: object
       *             properties:
       *               resetToken:
       *                 type: string
       *               newPassword:
       *                 type: string
       *     responses:
       *       200:
       *         description: Mot de passe réinitialisé
       *       400:
       *         description: Token invalide ou expiré
       *       500:
       *         description: Erreur serveur
       */
      this.post('/reset-password', publicRoutes, async (req: EnduranceRequest, res: Response) => {
        const { resetToken, newPassword } = req.body;
        const user = await User.findOne({ resetToken, resetTokenExpiration: { $gt: Date.now() } });

        if (!user) {
          res.status(400).json({ message: 'Invalid or expired reset token' });
          return;
        }

        user.password = newPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        emitter.emit('passwordReset', user);

        res.json({ message: 'Password has been reset successfully' });
      });
    }

    if (process.env.LOGIN_AZURE_ACTIVATED === 'true') {
      this.setupAzureRoutes();
    }

    // Routes protégées avec permissions
    const adminRoutes: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageUsers']
    };

    /**
     * @swagger
     * /profile:
     *   get:
     *     summary: Récupérer le profil utilisateur
     *     description: Retourne les informations de profil de l'utilisateur authentifié, rôles et permissions hachées.
     *     tags: [Profil]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: Profil retourné
     *       401:
     *         description: Non authentifié
     *       404:
     *         description: Utilisateur introuvable
     *       500:
     *         description: Erreur serveur
     */
    this.get('/profile', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {
      if (!req.user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }

      try {
        const user = await User.findById(req.user._id)
          .select('-password -refreshToken')
          .exec() as unknown as UserDocument;

        if (!user) {
          res.status(404).json({ message: 'User not found' });
          return;
        }

        // Utilisation des fonctions utilitaires pour récupérer les données complètes
        const rolesWithDetails = await (User as any).getRolesWithDetails(user._id.toString());
        const userPermissions = await (User as any).getUserPermissions(user._id.toString());
        // Hash des permissions
        const hashedPermissions = [];
        for (const permission of userPermissions) {
          if (permission && permission.name) {
            hashedPermissions.push(simpleHash(permission.name, user.firstname));
          }
        }

        res.json({
          id: user._id,
          email: user.email,
          firstname: user.firstname,
          lastname: user.lastname,
          name: user.name,
          roles: rolesWithDetails.map((role: any) => simpleHash(role.name, user.firstname)),
          permissions: hashedPermissions,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt
        });
      } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Error fetching user profile' });
      }
    });

    /**
     * @swagger
     * /profile:
     *   patch:
     *     summary: Mettre à jour le profil utilisateur
     *     description: Met à jour les champs autorisés du profil de l'utilisateur connecté.
     *     tags: [Profil]
     *     security:
     *       - bearerAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               name:
     *                 type: string
     *               email:
     *                 type: string
     *               password:
     *                 type: string
     *     responses:
     *       200:
     *         description: Profil mis à jour
     *       400:
     *         description: Champs invalides
     *       401:
     *         description: Non authentifié
     *       500:
     *         description: Erreur serveur
     */
    this.patch('/profile', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {
      if (!req.user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }

      const allowedUpdates = ['name', 'email', 'password'];
      const updates = Object.keys(req.body);

      const isValidOperation = updates.every(update => allowedUpdates.includes(update));

      if (!isValidOperation) {
        res.status(400).json({ message: 'Invalid updates!' });
        return;
      }

      updates.forEach(update => {
        req.user[update] = req.body[update];
      });

      if (req.body.password) {
        req.user.password = req.body.password;
      }

      await req.user.save();
      emitter.emit(eventTypes.userProfileUpdated, req.user);
      res.json(req.user);
    });

    /**
     * @swagger
     * /profile:
     *   delete:
     *     summary: Supprimer un utilisateur (admin)
     *     description: Supprime l'utilisateur authentifié, nécessite la permission manageUsers.
     *     tags: [Profil]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: Utilisateur supprimé
     *       401:
     *         description: Non authentifié
     *       403:
     *         description: Permissions insuffisantes
     *       500:
     *         description: Erreur serveur
     */
    this.delete('/profile', adminRoutes, async (req: EnduranceRequest, res: Response) => {
      if (!req.user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }
      await req.user.remove();
      emitter.emit('userDeleted', req.user);
      res.json({ message: 'User deleted successfully' });
    });

    /**
     * @swagger
     * /assign-role:
     *   post:
     *     summary: Assigner un rôle à un utilisateur
     *     description: Ajoute un rôle existant à un utilisateur. Permission manageUsers requise.
     *     tags: [Rôles]
     *     security:
     *       - bearerAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               userId:
     *                 type: string
     *               roleId:
     *                 type: string
     *     responses:
     *       200:
     *         description: Rôle assigné
     *       400:
     *         description: Données manquantes
     *       404:
     *         description: Utilisateur ou rôle introuvable
     *       500:
     *         description: Erreur serveur
     */
    this.post('/assign-role', adminRoutes, async (req: EnduranceRequest, res: Response) => {
      const { userId, roleId } = req.body;

      if (!userId || !roleId) {
        res.status(400).json({ message: 'User ID and Role ID are required' });
        return;
      }

      const user = await User.findById(userId);
      const role = await Role.findById(roleId);

      if (!user || !role) {
        res.status(404).json({ message: 'User or Role not found' });
        return;
      }

      if (!user.roles) {
        user.roles = [];
      }
      user.roles.push(roleId);
      await user.save();
      emitter.emit(eventTypes.roleAssigned, { user, role });
      res.json({ message: 'Role assigned successfully', user });
    });

    /**
     * @swagger
     * /refresh-token:
     *   post:
     *     summary: Rafraîchir le token d'accès
     *     description: Utilise le refresh token pour générer un nouveau JWT.
     *     tags: [Auth]
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             description: Refresh token fourni
     *     responses:
     *       200:
     *         description: Token rafraîchi
     *       401:
     *         description: Refresh token invalide
     *       500:
     *         description: Erreur serveur
     */
    this.post('/refresh-token', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.refreshJwt(req, res, next);
      } catch (error) {
        next(error);
      }
    });

    /**
     * @swagger
     * /revoke-token:
     *   post:
     *     summary: Révoquer le refresh token
     *     description: Invalide le refresh token de l'utilisateur authentifié.
     *     tags: [Auth]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: Token révoqué
     *       401:
     *         description: Non authentifié
     *       500:
     *         description: Erreur serveur
     */
    this.post('/revoke-token', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.revokeRefreshToken(req, res, next);
      } catch (error) {
        next(error);
      }
    });
  }

  private setupAzureRoutes(): void {
    if (!process.env.AZURE_CLIENT_ID ||
      !process.env.AZURE_CLIENT_SECRET ||
      !process.env.AZURE_RESOURCE ||
      !process.env.AZURE_TENANT ||
      !process.env.AZURE_CALLBACK_URL) {
      console.error('Error: Azure environment variables are not set. Azure login routes will not be loaded.');
      return;
    }

    const publicRoutes: SecurityOptions = {
      requireAuth: false
    };

    /**
     * @swagger
     * /login/azure:
     *   get:
     *     summary: Connexion Azure
     *     description: Authentifie l'utilisateur via Azure AD et génère les tokens.
     *     tags: [Auth Azure]
     *     responses:
     *       200:
     *         description: Connexion Azure réussie
     *       302:
     *         description: Redirection vers l'URL de callback Azure
     *       500:
     *         description: Erreur serveur
     */
    this.get('/login/azure', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.authenticateAzureAndGenerateTokens(req, res, next);
        emitter.emit(eventTypes.userLoggedIn, req.user);
        const loginCallbackUrl = process.env.AZURE_CALLBACK_URL;
        if (loginCallbackUrl) {
          return res.redirect(loginCallbackUrl);
        }
        res.json({ message: 'User logged in successfully' });
      } catch (error) {
        next(error);
      }
    });

    /**
     * @swagger
     * /login/azure/exchange:
     *   post:
     *     summary: Échanger le code Azure contre des tokens
     *     description: Génère les tokens à partir du code d'autorisation Azure reçu.
     *     tags: [Auth Azure]
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             description: Charge utile de l'échange de code
     *     responses:
     *       200:
     *         description: Tokens générés
     *       400:
     *         description: Code invalide
     *       500:
     *         description: Erreur serveur
     */
    this.post('/login/azure/exchange', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.generateAzureTokens(req, res, next);
      } catch (error) {
        if (!res.headersSent) {
          next(error);
        } else {
          console.error('Error after headers sent:', error);
        }
      }
    });
  }
}

const userRouter = new UserRouter();
export default userRouter;
