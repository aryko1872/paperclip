// server/src/routes/embed-auth.ts
import { Router } from "express";
import type { Db } from "@paperclipai/db";
import { verifyBuckguruJwt, createEmbedToken } from "../embed-auth.js";
import { provisionEmbedUser } from "../services/embed-user-provisioning.js";
import { logger } from "../middleware/logger.js";

export function embedAuthRoutes(db: Db) {
  const router = Router();

  /**
   * POST /api/auth/embed
   *
   * Exchanges a BuckGuru JWT for a Paperclip embed token.
   * Body: { token: string }
   * Returns: { embedToken: string, user: { id, email, name } }
   */
  router.post("/", async (req, res) => {
    const { token } = req.body as { token?: string };
    if (!token || typeof token !== "string") {
      res.status(400).json({ error: "Missing token in request body" });
      return;
    }

    // Validate BuckGuru JWT
    const claims = verifyBuckguruJwt(token);
    if (!claims) {
      logger.warn("Embed auth: invalid or expired BuckGuru JWT");
      res.status(401).json({ error: "Invalid or expired token" });
      return;
    }

    // Provision user
    let user;
    try {
      user = await provisionEmbedUser(db, {
        buckguruUserId: claims.userId,
        email: claims.email,
        role: claims.role,
      });
    } catch (err) {
      logger.error({ err }, "Embed auth: failed to provision user");
      res.status(500).json({ error: "Failed to provision user" });
      return;
    }

    // Create embed token
    const embedToken = createEmbedToken(user.id, user.email, claims.role);
    if (!embedToken) {
      logger.error("Embed auth: failed to create embed token (missing secret)");
      res.status(500).json({ error: "Embed auth not configured" });
      return;
    }

    res.json({
      embedToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  });

  return router;
}
