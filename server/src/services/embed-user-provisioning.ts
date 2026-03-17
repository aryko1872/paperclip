// server/src/services/embed-user-provisioning.ts
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { authUsers, companies, companyMemberships, instanceUserRoles } from "@paperclipai/db";

export interface EmbedUser {
  id: string;
  email: string;
  name: string;
  isInstanceAdmin: boolean;
  companyIds: string[];
}

/**
 * Find or create a user for embed auth.
 *
 * - Looks up user by email.
 * - If not found, creates user with id `embed:<buckguruUserId>`.
 * - If role is "owner", grants instance_admin.
 * - Adds user to all active companies in the instance.
 *
 * NOTE: Single-tenant assumption — each BuckGuru RIA
 * gets its own Paperclip instance, so adding the user
 * to all companies is correct. If multi-tenant
 * Paperclip instances are ever needed, this must be
 * scoped by a firm/tenant identifier.
 */
export async function provisionEmbedUser(
  db: Db,
  opts: {
    buckguruUserId: string;
    email: string;
    role: string;
  },
): Promise<EmbedUser> {
  const { buckguruUserId, email, role } = opts;
  const isOwner = role === "owner";

  // Find existing user by email
  let user = await db
    .select()
    .from(authUsers)
    .where(eq(authUsers.email, email))
    .then((rows) => rows[0] ?? null);

  const now = new Date();

  if (!user) {
    const userId = `embed:${buckguruUserId}`;
    const name = email.split("@")[0] ?? "Embed User";
    await db.insert(authUsers).values({
      id: userId,
      name,
      email,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });
    user = {
      id: userId,
      name,
      email,
      emailVerified: true,
      image: null,
      createdAt: now,
      updatedAt: now,
    };
  }

  // Ensure instance_admin role if owner
  if (isOwner) {
    const existing = await db
      .select()
      .from(instanceUserRoles)
      .where(
        and(
          eq(instanceUserRoles.userId, user.id),
          eq(instanceUserRoles.role, "instance_admin"),
        ),
      )
      .then((rows) => rows[0] ?? null);

    if (!existing) {
      await db.insert(instanceUserRoles).values({
        userId: user.id,
        role: "instance_admin",
        createdAt: now,
        updatedAt: now,
      });
    }
  }

  // Ensure membership in all active companies
  const allCompanies = await db
    .select({ id: companies.id })
    .from(companies)
    .where(eq(companies.status, "active"));

  const existingMemberships = await db
    .select({ companyId: companyMemberships.companyId })
    .from(companyMemberships)
    .where(
      and(
        eq(companyMemberships.principalType, "user"),
        eq(companyMemberships.principalId, user.id),
        eq(companyMemberships.status, "active"),
      ),
    );

  const existingCompanyIds = new Set(existingMemberships.map((m) => m.companyId));

  for (const company of allCompanies) {
    if (!existingCompanyIds.has(company.id)) {
      await db.insert(companyMemberships).values({
        companyId: company.id,
        principalType: "user",
        principalId: user.id,
        status: "active",
        createdAt: now,
        updatedAt: now,
      });
    }
  }

  const companyIds = allCompanies.map((c) => c.id);

  const isInstanceAdmin =
    isOwner ||
    (await db
      .select()
      .from(instanceUserRoles)
      .where(
        and(
          eq(instanceUserRoles.userId, user.id),
          eq(instanceUserRoles.role, "instance_admin"),
        ),
      )
      .then((rows) => rows.length > 0));

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    isInstanceAdmin,
    companyIds,
  };
}
