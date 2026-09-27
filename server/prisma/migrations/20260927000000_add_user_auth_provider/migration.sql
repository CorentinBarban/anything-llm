-- AlterTable
ALTER TABLE "users" ADD COLUMN "auth_provider" TEXT NOT NULL DEFAULT 'local';
ALTER TABLE "users" ADD COLUMN "external_id" TEXT;
ALTER TABLE "users" ADD COLUMN "last_ldap_sync" DATETIME;

-- CreateIndex
CREATE UNIQUE INDEX "users_external_id_key" ON "users"("external_id");
