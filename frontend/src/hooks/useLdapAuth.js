import { useEffect, useState } from "react";
import System from "@/models/system";

/**
 * Checks if Active Directory (LDAP) authentication is enabled and how it is configured.
 * @returns {{loading: boolean, ldapConfig: {enabled: boolean, loginLabel: string | null, allowLocalLogin: boolean, roleSyncEnabled: boolean, multiUserMode: boolean}}}
 */
export default function useLdapAuth() {
  const [loading, setLoading] = useState(true);
  const [ldapConfig, setLdapConfig] = useState({
    enabled: false,
    loginLabel: null,
    allowLocalLogin: false,
    roleSyncEnabled: false,
    multiUserMode: false,
  });

  useEffect(() => {
    async function checkLdapConfig() {
      try {
        const settings = await System.keys();
        setLdapConfig({
          enabled: !!settings?.LdapEnabled,
          loginLabel: settings?.LdapLoginLabel || null,
          allowLocalLogin: !!settings?.LdapAllowLocalLogin,
          roleSyncEnabled: !!settings?.LdapRoleSyncEnabled,
          multiUserMode: !!settings?.MultiUserMode,
        });
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    checkLdapConfig();
  }, []);

  return { loading, ldapConfig };
}
