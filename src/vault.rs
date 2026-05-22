use crate::entry::Entry;
use crate::error::{LocalPassError, Result};
use chrono::Utc;

#[derive(Debug, Clone, Default)]
pub struct Vault {
    entries: Vec<Entry>,
}

impl Vault {
    pub fn add(&mut self, site: &str, username: &str, password: &str, notes: &str) -> Result<()> {
        if self.entries.iter().any(|entry| entry.site == site) {
            return Err(LocalPassError::DuplicateEntry(site.to_owned()));
        }

        self.entries
            .push(Entry::new(site, username, password, notes));
        Ok(())
    }

    pub fn find(&self, site: &str) -> Result<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.site == site)
            .ok_or_else(|| LocalPassError::EntryNotFound(site.to_owned()))
    }

    pub fn delete(&mut self, site: &str) -> Result<()> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.site != site);
        if self.entries.len() == before {
            return Err(LocalPassError::EntryNotFound(site.to_owned()));
        }
        Ok(())
    }

    pub fn update(
        &mut self,
        site: &str,
        username: &str,
        password: &str,
        notes: &str,
    ) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.site == site)
            .ok_or_else(|| LocalPassError::EntryNotFound(site.to_owned()))?;

        entry.username = username.to_owned();
        entry.password = password.to_owned();
        entry.notes = notes.to_owned();
        entry.updated_at = Utc::now();
        Ok(())
    }

    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query = query.to_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                entry.site.to_lowercase().contains(&query)
                    || entry.username.to_lowercase().contains(&query)
            })
            .collect()
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.entries)?)
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        let entries = serde_json::from_slice(bytes)?;
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find_entry_by_site() {
        let mut vault = Vault::default();
        vault
            .add("github", "mahdi@example.com", "secret", "")
            .unwrap();

        let entry = vault.find("github").unwrap();

        assert_eq!(entry.site, "github");
        assert_eq!(entry.username, "mahdi@example.com");
        assert_eq!(entry.password, "secret");
    }

    #[test]
    fn delete_removes_entry() {
        let mut vault = Vault::default();
        vault
            .add("github", "mahdi@example.com", "secret", "")
            .unwrap();

        vault.delete("github").unwrap();

        assert!(matches!(
            vault.find("github"),
            Err(LocalPassError::EntryNotFound(site)) if site == "github"
        ));
    }

    #[test]
    fn serializes_and_deserializes_json_payload() {
        let mut vault = Vault::default();
        vault
            .add("github", "mahdi@example.com", "secret", "main account")
            .unwrap();

        let json = vault.to_json_bytes().unwrap();
        let parsed = Vault::from_json_bytes(&json).unwrap();

        assert_eq!(parsed.find("github").unwrap().notes, "main account");
    }

    #[test]
    fn update_replaces_entry_fields() {
        let mut vault = Vault::default();
        vault
            .add("github", "old@example.com", "old-secret", "old notes")
            .unwrap();

        vault
            .update("github", "new@example.com", "new-secret", "new notes")
            .unwrap();

        let entry = vault.find("github").unwrap();
        assert_eq!(entry.username, "new@example.com");
        assert_eq!(entry.password, "new-secret");
        assert_eq!(entry.notes, "new notes");
    }

    #[test]
    fn add_rejects_duplicate_site() {
        let mut vault = Vault::default();
        vault
            .add("github", "first@example.com", "first-secret", "")
            .unwrap();

        let result = vault.add("github", "second@example.com", "second-secret", "");

        assert!(matches!(
            result,
            Err(LocalPassError::DuplicateEntry(site)) if site == "github"
        ));
        assert_eq!(vault.list().len(), 1);
    }

    #[test]
    fn search_matches_site_and_username_case_insensitively() {
        let mut vault = Vault::default();
        vault
            .add("github", "mahdi@example.com", "secret", "")
            .unwrap();
        vault
            .add("email", "git.user@example.com", "secret", "")
            .unwrap();
        vault
            .add("bank", "mahdi@example.com", "secret", "")
            .unwrap();

        let matches = vault.search("GIT");
        let sites = matches
            .iter()
            .map(|entry| entry.site.as_str())
            .collect::<Vec<_>>();

        assert_eq!(sites, vec!["github", "email"]);
    }

    #[test]
    fn entry_count_returns_number_of_entries() {
        let mut vault = Vault::default();
        vault
            .add("github", "mahdi@example.com", "secret", "")
            .unwrap();
        vault
            .add("gitlab", "mahdi@example.com", "secret", "")
            .unwrap();

        assert_eq!(vault.entry_count(), 2);
    }
}
