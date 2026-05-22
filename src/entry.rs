use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: Uuid,
    pub site: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Entry {
    pub fn new(site: &str, username: &str, password: &str, notes: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            site: site.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            notes: notes.to_owned(),
            created_at: now,
            updated_at: now,
        }
    }
}
