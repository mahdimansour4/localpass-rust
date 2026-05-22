use localpass::commands::{
    add_entry_with_values, delete_entry_with_password, generate_and_save_entry_with_values,
    init_vault_with_password, list_entries_with_password, read_password_with_password,
    rekey_vault_with_passwords, search_entries_with_password, stats_with_password,
    update_entry_with_values,
};
use localpass::error::LocalPassError;
use localpass::generator::GeneratorOptions;
use tempfile::tempdir;

#[test]
fn init_add_list_get_delete_flow() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();

    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert_eq!(
        entries,
        vec![("github".to_owned(), "mahdi@example.com".to_owned())]
    );

    let password = read_password_with_password(&vault_path, "master password", "github").unwrap();
    assert_eq!(password, "secret-password");

    update_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "new@example.com",
        "new-secret",
        "updated account",
    )
    .unwrap();
    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert_eq!(
        entries,
        vec![("github".to_owned(), "new@example.com".to_owned())]
    );
    let password = read_password_with_password(&vault_path, "master password", "github").unwrap();
    assert_eq!(password, "new-secret");

    delete_entry_with_password(&vault_path, "master password", "github").unwrap();
    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert!(entries.is_empty());
}

#[test]
fn generate_and_save_stores_generated_password() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    generate_and_save_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "generated account",
        &GeneratorOptions {
            length: 24,
            symbols: true,
            no_upper: false,
            no_digits: false,
        },
    )
    .unwrap();

    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert_eq!(
        entries,
        vec![("github".to_owned(), "mahdi@example.com".to_owned())]
    );

    let password = read_password_with_password(&vault_path, "master password", "github").unwrap();
    assert_eq!(password.len(), 24);
}

#[test]
fn add_and_generate_save_reject_duplicate_sites() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();

    let add_result = add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "other@example.com",
        "other-password",
        "duplicate",
    );
    assert!(matches!(
        add_result,
        Err(LocalPassError::DuplicateEntry(site)) if site == "github"
    ));

    let save_result = generate_and_save_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "other@example.com",
        "generated duplicate",
        &GeneratorOptions {
            length: 24,
            symbols: true,
            no_upper: false,
            no_digits: false,
        },
    );
    assert!(matches!(
        save_result,
        Err(LocalPassError::DuplicateEntry(site)) if site == "github"
    ));

    let entries = list_entries_with_password(&vault_path, "master password").unwrap();
    assert_eq!(
        entries,
        vec![("github".to_owned(), "mahdi@example.com".to_owned())]
    );
}

#[test]
fn rekey_changes_master_password_without_losing_entries() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "old master").unwrap();
    add_entry_with_values(
        &vault_path,
        "old master",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();

    rekey_vault_with_passwords(&vault_path, "old master", "new master").unwrap();

    let old_result = read_password_with_password(&vault_path, "old master", "github");
    assert!(matches!(old_result, Err(LocalPassError::UnlockFailed)));

    let password = read_password_with_password(&vault_path, "new master", "github").unwrap();
    assert_eq!(password, "secret-password");
}

#[test]
fn search_returns_matching_site_and_username_without_passwords() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "email",
        "git.user@example.com",
        "another-secret",
        "work account",
    )
    .unwrap();

    let entries = search_entries_with_password(&vault_path, "master password", "git").unwrap();

    assert_eq!(
        entries,
        vec![
            ("github".to_owned(), "mahdi@example.com".to_owned()),
            ("email".to_owned(), "git.user@example.com".to_owned())
        ]
    );
}

#[test]
fn stats_returns_entry_count() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("test.vault");

    init_vault_with_password(&vault_path, "master password").unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "github",
        "mahdi@example.com",
        "secret-password",
        "main account",
    )
    .unwrap();
    add_entry_with_values(
        &vault_path,
        "master password",
        "gitlab",
        "mahdi@example.com",
        "another-secret",
        "work account",
    )
    .unwrap();

    let count = stats_with_password(&vault_path, "master password").unwrap();

    assert_eq!(count, 2);
}
