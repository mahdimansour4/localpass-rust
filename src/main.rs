use clap::Parser;
use localpass::cli::{Cli, Command};
use localpass::commands::{
    add_entry_with_values, default_vault_path, delete_entry_with_password,
    generate_and_save_entry_with_values, init_vault_with_password, list_entries_with_password,
    read_password_with_password, rekey_vault_with_passwords, search_entries_with_password,
    stats_with_password, update_entry_with_values,
};
use localpass::error::Result;
use localpass::generator::{GeneratorOptions, generate_password};
use std::io::{self, Write};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(default_vault_path);

    match cli.command {
        Command::Init => {
            let password = prompt_password_confirmed()?;
            init_vault_with_password(&vault_path, &password)?;
            println!("vault initialized at {}", vault_path.display());
        }
        Command::Add { site } => {
            let master = rpassword::prompt_password("Master password: ")?;
            let username = prompt("Username: ")?;
            let password = rpassword::prompt_password("Password: ")?;
            let notes = prompt("Notes: ")?;
            add_entry_with_values(&vault_path, &master, &site, &username, &password, &notes)?;
            println!("added {site}");
        }
        Command::List => {
            let master = rpassword::prompt_password("Master password: ")?;
            for (site, username) in list_entries_with_password(&vault_path, &master)? {
                println!("{site}\t{username}");
            }
        }
        Command::Search { query } => {
            let master = rpassword::prompt_password("Master password: ")?;
            for (site, username) in search_entries_with_password(&vault_path, &master, &query)? {
                println!("{site}\t{username}");
            }
        }
        Command::Stats => {
            let master = rpassword::prompt_password("Master password: ")?;
            let count = stats_with_password(&vault_path, &master)?;
            println!("entries: {count}");
            println!("vault path: {}", vault_path.display());
        }
        Command::Get { site, show } => {
            let master = rpassword::prompt_password("Master password: ")?;
            let password = read_password_with_password(&vault_path, &master, &site)?;
            if show {
                println!("{password}");
            } else {
                localpass::clipboard::copy_and_clear_after(password, 30)?;
                println!("password copied to clipboard");
            }
        }
        Command::Delete { site } => {
            let master = rpassword::prompt_password("Master password: ")?;
            delete_entry_with_password(&vault_path, &master, &site)?;
            println!("deleted {site}");
        }
        Command::Update { site } => {
            let master = rpassword::prompt_password("Master password: ")?;
            let username = prompt("New username: ")?;
            let password = rpassword::prompt_password("New password: ")?;
            let notes = prompt("New notes: ")?;
            update_entry_with_values(&vault_path, &master, &site, &username, &password, &notes)?;
            println!("updated {site}");
        }
        Command::Rekey => {
            let current = rpassword::prompt_password("Current master password: ")?;
            let new_password = prompt_new_master_password_confirmed()?;
            rekey_vault_with_passwords(&vault_path, &current, &new_password)?;
            println!("master password changed");
        }
        Command::Generate {
            length,
            symbols,
            no_upper,
            no_digits,
            save,
        } => {
            let options = GeneratorOptions {
                length,
                symbols,
                no_upper,
                no_digits,
            };

            if let Some(site) = save {
                let master = rpassword::prompt_password("Master password: ")?;
                let username = prompt("Username: ")?;
                let notes = prompt("Notes: ")?;
                generate_and_save_entry_with_values(
                    &vault_path,
                    &master,
                    &site,
                    &username,
                    &notes,
                    &options,
                )?;
                println!("generated and saved password for {site}");
            } else {
                let password = generate_password(&options)?;
                println!("{password}");
            }
        }
    }

    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end().to_owned())
}

fn prompt_password_confirmed() -> Result<String> {
    let password = rpassword::prompt_password("Master password: ")?;
    let confirm = rpassword::prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err(localpass::error::LocalPassError::Message(
            "master passwords do not match".to_owned(),
        ));
    }
    Ok(password)
}

fn prompt_new_master_password_confirmed() -> Result<String> {
    let password = rpassword::prompt_password("New master password: ")?;
    let confirm = rpassword::prompt_password("Confirm new master password: ")?;
    if password != confirm {
        return Err(localpass::error::LocalPassError::Message(
            "new master passwords do not match".to_owned(),
        ));
    }
    Ok(password)
}
