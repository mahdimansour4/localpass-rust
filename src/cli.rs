use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "localpass")]
pub struct Cli {
    #[arg(long, global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init,
    Add {
        site: String,
    },
    List,
    Search {
        query: String,
    },
    Stats,
    Get {
        site: String,
        #[arg(long)]
        show: bool,
    },
    Delete {
        site: String,
    },
    Update {
        site: String,
    },
    Rekey,
    Generate {
        #[arg(long, default_value_t = 16)]
        length: usize,
        #[arg(long)]
        symbols: bool,
        #[arg(long = "no-upper")]
        no_upper: bool,
        #[arg(long = "no-digits")]
        no_digits: bool,
        #[arg(long)]
        save: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vault_override_and_get_show() {
        let cli = Cli::parse_from([
            "localpass",
            "--vault",
            "./demo.vault",
            "get",
            "github",
            "--show",
        ]);

        assert_eq!(cli.vault, Some(PathBuf::from("./demo.vault")));
        match cli.command {
            Command::Get { site, show } => {
                assert_eq!(site, "github");
                assert!(show);
            }
            _ => panic!("expected get command"),
        }
    }

    #[test]
    fn generate_defaults_to_length_16() {
        let cli = Cli::parse_from(["localpass", "generate"]);

        match cli.command {
            Command::Generate {
                length,
                symbols,
                no_upper,
                no_digits,
                save,
            } => {
                assert_eq!(length, 16);
                assert!(!symbols);
                assert!(!no_upper);
                assert!(!no_digits);
                assert_eq!(save, None);
            }
            _ => panic!("expected generate command"),
        }
    }

    #[test]
    fn parses_generate_save_site() {
        let cli = Cli::parse_from([
            "localpass",
            "generate",
            "--length",
            "24",
            "--symbols",
            "--save",
            "github",
        ]);

        match cli.command {
            Command::Generate {
                length,
                symbols,
                save,
                ..
            } => {
                assert_eq!(length, 24);
                assert!(symbols);
                assert_eq!(save, Some("github".to_owned()));
            }
            _ => panic!("expected generate command"),
        }
    }

    #[test]
    fn parses_update_command() {
        let cli = Cli::parse_from(["localpass", "update", "github"]);

        match cli.command {
            Command::Update { site } => assert_eq!(site, "github"),
            _ => panic!("expected update command"),
        }
    }

    #[test]
    fn parses_rekey_command() {
        let cli = Cli::parse_from(["localpass", "rekey"]);

        match cli.command {
            Command::Rekey => {}
            _ => panic!("expected rekey command"),
        }
    }

    #[test]
    fn parses_search_command() {
        let cli = Cli::parse_from(["localpass", "search", "git"]);

        match cli.command {
            Command::Search { query } => assert_eq!(query, "git"),
            _ => panic!("expected search command"),
        }
    }

    #[test]
    fn parses_stats_command() {
        let cli = Cli::parse_from(["localpass", "stats"]);

        match cli.command {
            Command::Stats => {}
            _ => panic!("expected stats command"),
        }
    }
}
