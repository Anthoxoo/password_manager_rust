use clap::{Parser, Subcommand};
use password_manager::*;
use std::process;

#[derive(Parser)]
#[command(
    name = "pass-manager",
    version = "1.0",
    author = "https://github.com/Anthoxoo",
    about = "A simple password manager."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Exit,
    Add {
        #[arg(long)]
        url: String,

        #[arg(long)]
        username: String,
    },
    Delete {
        #[arg(long)]
        url: String,
    },
    Modify {
        #[arg(long)]
        url: String,

        #[arg(long)]
        new_username: String,
    },
    List,
}

fn main() {
    let cli = Cli::parse();

    let mut manager = launch_program();
    find_create_folder("~/.config/password-manager")
        .expect("Error creating or finding the folder.");

    match cli.command {
        Commands::Exit => manager.close_manager(),
        Commands::Add { url, username } => {
            let input_password = dialoguer::Password::new()
                .with_prompt("Enter your master password ")
                .interact()
                .unwrap();

            if let Err(e) = manager.add_password(url, username, input_password) {
                eprintln!("An error occurred : {}", e);
                process::exit(2);
            }
        }
        Commands::Delete { url } => {
            if let Err(e) = manager.delete_password(url) {
                eprintln!("An error occurred : {}", e);
                process::exit(3);
            }
        }
        Commands::Modify { url, new_username } => {
            let input_password = dialoguer::Password::new()
                .with_prompt("Enter your master password ")
                .interact()
                .unwrap();

            if let Err(e) = manager.modify_password(url, new_username, input_password) {
                eprintln!("An error occurred : {}", e);
                process::exit(3);
            }
        }
        Commands::List => {
            if let Err(e) = manager.list_passwords() {
                eprintln!("An error occurred : {}", e);
                process::exit(4);
            }
        }
    }
}
