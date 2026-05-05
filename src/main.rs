use clap::{Parser, Subcommand};
use dialoguer::Password;
use password_manager::PasswordManager;
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
    Open,
    Close,
    Add {
        #[arg(short, long)]
        url: String,

        #[arg(short, long)]
        username: String,
    },
    Delete {
        #[arg(short, long)]
        url: String,
    },
    Modify {
        #[arg(short, long)]
        url: String,

        #[arg(short, long)]
        new_username: String,
    },
    List,
}

fn main() {
    let cli = Cli::parse();

    match PasswordManager::load() {
        Ok(mut existing_manager) => {
            // mut because open_manager takes a &mut self
            let input_master = Password::new()
                .with_prompt("Enter your master password : ")
                .interact()
                .unwrap();

            if let Err(e) = existing_manager.open_manager(input_master) {
                eprintln!("Denied acces ! : {}", e);
                process::exit(1);
            }

            existing_manager
        }
        Err(_) => {
            println!("Welcome on our password manager !");

            let new_master = Password::new()
                .with_prompt("Create a master password (you'll have to remember it !!)")
                .with_confirmation("Retype de password, authentication failed.", "error")
                .interact()
                .unwrap();

            let new_manager = PasswordManager::new(new_master);

            if let Err(e) = new_manager.save_file() {
                eprintln!("Error while saving the file on the disk : {}", e);
                process::exit(1);
            }

            new_manager
        }
    };
}
