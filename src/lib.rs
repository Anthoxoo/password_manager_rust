use bcrypt::{DEFAULT_COST, hash, verify};
use magic_crypt::{MagicCrypt256, MagicCryptTrait, new_magic_crypt};

use std::collections::HashMap;

pub struct PasswordManager {
    state: State,
    master_password: String,
    password: HashMap<String, Password>,
    encryption_key: Option<String>,
}

#[derive(Debug)]
pub struct Password {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq)]
enum State {
    Locked,
    Unlocked,
}

impl PasswordManager {
    pub fn new(master_password: String) -> Self {
        PasswordManager {
            state: State::Locked,
            master_password: hash(master_password, DEFAULT_COST)
                .expect("Error hashing the master password."),
            password: HashMap::new(),
            encryption_key: None,
        }
    }

    pub fn open_manager(&mut self, master_pass: String) -> Result<(), &'static str> {
        if verify(&master_pass, &self.master_password)
            .expect("Error hashing password to verify it.")
        {
            self.state = State::Unlocked;
            self.encryption_key = Some(master_pass);
            Ok(())
        } else {
            Err("Wrong password.")
        }
    }

    pub fn close_manager(&mut self) {
        self.state = State::Locked;
        self.encryption_key = None;
    }

    pub fn add_password(
        &mut self,
        url: String,
        username: String,
        password: String,
    ) -> Result<(), &'static str> {
        if self.state == State::Locked {
            Err("The manager is locked.")
        } else {
            let key = self.encryption_key.as_ref().unwrap();
            let mc = new_magic_crypt!(key, 256);

            let new_password = Password {
                username: username,
                password: encrypt_password(password, mc),
            };

            self.password.insert(url, new_password);
            Ok(())
        }
    }

    pub fn modify_password(
        &mut self,
        url: String,
        username: String,
        new_password: String,
    ) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        if let Some(entry) = self.password.get_mut(&url) {
            let key = self.encryption_key.as_ref().unwrap();
            let mc = new_magic_crypt!(key, 256);

            entry.username = username;
            entry.password = encrypt_password(new_password, mc);

            Ok(())
        } else {
            Err("Url not found.")
        }
    }

    pub fn delete_password(&mut self, url: String) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        if self.password.remove(&url).is_some() {
            Ok(())
        } else {
            Err("Url not found.")
        }
    }

    pub fn list_passwords(&self) -> Result<(), &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        let key = self.encryption_key.as_ref().unwrap();
        let mc = new_magic_crypt!(key, 256);

        for (url, entry) in self.password.iter() {
            let decrypted_password = decrypt_password(entry.password.clone(), mc.clone());

            println!(
                "URL : {} | username : {} | password : {}",
                url, entry.username, decrypted_password
            );
        }

        Ok(())
    }
}

fn encrypt_password(password: String, key: MagicCrypt256) -> String {
    key.encrypt_str_to_base64(password)
}

fn decrypt_password(password: String, key: MagicCrypt256) -> String {
    key.decrypt_base64_to_string(password)
        .expect("Error decrypting the password.")
}
