use bcrypt::{DEFAULT_COST, hash, verify};

use std::collections::HashMap;

pub struct PasswordManager {
    state: State,
    master_password: String,
    password: HashMap<String, Password>,
}

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
            master_password: encrypt_password(master_password),
            password: HashMap::new(),
        }
    }

    pub fn open_manager(&mut self, master_pass: String) -> Result<(), &'static str> {
        if verify(master_pass, &self.master_password).expect("Error hashing password.") {
            self.state = State::Unlocked;
            Ok(())
        } else {
            Err("Wrong password.")
        }
    }

    pub fn close_manager(&mut self) {
        self.state = State::Locked
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
            let new_password = Password {
                username: username,
                password: encrypt_password(password),
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
            entry.username = username;
            entry.password = encrypt_password(new_password);

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

    pub fn list_passwords(&self) -> Result<Vec<&Password>, &'static str> {
        if self.state == State::Locked {
            return Err("The manager is locked.");
        }
        Ok(self.password.values().collect())
    }
}

fn encrypt_password(password: String) -> String {
    hash(password, DEFAULT_COST).expect("Error hashing password.")
}
