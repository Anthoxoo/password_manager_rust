use std::collections::HashMap;

pub struct PasswordManager {
    state: State,
    master_password: String,
    password: HashMap<String, Password>,
}

struct Password {
    username: String,
    password: String,
}

enum State {
    Locked,
    Unlocked,
}

impl PasswordManager {
    pub fn new(master_password: String) -> Self {
        PasswordManager {
            state: State::Locked,
            master_password,
            password: HashMap::new(),
        }
    }

    pub fn open_manager(&mut self, master_pass: String) {
        todo!()
    }

    pub fn close_manager(&mut self) {
        todo!()
    }

    pub fn add_password(&mut self, url: String, username: String, password: String) {
        todo!()
    }

    pub fn modify_password(&mut self, url: String, username: String) {
        todo!()
    }

    pub fn delete_password(&mut self, url: String, username: String) {
        todo!()
    }

    pub fn list_passwords(&self) -> Result<Vec<&Password>, &'static str> {
        todo!()
    }

    fn encrypt_password(password: String) -> String {
        todo!()
    }
}
