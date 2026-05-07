## Password Manager Cli in Rust.

this project has been done for around 1 - 2 weeks, i used populars crates such as Serde, Serde_json, Bcrypt, Clap.

This password manager allows you to be called everywhere in the terminal by typing ```password-manager [COMMAND]```. All your passwords will be encrypted and not seenable from the passwords.json file directly, to show them you'll have to type ```password-manager list```.

#### Example of the help message
```
$password-manager
A simple password manager.

Usage: password-manager <COMMAND>

Commands:
  add
  delete
  modify
  list
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Complementary informations
When trying any command at first, you'll be asking to create your master password, you **MUST** remember it because otherwise you wont be able to retrieve it, in case, if you want to try a lot of passwords if you lose it you can still create a random test project where you ```cargo add bcrypt```, make a vector and use the verify function to check if the hash of your master password in your ~/.config/password-manager/passwords.json is the same as your guess.
