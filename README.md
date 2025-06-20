<div align="center">
    <img alt="databoxer" src="media/icons/icon_3d.png">
    <h1>Databoxer</h1>
</div>

> A data encryption program, which focuses on speed, safety and user-friendliness

![windows](https://img.shields.io/github/actions/workflow/status/duckysmacky/databoxer/windows.yml?label=Windows)
![linux](https://img.shields.io/github/actions/workflow/status/duckysmacky/databoxer/macos.yml?label=macOS)
![macos](https://img.shields.io/github/actions/workflow/status/duckysmacky/databoxer/linux.yml?label=Linux)
![version](https://img.shields.io/crates/v/databoxer)
![donwloads](https://img.shields.io/crates/d/databoxer)

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Development](#-development)

## 💡 About

Databoxer aims to be a lightweight cross-platform solution for file encryption, while also being efficient and safe. **It is not a drop-in replacement** for already long-existing
encryption tools, such as _Bitlocker_, but instead more of an alternative.

It is aimed at both average and more advanced users. Possible use cases can range from simple local data protection
and access restriction to wireless data transfer and removable drive safety insurance. It's up to the user to decide
how to use the program, which is one of the Databoxer's key principles: to **be flexible and efficient**.

Databoxer operates based on the **ChaCha20** encryption algorithm in combination with the **Poly1305** universal hash
function to perform its encryption operations. It proved to be much more safe and fast than the most popular **AES**
algorithm used in many other similar programs. The files are encrypted using a randomly generated 32-byte _encryption
key_ and per-file 12-byte _nonce_, which ensures ciphertext's uniqueness across different files.

## 📂 Installation

Databoxer is cross-platform and is supported on all major platforms (Windows, Linux and macOS)

> [!NOTE]
> The current version provides all the main features of the project fully implemented, but with time many of the will be
> expanded upon and many new ones will be added. Since the project is still in development, many already existing features
> might and will change. Consider all version under `1.0.0` to be prone to many interface, functionality and API changes.

### With Cargo

_This is the recommended way to install Databoxer_

```shell
cargo install databoxer
```

### From releases

1. Go to [Releases](https://github.com/duckysmacky/databoxer/releases)
2. Select the version you want to download
3. Download the binary for your system

### From source

_From latest commit at branch `master`_

```shell
cargo install --git https://github.com/duckysmacky/copper.git
```

## ⭐ Features

### 👤 Profile system

One of the key features of Databoxer is its **profile management system**. The user of the application can create
different profiles in order to store keys and manage file. Each profile has a unique encryption key which is later
used to encrypt/decrypt files and can be protected by user-defined password.

Later down the lineDataboxer is planned to have support for native
toolchains, such as _GnuPG_ and _Kleopatra_ for UNIX-like systems and _CryptoAPI (CNG)_ for Windows in order to ensure safer key storage.

### 📦 "Boxfile" file format

The encrypted files are "boxed" into a `.box` file and stored in that way on the drive. A "boxfile" is a custom file
format which uses different techniques in order to ensure safety of the data, verify its content integrity and embed
additional information about the file. It is a way of obfuscating the stored data combined with giving the program
its unique features.

A `.box` file consists of a _header_, _body_ and _checksum_.

- **Header** contains all the publicly available information about the file: version of the boxfile version used, length of
  random padding and per-file randomly generated `nonce`, which is user for encryption processes.

- **Body** of the `.box` file is made up from two things: the actual original file data and randomly generated padding. The
  original data consists of original file name, extension, edit and access times, and the actual file contents. Padding
  is a randomly generated stream of bytes (from sizes 4-255) which acts as an obfuscation technique during encryption,
  as it combined with file data to make it harder to access original information and mislead the bad actor.

- **Checksum** is generated from the header and body content. It is a unique hash which represents the contents of the
  pre-encrypted file data. During the decryption process file contents are hashed again and compared with the original
  checksum to verify file data integrity.

## 🕹️ Usage

Currently, the program provides a CLI which is used for all major operations. The program can be run with
`databoxer <COMMAND>`. The complete list of commands can be viewed with `databoxer --help`. Below are shown usage
examples of some of the main commands.

### Encrypting files

<details>

<summary>Example</summary>

<div>
    <img alt="encryption" src="media/gif/encryption-full.gif">
</div>

</details>

```shell
databoxer box <PATH>...
```

Multiple paths can be supplied for multi-file encryption, as well as directories (with optional recursive feature `-R`)

Output files will be encrypted and formatted into a custom `.box` file type with a random UUID as a name. User also
can specify the output location for each file with a `-o` flag

### Decrypting files

<details>

<summary>Example</summary>

<div>
    <img alt="decryption" src="media/gif/decryption-full.gif">
</div>

</details>

```shell
databoxer unbox <PATH>...
```

Functions similarly to encryption: support for multiple paths and directories. The original file name can be supplied
instead of a UUID to easily identify files

The input files have to have a `.box` file type. During decryption the program will restore original file name and
extension

### Configuring profiles

<details>

<summary>Example</summary>

<div>
    <img alt="profiles" src="media/gif/profile-full.gif">
</div>

</details>

```shell
databoxer profile <ACTION> <NAME>
```

A new profile can be created with the `profile new` command. Each profile should have a name and password, which is
asked every time a profile-related feature is used by the user (e.g. encryption, as it requires profile's encryption
key).

Other profile manipulation actions include `select` which profile to use, `delete` to delete one and `list` to list
all other existing profiles.

### Manipulating encryption keys

<details>

<summary>Example</summary>

<div>
    <img alt="key" src="media/gif/key-set.gif">
</div>

</details>

```shell
databoxer key <ACTION>
```

The `key` subcommand is used to control the profile's stored encryption key. It can be outputted it in a formatted hex
string using the `key get` command.

A new key can be created with the `key new` command, generating a fresh encryption key and overwriting the old one. A
key can also be set from the outside (using a hex string) using the `key set <KEY>` command. The key has to be a 32-byte
key to be accepted (refer to `key get` command's output for how the key should look to be valid).

## 🧰 Development

As stated previously this project is in very active development. The current implementation of many things might
completely change by the time it is fully released.

### Feature plan

_These plans could change during future development_

- [x] User profile system
- [x] `.box` file format
- [x] Multiple profiles/keys support
- [ ] Support for custom user config (using `config.toml`)
- [ ] File data compression
- [ ] Improved profile storage (SQLite?)
- [ ] Batch file encryption (`boxfile` archive)
- [ ] Remote key storage support (Google Drive, etc)
- [ ] OS-native toolchain support (GnuPG, Kleopatra, CryptoAPI, etc.)
- [ ] GUI interface

### Contribution

Any kind of contribution is very welcomed! The codebase is well-documented and actively maintained, so it would not
be too hard to get started with it.
