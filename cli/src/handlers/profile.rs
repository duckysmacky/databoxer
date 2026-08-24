//! Handlers for the `databoxer profile` command and its subcommands

use databoxer_core::{
    data::{self, profiles::{Profile, ProfileError}},
    log,
};

use crate::{
    command::{ProfileDeleteArgs, ProfileNewArgs, ProfileSetArgs},
    error::OrFail,
    output,
};

/// Handles the `databoxer profile create` subcommand
pub fn handle_profile_create(args: &ProfileNewArgs) {
    let name = &args.name;

    create_profile(args.password.as_deref(), name)
        .or_fail_with(format!("Unable to create a new profile named '{}'", name));

    output!(SUCCESS, "Successfully created new profile '{}'", name);
}

fn create_profile(password: Option<&str>, name: &str) -> Result<(), ProfileError> {
    let mut profiles = data::get_profiles()?;

    // checked before authenticating, so a doomed request never costs a password prompt
    profiles.ensure_absent(name)?;

    let password = super::resolve_password(password).or_fail_with("Unable to read the password");
    profiles.new_profile(Profile::new(name, &password)?)
}

/// Handles the `databoxer profile delete` subcommand
pub fn handle_profile_delete(args: &ProfileDeleteArgs) {
    let name = &args.name;

    delete_profile(args.password.as_deref(), name)
        .or_fail_with(format!("Unable to delete profile '{}'", name));

    output!(SUCCESS, "Successfully deleted profile '{}'", name);
}

fn delete_profile(password: Option<&str>, name: &str) -> Result<(), ProfileError> {
    let mut profiles = data::get_profiles()?;
    profiles.ensure_exists(name)?;

    let password = super::resolve_password(password).or_fail_with("Unable to read the password");
    profiles.delete_profile(&password, name)
}

/// Handles the `databoxer profile set` subcommand
pub fn handle_profile_set(args: &ProfileSetArgs) {
    let name = &args.name;

    select_profile(args.password.as_deref(), name)
        .or_fail_with(format!("Unable to switch to profile '{}'", name));

    output!(SUCCESS, "Successfully set current profile to '{}'", name);
}

fn select_profile(password: Option<&str>, name: &str) -> Result<(), ProfileError> {
    let mut profiles = data::get_profiles()?;
    profiles.ensure_selectable(name)?;

    let password = super::resolve_password(password).or_fail_with("Unable to read the password");
    profiles.set_current(&password, name)
}

/// Handles the `databoxer profile get` subcommand
pub fn handle_profile_get() {
    // no authentication needed, as only the name is read
    let name = data::get_profiles()
        .and_then(|mut profiles| Ok(profiles.get_current_profile()?.name.clone()))
        .or_fail_with("Unable to get currently selected profile");

    output!(SUCCESS, "Currently selected profile:");
    output!(DATA, "{}", name);
}

/// Handles the `databoxer profile list` subcommand
pub fn handle_profile_list() {
    // no authentication needed, as only the names are read
    let names = data::get_profiles()
        .map(|profiles| profiles.get_profiles()
            .iter()
            .map(|profile| profile.name.clone())
            .collect::<Vec<String>>()
        )
        .or_fail_with("Unable to get a list of all profiles");

    let count = names.len();

    if count == 0 {
        output!(SUCCESS, "No profiles found");
        log!(WARN, "New profile can be created with 'databoxer profile new'");
        return;
    }

    if count > 1 {
        output!(SUCCESS, "There are {} profiles found:", count);
    } else {
        output!(SUCCESS, "There is {} profile found:", count);
    }

    for name in names {
        output!(DATA, "{}", name);
    }
}
