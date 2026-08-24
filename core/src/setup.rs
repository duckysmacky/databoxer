use crate::io::{input::InputPrompter, log::Logger};

/// Components every frontendmust supply before using this crate. Construct
/// with all fields, then pass to `set_hooks`
pub struct FrontendHooks {
    pub logger: Box<dyn Logger>,
    pub prompter: Box<dyn InputPrompter>,
}

/// Registers the components in `FrontendHooks`. Should be called once during startup, before
/// any other core function
pub fn set_hooks(hooks: FrontendHooks) {
    crate::io::log::set_logger(hooks.logger);
    crate::io::input::set_input_prompter(hooks.prompter);
}
