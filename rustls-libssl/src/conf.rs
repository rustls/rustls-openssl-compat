/// Implementation of the `SSL_CONF_*` API functions.
use std::os::raw::{c_int, c_uint};
use std::sync::Arc;

use rustls::ProtocolVersion;

use crate::error::Error;
use crate::not_thread_safe::NotThreadSafe;
use crate::{Ssl, SslContext};

#[derive(Default)]
pub(super) struct SslConfigCtx {
    prefix: String,
    flags: Flags,
    state: State,
}

impl SslConfigCtx {
    pub(super) fn new() -> Self {
        Self {
            prefix: "-".to_owned(), // OpenSSL default.
            flags: Flags::default(),
            state: State::default(),
        }
    }

    pub(super) fn cmd(&mut self, cmd: &str, value: Option<&str>) -> c_int {
        let command = match self.supported_command(cmd) {
            Some(command) => command,
            None => {
                return -2; // "A return value of -2 means option is not recognised."
            }
        };

        match (command.action)(self, value) {
            Err(mut e) => {
                if self.flags.is_show_errors() {
                    e = Error::bad_data(&format!("cmd={cmd} value={}", value.unwrap_or("none")))
                        .raise()
                }
                e.into()
            }
            Ok(action_result) => action_result.into(),
        }
    }

    pub(super) fn cmd_value_type(&self, cmd: &str) -> ValueType {
        self.supported_command(cmd)
            .map(|c| c.value_type)
            .unwrap_or(ValueType::Unknown)
    }

    pub(super) fn set_flags(&mut self, flags: u32) -> Flags {
        self.flags.0 |= flags;
        self.flags
    }

    pub(super) fn clear_flags(&mut self, flags: u32) -> Flags {
        self.flags.0 &= !flags;
        self.flags
    }

    pub(super) fn set_prefix(&mut self, prefix: &str) {
        // Note: allows setting the prefix to "" explicitly, overriding the default "-".
        prefix.clone_into(&mut self.prefix)
    }

    pub(super) fn apply_to_ctx(&mut self, ctx: Arc<NotThreadSafe<SslContext>>) {
        self.state = ctx.into()
    }

    pub(super) fn apply_to_ssl(&mut self, ssl: Arc<NotThreadSafe<Ssl>>) {
        self.state = ssl.into()
    }

    pub(super) fn validation_only(&mut self) {
        self.state = State::Validating
    }

    pub(super) fn finish(&mut self) -> bool {
        // NOTE(XXX): only CA names and, SSL_CONF_FLAG_REQUIRE_PRIVATE are handled here, and both
        //  are NYI for this shim. For other cmds, the CTX (if set) is mutated along the way.
        true
    }

    fn min_protocol(&mut self, proto: Option<&str>) -> Result<ActionResult, Error> {
        let ver = match Self::parse_protocol_version(proto) {
            Some(ver) => ver,
            None => return Err(Error::bad_data("unrecognized protocol version")),
        };

        Ok(match &self.state {
            // For some reason the upstream returns 0 in this case.
            State::Validating => return Err(Error::bad_data("no ctx/ssl")),
            State::ApplyingToCtx(ctx) => {
                ctx.get_mut().set_min_protocol_version(ver);
                ActionResult::Applied
            }
            State::ApplyingToSsl(ssl) => {
                ssl.get_mut().set_min_protocol_version(ver);
                ActionResult::Applied
            }
        })
    }

    fn max_protocol(&mut self, proto: Option<&str>) -> Result<ActionResult, Error> {
        let ver = match Self::parse_protocol_version(proto) {
            Some(ver) => ver,
            None => return Err(Error::bad_data("unrecognized protocol version")),
        };

        Ok(match &self.state {
            // For some reason the upstream returns 0 in this case.
            State::Validating => return Err(Error::bad_data("no ctx/ssl")),
            State::ApplyingToCtx(ctx) => {
                ctx.get_mut().set_max_protocol_version(ver);
                ActionResult::Applied
            }
            State::ApplyingToSsl(ssl) => {
                ssl.get_mut().set_max_protocol_version(ver);
                ActionResult::Applied
            }
        })
    }

    fn parse_protocol_version(proto: Option<&str>) -> Option<u16> {
        Some(match proto {
            Some("None") => 0,
            Some("TLSv1.2") => u16::from(ProtocolVersion::TLSv1_2),
            Some("TLSv1.3") => u16::from(ProtocolVersion::TLSv1_3),
            _ => return None,
        })
    }

    fn supported_command(&self, cmd_name: &str) -> Option<&Command> {
        SUPPORTED_COMMANDS.iter().find(|cmd| {
            // If the cctx flags don't permit the cmd, skip it.
            if !cmd.permitted(self) {
                return false;
            }

            // cmd line flag options are matched case-sensitively, honouring the prefix.
            if self.flags.is_cmdline() {
                if let Some(cli_cmd) = cmd.name_cmdline {
                    if cmd_name == format!("{}{cli_cmd}", self.prefix) {
                        return true;
                    }
                }
            }

            // cmd file options are matched **case-insensitively**. The prefix is only considered
            // if it's non-default.
            if self.flags.is_file() {
                if let Some(file_cmd) = cmd.name_file {
                    if match self.prefix.as_str() {
                        // Default prefix - ignore in comparison.
                        "-" => cmd_name.eq_ignore_ascii_case(file_cmd),
                        // Custom prefix, use in comparison.
                        prefix => cmd_name.eq_ignore_ascii_case(&format!("{prefix}{file_cmd}")),
                    } {
                        return true;
                    }
                }
            }

            false
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i32)]
pub(super) enum ValueType {
    /// The option is unrecognized.
    Unknown = 0x0,
    /// The option value is a string without any specific structure.
    String = 0x1,
    // The option value is a filename.
    //File = 0x2,
    // The option value is a directory name.
    //Dir = 0x3,
    // The option value is not used.
    //None = 0x4,
}

impl From<ValueType> for c_int {
    fn from(value: ValueType) -> Self {
        value as i32
    }
}

/// Describes how option calls on a `SslConfigCtx` should be handled.
///
/// If no `SslContext` or `Ssl` is set, the command is validated but not applied.
/// Otherwise, commands mutate the `SslContext` or `Ssl` as appropriate.
#[derive(Default)]
enum State {
    /// Command values are validated, but not applied to a [`Ssl`] or [`SslContext`]
    #[default]
    Validating,
    /// Commands are applied to a [`SslContext`]
    ApplyingToCtx(Arc<NotThreadSafe<SslContext>>),
    /// Commands are applied to a [`Ssl`]
    ApplyingToSsl(Arc<NotThreadSafe<Ssl>>),
}

impl From<Arc<NotThreadSafe<SslContext>>> for State {
    fn from(ctx: Arc<NotThreadSafe<SslContext>>) -> Self {
        Self::ApplyingToCtx(ctx)
    }
}

impl From<Arc<NotThreadSafe<Ssl>>> for State {
    fn from(ssl: Arc<NotThreadSafe<Ssl>>) -> Self {
        Self::ApplyingToSsl(ssl)
    }
}

/// A command that can be applied to a [`SslConfigCtx`] based on the context and command flags.
struct Command {
    /// Name of the command when used by a [`SslConfigCtx`] with [`Flags::FILE`] set.
    name_file: Option<&'static str>,
    /// Name of the command when used by a [`SslConfigCtx`] with [`Flags::CMDLINE`] set.
    name_cmdline: Option<&'static str>,
    /// Flags that must be set on the [`SslConfigCtx`] for the command to be permitted.
    flags: Flags,
    /// Type of value expected by the [`CommandAction`].
    value_type: ValueType,
    /// Function that updates the [`SslConfigCtx`] based on the command value.
    action: CommandAction,
}

impl Command {
    /// Returns true if the command is permitted based on the context flags.
    fn permitted(&self, cctx: &SslConfigCtx) -> bool {
        // Matched to the logic from OpenSSL `static ssl_conf_cmd_allowed`.
        if self.flags.is_server() && !cctx.flags.is_server() {
            return false;
        }

        if self.flags.is_client() && !cctx.flags.is_client() {
            return false;
        }

        if self.flags.is_certificate() && !cctx.flags.is_certificate() {
            return false;
        }

        true
    }
}

/// A fn that can update `SslConfigCtx` after parsing `value`.
type CommandAction = fn(&mut SslConfigCtx, value: Option<&str>) -> Result<ActionResult, Error>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i32)]
enum ActionResult {
    /// The action value was recognized, but not applied.
    ///
    /// For example, if no `SSL_CTX` has been set a [`CommandAction`] may return `NotApplied` after
    /// validating the command value.
    #[allow(dead_code)] // TODO(XXX): remove with first ref.
    NotApplied = 1,
    /// The action value was recognized and applied.
    Applied = 2,
}

impl From<ActionResult> for c_int {
    fn from(value: ActionResult) -> Self {
        value as c_int
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct Flags(c_uint);

impl Flags {
    const ANY: c_uint = 0x0;

    // See openssl/ssl.h
    const CMDLINE: c_uint = 0x1;
    const FILE: c_uint = 0x2;
    const CLIENT: c_uint = 0x4;
    const SERVER: c_uint = 0x8;
    const SHOW_ERRORS: c_uint = 0x10;
    const CERTIFICATE: c_uint = 0x20;
    #[allow(dead_code)] // TODO(XXX): Remove once REQUIRE_PRIVATE is used.
    const REQUIRE_PRIVATE: c_uint = 0x40;

    fn is_cmdline(&self) -> bool {
        self.0 & Self::CMDLINE == Self::CMDLINE
    }

    fn is_file(&self) -> bool {
        self.0 & Self::FILE == Self::FILE
    }

    fn is_client(&self) -> bool {
        self.0 & Self::CLIENT == Self::CLIENT
    }

    fn is_server(&self) -> bool {
        self.0 & Self::SERVER == Self::SERVER
    }

    fn is_certificate(&self) -> bool {
        self.0 & Self::CERTIFICATE == Self::CERTIFICATE
    }

    #[allow(dead_code)] // TODO(XXX): Remove once REQUIRE_PRIVATE is used.
    fn is_require_private(&self) -> bool {
        self.0 & Self::REQUIRE_PRIVATE == Self::REQUIRE_PRIVATE
    }

    fn is_show_errors(&self) -> bool {
        self.0 & Self::SHOW_ERRORS == Self::SHOW_ERRORS
    }
}

impl From<Flags> for c_uint {
    fn from(flags: Flags) -> c_uint {
        flags.0
    }
}

/// All the [`Command`]s that are supported by [`SslConfigCtx`].
const SUPPORTED_COMMANDS: &[Command] = &[
    Command {
        name_file: Some("MinProtocol"),
        name_cmdline: Some("min_protocol"),
        flags: Flags(Flags::ANY),
        value_type: ValueType::String,
        action: SslConfigCtx::min_protocol,
    },
    Command {
        name_file: Some("MaxProtocol"),
        name_cmdline: Some("max_protocol"),
        flags: Flags(Flags::ANY),
        value_type: ValueType::String,
        action: SslConfigCtx::max_protocol,
    },
];
