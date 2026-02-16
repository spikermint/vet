//! Email service providers.

mod mailgun;
mod resend;
mod sendgrid;

pub use mailgun::MailgunProvider;
pub use resend::ResendProvider;
pub use sendgrid::SendGridProvider;
