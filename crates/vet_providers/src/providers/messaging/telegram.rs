//! Telegram secret patterns.

crate::declare_provider!(
    TelegramProvider,
    id: "telegram",
    name: "Telegram",
    group: Group::Messaging,
    patterns: [
        crate::pattern! {
            id: "messaging/telegram-bot-token",
            group: Group::Messaging,
            name: "Telegram Bot Token",
            description: "Grants full control of a Telegram bot including sending messages and accessing updates.",
            severity: Severity::High,
            regex: r"\b([0-9]{5,16}:A[A-Za-z0-9_-]{34})\b",
            keywords: &["telegram", ":A"],
            default_enabled: true,
            min_entropy: None,
        },
    ],
);

#[cfg(test)]
mod extra_tests {
    use regex::Regex;

    fn regex() -> Regex {
        Regex::new(r"\b([0-9]{5,16}:A[A-Za-z0-9_-]{34})\b").unwrap()
    }

    #[test]
    fn matches_telegram_bot_token_format() {
        let re = regex();
        assert!(re.is_match("123456789:ABCDefGHIJKlmnOPQRSTuvwxyz012345678"));
    }

    #[test]
    fn rejects_missing_colon_a_prefix() {
        let re = regex();
        assert!(!re.is_match("123456789:BCDDefGHIJKlmnOPQRSTuvwxyz012345678"));
    }

    #[test]
    fn rejects_too_short_bot_id() {
        let re = regex();
        assert!(!re.is_match("1234:ABCDefGHIJKlmnOPQRSTuvwxyz012345678"));
    }

    #[test]
    fn rejects_wrong_length_token_part() {
        let re = regex();
        assert!(!re.is_match("123456789:ABCDefGHIJK"));
    }
}
