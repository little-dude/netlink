use crate::constants::*;

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum RuleAction {
    Never,
    Possible,
    Always,
    Unknown(u32),
}

impl From<u32> for RuleAction {
    fn from(value: u32) -> Self {
        use self::RuleAction::*;
        match value {
            AUDIT_NEVER => Never,
            AUDIT_POSSIBLE => Possible,
            AUDIT_ALWAYS => Always,
            _ => Unknown(value),
        }
    }
}

impl From<RuleAction> for u32 {
    fn from(value: RuleAction) -> Self {
        use self::RuleAction::*;
        match value {
            Never => AUDIT_NEVER,
            Possible => AUDIT_POSSIBLE,
            Always => AUDIT_ALWAYS,
            Unknown(value) => value,
        }
    }
}
