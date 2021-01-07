use super::matcher::*;

/// Trait for matching actions. When evaluating a policy, this is used to determine if
/// the policy applies with respect to a concrete action.
pub trait ActionMatch {
    /// The type of action matched by this implementation.
    type Action;

    /// Determine if a concrete action matches
    fn test(&self, action: &Self::Action) -> bool;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct StrAction<'a>(pub &'a str);

impl<'a> From<&'a str> for StrAction<'a> {
    fn from(v: &'a str) -> Self {
        StrAction(v)
    }
}

impl<'a> Matcher for StrAction<'a> {
    type Target = Self;

    fn test(&self, target: &Self::Target) -> bool {
        self.0 == target.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_str_action_matcher() {
        let action = StrAction("abc");

        assert_eq!(StrAction("abc").test(&action), true);
        assert_eq!(StrAction("xyz").test(&action), false);
    }
}
