//! Authorization query effects and functions.
//!

/// Result of an authorization inquiry
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Authorization is granted
    ALLOW,

    /// Authorization is denied
    DENY,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect2 {
    ALLOW,
    DENY,
    SILENT,
}

/// Combine two effects for evaluating an aggregate. Result is `Effect::ALLOW` iff
/// both arguments are `Effect::ALLOW`.
pub fn reduce_effects(e1: Effect, e2: Effect) -> Effect {
    use Effect::*;

    if e1 == ALLOW {
        e2
    } else {
        DENY
    }
}

/// Combine two optional effets for evaluating an aggregate. `None` is interpreted to
/// mean silence and if either argument is `None`, then the result is `None`. If both arguments
/// are `Some(eff)` the result is also `Some(r)` where `r` is the result of applying
/// `reduce_effects(..)` to the inner values.
pub fn reduce_optional_effects(e1: Option<Effect>, e2: Option<Effect>) -> Option<Effect> {
    match (e1, e2) {
        (None, x) => x,
        (x, None) => x,
        (Some(x), Some(y)) => Some(reduce_effects(x, y)),
    }
}

/// Combine multiple optional effects in non-strict fashion. i.e. where combining
/// can result in silence. This function returns silence iff the argument is empty or
/// contains only silence. Otherwise, it returns `Some(ALLOW)` iff all non-silent
/// constituents are `Some(ALLOW)`.
///
/// This is used when evaluating multiple applicable effects for a single principal. Non-
/// applicable effects  (those resolving to silence) are ignored. If there are no
/// applicable effects (none provide or all are silent), then combinaing them results
/// in silence.
///
/// ```
/// use authorization_core::effect::*;
/// use Effect2::*;
///
/// // empty is silence
/// assert_eq!(SILENT, combine_non_strict(Vec::default()));
///
/// // all silence is silence
/// assert_eq!(SILENT, combine_non_strict(vec![SILENT, SILENT]));
///
/// // silence ignored
/// assert_eq!(ALLOW, combine_non_strict(vec![SILENT, ALLOW]));
/// assert_eq!(DENY, combine_non_strict(vec![SILENT, DENY]));
///
/// // deny wins
/// assert_eq!(DENY, combine_non_strict(vec![ALLOW, DENY, ALLOW]));
/// assert_eq!(ALLOW, combine_non_strict(vec![ALLOW, ALLOW, ALLOW]));
/// ```
pub fn combine_non_strict<I>(effs: I) -> Effect2
where
    I: IntoIterator<Item = Effect2>,
{
    use Effect2::*;

    effs.into_iter().fold(SILENT, |a, e| match (a, e) {
        (SILENT, x) => x,
        (x, SILENT) => x,
        (ALLOW, ALLOW) => ALLOW,
        _ => DENY,
    })
}

/// Combine multiple optional effects in strict fashion. i.e. combination always
/// results in a non-silent effect.  This function returns `Some(ALLOW)` iff it is non-empty
/// and every constituent is `Some(ALLOW)`. It returns silence (`None`) iff the argument is empty
/// or any constituent is silent.
///
/// This is used to combine effects for multiple principals, granting the least
/// common effect. If the effect for any principal is silent, then the overall effect
/// is silence.
///
/// ```
/// use authorization_core::effect::*;
/// use Effect2::*;
///
/// // empty is silence
/// assert_eq!(SILENT, combine_strict(Vec::default()));
///
/// // all silence is silence
/// assert_eq!(SILENT, combine_strict(vec![SILENT, SILENT]));
///
/// // silence wins
/// assert_eq!(SILENT, combine_strict(vec![SILENT, ALLOW]));
/// assert_eq!(SILENT, combine_strict(vec![DENY, SILENT]));
///
/// // if no silence, DENY wins
/// assert_eq!(DENY, combine_strict(vec![ALLOW, DENY, ALLOW]));
/// assert_eq!(ALLOW, combine_strict(vec![ALLOW, ALLOW, ALLOW]));
/// ```
pub fn combine_strict<I>(effs: I) -> Effect2
where
    I: IntoIterator<Item = Effect2>,
{
    use Effect2::*;

    effs.into_iter()
        .fold(None, |a, e| match (a, e) {
            (None, x) => Some(x),
            (Some(SILENT), _) => Some(SILENT),
            (_, SILENT) => Some(SILENT),
            (Some(ALLOW), ALLOW) => Some(ALLOW),
            _ => Some(DENY),
        })
        .unwrap_or(SILENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce() {
        use Effect::*;
        assert_eq!(reduce_effects(ALLOW, DENY), DENY);
        assert_eq!(reduce_effects(ALLOW, ALLOW), ALLOW);
        assert_eq!(reduce_effects(DENY, DENY), DENY);
        assert_eq!(reduce_effects(DENY, ALLOW), DENY);
    }

    #[test]
    fn test_reduce_optional() {
        use Effect::*;
        fn check_reduce_optional(e1: Effect, e2: Effect) {
            assert_eq!(
                reduce_optional_effects(Some(e1), Some(e2)),
                Some(reduce_effects(e1, e2))
            );
        }

        check_reduce_optional(ALLOW, DENY);
        check_reduce_optional(ALLOW, ALLOW);
        check_reduce_optional(DENY, ALLOW);
        check_reduce_optional(DENY, DENY);

        assert_eq!(reduce_optional_effects(Some(DENY), None), Some(DENY));
        assert_eq!(reduce_optional_effects(Some(ALLOW), None), Some(ALLOW));
        assert_eq!(reduce_optional_effects(None, Some(DENY)), Some(DENY));
        assert_eq!(reduce_optional_effects(None, Some(ALLOW)), Some(ALLOW));

        assert_eq!(reduce_optional_effects(None, None), None);
    }

    #[test]
    fn test_combine_non_strict() {
        use Effect2::*;
        fn check<I>(effs: I, expected: Effect2)
        where
            I: IntoIterator<Item = Effect2>,
        {
            assert_eq!(combine_non_strict(effs), expected);
        }

        check(vec![DENY, DENY, DENY], DENY);
        check(vec![DENY, DENY, ALLOW], DENY);
        check(vec![DENY, ALLOW, DENY], DENY);
        check(vec![DENY, ALLOW, ALLOW], DENY);
        check(vec![ALLOW, DENY, DENY], DENY);
        check(vec![ALLOW, DENY, ALLOW], DENY);
        check(vec![ALLOW, ALLOW, DENY], DENY);

        check(vec![ALLOW, ALLOW, ALLOW], ALLOW);

        check(vec![], SILENT);
        check(vec![SILENT, SILENT], SILENT);
        check(vec![SILENT, DENY, SILENT, DENY, SILENT], DENY);
        check(vec![SILENT, DENY, SILENT, ALLOW, SILENT], DENY);
        check(vec![SILENT, ALLOW, SILENT, ALLOW, SILENT], ALLOW);
    }

    #[test]
    fn test_combine_strict() {
        use Effect2::*;
        fn check<I>(effs: I, expected: Effect2)
        where
            I: IntoIterator<Item = Effect2>,
        {
            assert_eq!(combine_strict(effs), expected);
        }

        check(vec![DENY, DENY, DENY], DENY);
        check(vec![DENY, DENY, ALLOW], DENY);
        check(vec![DENY, ALLOW, DENY], DENY);
        check(vec![DENY, ALLOW, ALLOW], DENY);
        check(vec![ALLOW, DENY, DENY], DENY);
        check(vec![ALLOW, DENY, ALLOW], DENY);
        check(vec![ALLOW, ALLOW, DENY], DENY);

        check(vec![ALLOW, ALLOW, ALLOW], ALLOW);

        check(vec![], SILENT);
        check(vec![SILENT, SILENT], SILENT);
        check(vec![SILENT, DENY, SILENT, DENY, SILENT], SILENT);
        check(vec![SILENT, DENY, SILENT, ALLOW, SILENT], SILENT);
        check(vec![SILENT, ALLOW, SILENT, ALLOW, SILENT], SILENT);
    }
}
