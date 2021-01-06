//! Authorization query effects and functions.
//!

/// Result of an authorization inquiry
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[deprecated()]
pub enum Effect {
    /// Authorization is granted
    ALLOW,

    /// Authorization is denied
    DENY,
}

/// Result of authorization inquiry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect2 {
    // Authorized.
    ALLOW,
    // Not authorized.
    DENY,
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
/// assert_eq!(None, combine_non_strict(Vec::default()));
///
/// // all silence is silence
/// assert_eq!(None, combine_non_strict(vec![None, None]));
///
/// // silence ignored
/// assert_eq!(Some(ALLOW), combine_non_strict(vec![None, Some(ALLOW)]));
/// assert_eq!(Some(DENY), combine_non_strict(vec![None, Some(DENY)]));
///
/// // deny wins
/// assert_eq!(Some(DENY), combine_non_strict(vec![Some(ALLOW), Some(DENY), Some(ALLOW)]));
/// assert_eq!(Some(ALLOW), combine_non_strict(vec![Some(ALLOW), Some(ALLOW), Some(ALLOW)]));
/// ```
pub fn combine_non_strict<I>(effs: I) -> Option<Effect2>
where
    I: IntoIterator<Item = Option<Effect2>>,
{
    use Effect2::*;

    effs.into_iter().fold(None, |a, e| match (a, e) {
        (None, x) => x,
        (x, None) => x,
        (Some(ALLOW), Some(ALLOW)) => Some(ALLOW),
        _ => Some(DENY),
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
/// assert_eq!(None, combine_strict(Vec::default()));
///
/// // all silence is silence
/// assert_eq!(None, combine_strict(vec![None, None]));
///
/// // silence wins
/// assert_eq!(None, combine_strict(vec![None, Some(ALLOW)]));
/// assert_eq!(None, combine_strict(vec![Some(DENY), None]));
///
/// // if no silence, Some(DENY) wins
/// assert_eq!(Some(DENY), combine_strict(vec![Some(ALLOW), Some(DENY), Some(ALLOW)]));
/// assert_eq!(Some(ALLOW), combine_strict(vec![Some(ALLOW), Some(ALLOW), Some(ALLOW)]));
/// ```
pub fn combine_strict<I>(effs: I) -> Option<Effect2>
where
    I: IntoIterator<Item = Option<Effect2>>,
{
    use Effect2::*;

    const O_INIT: Option<Option<Effect2>> = None;
    const O_SILENCE: Option<Effect2> = None;
    const O_ALLOW: Option<Effect2> = Some(ALLOW);
    const O_DENY: Option<Effect2> = Some(DENY);

    effs.into_iter()
        .fold(O_INIT, |a, e| match (a, e) {
            (O_INIT, x) => Some(x),
            (Some(O_SILENCE), _) => Some(O_SILENCE),
            (_, O_SILENCE) => Some(O_SILENCE),
            (Some(O_ALLOW), O_ALLOW) => Some(O_ALLOW),
            _ => Some(O_DENY),
        })
        .unwrap_or(O_SILENCE)
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
        fn check<I>(effs: I, expected: Option<Effect2>)
        where
            I: IntoIterator<Item = Option<Effect2>>,
        {
            assert_eq!(combine_non_strict(effs), expected);
        }

        check(vec![Some(DENY), Some(DENY), Some(DENY)], Some(DENY));
        check(vec![Some(DENY), Some(DENY), Some(ALLOW)], Some(DENY));
        check(vec![Some(DENY), Some(ALLOW), Some(DENY)], Some(DENY));
        check(vec![Some(DENY), Some(ALLOW), Some(ALLOW)], Some(DENY));
        check(vec![Some(ALLOW), Some(DENY), Some(DENY)], Some(DENY));
        check(vec![Some(ALLOW), Some(DENY), Some(ALLOW)], Some(DENY));
        check(vec![Some(ALLOW), Some(ALLOW), Some(DENY)], Some(DENY));

        check(vec![Some(ALLOW), Some(ALLOW), Some(ALLOW)], Some(ALLOW));

        check(vec![], None);
        check(vec![None, None], None);
        check(vec![None, Some(DENY), None, Some(DENY), None], Some(DENY));
        check(vec![None, Some(DENY), None, Some(ALLOW), None], Some(DENY));
        check(
            vec![None, Some(ALLOW), None, Some(ALLOW), None],
            Some(ALLOW),
        );
    }

    #[test]
    fn test_combine_strict() {
        use Effect2::*;
        fn check<I>(effs: I, expected: Option<Effect2>)
        where
            I: IntoIterator<Item = Option<Effect2>>,
        {
            assert_eq!(combine_strict(effs), expected);
        }

        check(vec![Some(DENY), Some(DENY), Some(DENY)], Some(DENY));
        check(vec![Some(DENY), Some(DENY), Some(ALLOW)], Some(DENY));
        check(vec![Some(DENY), Some(ALLOW), Some(DENY)], Some(DENY));
        check(vec![Some(DENY), Some(ALLOW), Some(ALLOW)], Some(DENY));
        check(vec![Some(ALLOW), Some(DENY), Some(DENY)], Some(DENY));
        check(vec![Some(ALLOW), Some(DENY), Some(ALLOW)], Some(DENY));
        check(vec![Some(ALLOW), Some(ALLOW), Some(DENY)], Some(DENY));

        check(vec![Some(ALLOW), Some(ALLOW), Some(ALLOW)], Some(ALLOW));

        check(vec![], None);
        check(vec![None, None], None);
        check(vec![None, Some(DENY), None, Some(DENY), None], None);
        check(vec![None, Some(DENY), None, Some(ALLOW), None], None);
        check(vec![None, Some(ALLOW), None, Some(ALLOW), None], None);
    }
}
