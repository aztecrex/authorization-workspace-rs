//! Authorization query effects and functions.
//!

/// Result of an authorization inquiry
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Authorized.
    ALLOW,
    /// Not authorized.
    DENY,
}

/// Determine if an optional effect denotes authorization. `Some(ALLOW)` is the
/// only final result denoting authorization.
///
/// # Example
///
/// ```
/// use authorization_core::authorization::*;
/// use Effect::*;
///
/// assert_eq!(authorized(Some(ALLOW)), true);
/// assert_eq!(authorized(Some(DENY)), false);
/// assert_eq!(authorized(None), false);
/// ```
pub fn authorized(eff: Option<Effect>) -> bool {
    eff == Some(Effect::ALLOW)
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
/// use authorization_core::authorization::*;
/// use Effect::*;
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
pub fn combine_non_strict<I>(effs: I) -> Option<Effect>
where
    I: IntoIterator<Item = Option<Effect>>,
{
    use Effect::*;

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
/// use authorization_core::authorization::*;
/// use Effect::*;
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
pub fn combine_strict<I>(effs: I) -> Option<Effect>
where
    I: IntoIterator<Item = Option<Effect>>,
{
    use Effect::*;

    const O_INIT: Option<Option<Effect>> = None;
    const O_SILENCE: Option<Effect> = None;
    const O_ALLOW: Option<Effect> = Some(ALLOW);
    const O_DENY: Option<Effect> = Some(DENY);

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
    fn test_authorized_allow() {
        assert_eq!(authorized(Some(Effect::ALLOW)), true);
    }

    #[test]
    fn test_authorized_deny() {
        assert_eq!(authorized(Some(Effect::DENY)), false);
    }

    #[test]
    fn test_authorized_silent() {
        assert_eq!(authorized(None), false);
    }

    #[test]
    fn test_combine_non_strict() {
        use Effect::*;
        fn check<I>(effs: I, expected: Option<Effect>)
        where
            I: IntoIterator<Item = Option<Effect>>,
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
        use Effect::*;
        fn check<I>(effs: I, expected: Option<Effect>)
        where
            I: IntoIterator<Item = Option<Effect>>,
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
