//! Authorization effects.
//!

/// Definite authorization
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Authorized.
    ALLOW,
    /// Not authorized.
    DENY,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct ComputedEffect(Option<Effect>);

/// Authorization is not determined from a computation
pub const SILENT: ComputedEffect = ComputedEffect(None);

/// Authorized
pub const ALLOW: ComputedEffect = ComputedEffect(Some(Effect::ALLOW));

/// Undauthorized
pub const DENY: ComputedEffect = ComputedEffect(Some(Effect::DENY));

impl ComputedEffect {
    /// Determine if ComputedEffect authorizes access. The only effect that authorizes
    /// access is `ALLOW`.
    ///
    /// # Example
    ///
    /// ```
    /// use authorization_core::effect::*;
    ///
    /// assert_eq!(ALLOW.authorized(), true);
    /// assert_eq!(DENY.authorized(), false);
    /// assert_eq!(SILENT.authorized(), false);
    /// ```
    pub fn authorized(self) -> bool {
        self == ALLOW
    }
}

impl From<Effect> for ComputedEffect {
    fn from(permission: Effect) -> Self {
        ComputedEffect(Some(permission))
    }
}

impl From<Option<Effect>> for ComputedEffect {
    fn from(maybe_permission: Option<Effect>) -> Self {
        ComputedEffect(maybe_permission)
    }
}

/// Combine multiple optional effects in non-strict fashion. The result is
/// `ALLOW` if and only if there is at least one `ALLOW` constituent and
/// no `DENY` constituents.
///
/// This is used when evaluating multipl effects for a single principal. Total
/// silence indicates unauthorized as does the presence of any `DENY`. But if
/// at least one effect can be found to `ALLOW` and there are not results
/// that are `DENY`, the principal is authorized.
///
/// # Examples
///
/// ```
/// use authorization_core::effect::*;
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
pub fn combine_non_strict<I>(effs: I) -> ComputedEffect
where
    I: IntoIterator<Item = ComputedEffect>,
{
    effs.into_iter().fold(SILENT, |a, e| match (a, e) {
        (SILENT, x) => x,
        (x, SILENT) => x,
        (ALLOW, ALLOW) => ALLOW,
        _ => DENY,
    })
}

/// Combine mutiple effects in strict fashion. The result is `ALLOW` if
/// and only if there is at least one constituent effect and every consituent
/// effect is `ALLOW`
///
/// As with non-strict, if there are no constituents, the result is `SILENT`.
///
/// This function is used to combine effects for composite principals where a result
/// is determined for each atomic principal. In this case, access is authorized if
/// and only if access is authorized for each atomic principal.
///
/// # Examles
///
/// ```
/// use authorization_core::effect::*;
///
/// // silence if no constituents
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
pub fn combine_strict<I>(effs: I) -> ComputedEffect
where
    I: IntoIterator<Item = ComputedEffect>,
{
    const INIT: Option<ComputedEffect> = None;

    effs.into_iter()
        .fold(INIT, |a, e| match (a, e) {
            (INIT, x) => Some(x),
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
    fn test_authorized_allow() {
        assert_eq!(ALLOW.authorized(), true);
    }

    #[test]
    fn test_authorized_deny() {
        assert_eq!(DENY.authorized(), false);
    }

    #[test]
    fn test_authorized_silent() {
        assert_eq!(SILENT.authorized(), false);
    }

    #[test]
    fn test_combine_non_strict() {
        fn check<I>(effs: I, expected: ComputedEffect)
        where
            I: IntoIterator<Item = ComputedEffect>,
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
        fn check<I>(effs: I, expected: ComputedEffect)
        where
            I: IntoIterator<Item = ComputedEffect>,
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
