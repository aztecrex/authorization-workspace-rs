//! Authorization effects.
//!
//! Authorization to perform an action on a resource is goverened by policies
//! that resolve into effects. The basic effect is either `ALLOW` or `DENY`. However,
//! resolving a policy might result in SILENCE. i.e. the policy does not either
//! explicitly allow or deny the action.
//!
//! When combining policies for a principal, the fundamental rule is that there
//! must exist at least one policy that explicitly allows an action and there must
//! be no policy that explicitly denies the action. If all resolved policies are
//! silent or if there are no policies at all, an action is implicitly denied.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// Definite authorization
pub enum Effect {
    /// Definitiely authorized.
    ALLOW,
    /// Definitel not authorized.
    DENY,
}

/// Trait for authorizationi
pub trait Authorization {
    /// Is an action authorized according to this data.
    fn authorized(self) -> bool;
}

impl Authorization for Effect {
    /// Determine if Effect authorizes access. The only effect that authorizes
    /// access is `Effect::ALLOW`.
    ///
    /// # Examples
    ///
    /// ```
    /// use authorization_core::effect::*;
    ///
    /// assert_eq!(Effect::ALLOW.authorized(), true);
    /// assert_eq!(Effect::DENY.authorized(), false);
    /// ```
    fn authorized(self) -> bool {
        self == Self::ALLOW
    }
}

/// Result of an authorization computation. Represents
/// definite `Effect` plus an additional value representing no
/// (i.e. silent) effect. It is equivalent to `Option<Effect>` but defined
/// as a newtype for symbolic clarity and for implementing standard traits.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub struct ComputedEffect(Option<Effect>);

/// No effect. Alone this means an action is not authorized. In conbination
/// with other effects, its meaning depends on the type of combaination.
pub const SILENT: ComputedEffect = ComputedEffect(None);

/// Definitely Authorized
pub const ALLOW: ComputedEffect = ComputedEffect(Some(Effect::ALLOW));

/// Definitely Unauthorized
pub const DENY: ComputedEffect = ComputedEffect(Some(Effect::DENY));

impl Authorization for ComputedEffect {
    /// Determine if Effect authorizes access. The only effect that authorizes
    /// access is `Effect::ALLOW`.
    ///
    /// # Examples
    ///
    /// ```
    /// use authorization_core::effect::*;
    ///
    /// assert_eq!(ALLOW.authorized(), true);
    /// assert_eq!(DENY.authorized(), false);
    /// assert_eq!(SILENT.authorized(), false);
    /// ```
    fn authorized(self) -> bool {
        self.0.map_or(false, |e| e == Effect::ALLOW)
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

/// Combine multiple `ComputedEffect`s in non-strict fashion. The result is
/// `ALLOW` if and only if there is at least one `ALLOW` constituent and
/// no `DENY` constituents.
///
/// This is used when combining policies for a single principal. The
/// result is `SILENT` if there are no consituents or if all constituents
/// are silence. Otherwise silence is ignored and any `DENY` consituent will
/// cause the result to be `DENY`.
///
/// # Examples
///
/// ```
/// use authorization_core::effect::*;
///
/// // empty is silence
/// assert_eq!(SILENT, combine_non_strict(vec![]));
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
/// assert_eq!(ALLOW, combine_non_strict(vec![ALLOW, SILENT, ALLOW]));
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

/// Combine mutiple computed effects in strict fashion. The result is `ALLOW` if
/// and only if there is at least one constituent effect and every consituent
/// effect is `ALLOW`. Any consituent silence will result in silence. If all
/// constituents are definite (and there is a least one), conbination works
/// the same as for non-strict wherein any consituent `DENY` results in `DENY`.
///
/// As with non-strict, if there are no constituents, the result is `SILENT`.
///
/// This function is used to combine effects for composite principals where a result
/// is determined for each atomic principal. In this case, access is authorized if
/// and only if access is authorized for each atomic principal. Silence is preserved
/// so the result can be further combined if needed.
///
/// A way to think about ths is by imagining a composite principal consisting of
/// a user and, say, an application. In order to allow an operation, both the user
/// and application must be authorized. However, if either the determination is
/// silent for either principal, we can consider the composite question of authorization
/// to be unmatched, i.e. SILENT.
///
/// If a final result is SILENT, then authorization is denied per the basic rule but
/// we return SILENCE so that the caller can understand the reason is that no
/// policy reads on the request rather than an expicit denial.
///
/// # Examples
///
/// ```
/// use authorization_core::effect::*;
///
/// // silence if no constituents
/// assert_eq!(SILENT, combine_strict(vec![]));
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
    #[allow(clippy::bool_assert_comparison)]
    fn test_authorized_definite_allow() {
        assert_eq!(ALLOW.authorized(), true);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_not_authorized_definite_deny() {
        assert_eq!(DENY.authorized(), false);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_not_authorized_silent() {
        assert_eq!(SILENT.authorized(), false);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_authorized_effect_allow() {
        assert_eq!(Effect::ALLOW.authorized(), true);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_unauthorized_effect_deny() {
        assert_eq!(Effect::DENY.authorized(), false);
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
        check(vec![ALLOW, SILENT, SILENT, ALLOW, SILENT], SILENT);
        check(vec![DENY, SILENT, SILENT, ALLOW, SILENT], SILENT);
    }
}
