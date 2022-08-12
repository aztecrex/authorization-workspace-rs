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

use std::borrow::Borrow;

/// Compute authorization for an effect.
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
pub trait Authorized {
    fn authorized(&self) -> bool;
}

pub trait Silent {
    fn silent(&self) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
/// Definite authorization
pub enum Effect {
    /// Definitiely authorized.
    ALLOW,
    /// Definitel not authorized.
    DENY,
}

impl Authorized for Effect {
    fn authorized(&self) -> bool {
        *self == Effect::ALLOW
    }
}

impl Silent for Effect {
    fn silent(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct ComputedEffect(Option<Effect>);

pub const SILENT: ComputedEffect = ComputedEffect(None);

pub const ALLOW: ComputedEffect = ComputedEffect(Some(Effect::ALLOW));

pub const DENY: ComputedEffect = ComputedEffect(Some(Effect::DENY));

impl From<Effect> for ComputedEffect {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::ALLOW => ALLOW,
            Effect::DENY => DENY,
        }
    }
}

impl From<&Effect> for ComputedEffect {
    fn from(permission: &Effect) -> Self {
        ComputedEffect::from(*permission)
    }
}

impl Authorized for ComputedEffect {
    fn authorized(&self) -> bool {
        *self == ALLOW
    }
}

impl Silent for ComputedEffect {
    fn silent(&self) -> bool {
        *self == SILENT
    }
}

impl<E> FromIterator<E> for ComputedEffect
where
    E: Borrow<ComputedEffect>,
{
    fn from_iter<T: IntoIterator<Item = E>>(items: T) -> Self {
        items
            .into_iter()
            .fold(SILENT, |acc, effect| match (acc, *effect.borrow()) {
                (SILENT, x) | (x, SILENT) => x,
                (DENY, ComputedEffect(Some(_))) | (ALLOW, DENY) => DENY,
                (ALLOW, ALLOW) => ALLOW,
            })
    }
}

// / Combine mutiple computed effects in strict fashion. The result is `ALLOW` if
// / and only if there is at least one constituent effect and every consituent
// / effect is `ALLOW`. Any consituent silence will result in silence. If all
// / constituents are definite (and there is a least one), conbination works
// / the same as for non-strict wherein any consituent `DENY` results in `DENY`.
// /
// / As with non-strict, if there are no constituents, the result is `SILENT`.
// /
// / This function is used to combine effects for composite principals where a result
// / is determined for each atomic principal. In this case, access is authorized if
// / and only if access is authorized for each atomic principal. Silence is preserved
// / so the result can be further combined if needed.
// /
// / A way to think about ths is by imagining a composite principal consisting of
// / a user and, say, an application. In order to allow an operation, both the user
// / and application must be authorized. However, if either the determination is
// / silent for either principal, we can consider the composite question of authorization
// / to be unmatched, i.e. SILENT.
// /
// / If a final result is SILENT, then authorization is denied per the basic rule but
// / we return SILENCE so that the caller can understand the reason is that no
// / policy reads on the request rather than an expicit denial.
// /
// fn combine_strict<I>(effs: I) -> ComputedEffect
// where
//     I: IntoIterator<Item = ComputedEffect>,
// {
//     effs.into_iter()
//         .fold(None, |a, e| match (a, e) {
//             (None, x) => Some(x),
//             (Some(SILENT), _) => Some(SILENT),
//             (_, SILENT) => Some(SILENT),
//             (Some(ALLOW), ALLOW) => Some(ALLOW),
//             _ => Some(DENY),
//         })
//         .unwrap_or(SILENT)
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_computed_allow_authorized() {
        assert!(ALLOW.authorized());
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)]
    fn test_computed_allow_not_silent() {
        assert!(!ALLOW.silent());
    }

    #[test]
    fn test_computed_deny_not_authorized() {
        assert!(!DENY.authorized());
    }

    #[test]
    fn test_computed_deny_not_silent() {
        assert!(!DENY.silent());
    }

    #[test]
    fn test_computed_silent_not_authorized() {
        assert!(!SILENT.authorized());
    }

    #[test]
    fn test_computed_silent_silent() {
        assert!(SILENT.silent());
    }

    #[test]
    fn test_effect_allow_authorized() {
        assert!(Effect::ALLOW.authorized());
    }

    #[test]
    fn test_effect_deny_not_authorized() {
        assert!(!Effect::DENY.authorized());
    }

    #[test]
    fn test_effect_allow_not_silent() {
        assert!(!Effect::ALLOW.silent());
    }

    #[test]
    fn test_effect_deny_not_silent() {
        assert!(!Effect::DENY.silent());
    }

    #[test]
    fn collect_computed() {
        fn check<const N: usize>(effs: [ComputedEffect; N], expected: ComputedEffect) {
            assert_eq!(effs.iter().collect::<ComputedEffect>(), expected);
        }

        check([DENY, DENY, DENY], DENY);

        check([DENY, DENY, DENY], DENY);
        check([DENY, DENY, ALLOW], DENY);
        check([DENY, ALLOW, DENY], DENY);
        check([DENY, ALLOW, ALLOW], DENY);
        check([ALLOW, DENY, DENY], DENY);
        check([ALLOW, DENY, ALLOW], DENY);
        check([ALLOW, ALLOW, DENY], DENY);

        check([ALLOW, ALLOW, ALLOW], ALLOW);

        check([], SILENT);
        check([SILENT, SILENT], SILENT);

        check([SILENT, DENY, SILENT, DENY, SILENT], DENY);
        check([SILENT, DENY, SILENT, ALLOW, SILENT], DENY);
        check([SILENT, ALLOW, SILENT, ALLOW, SILENT], ALLOW);
    }

    // #[test]
    // fn test_combine_strict() {
    //     fn check<I>(effs: I, expected: ComputedEffect)
    //     where
    //         I: IntoIterator<Item = ComputedEffect>,
    //     {
    //         assert_eq!(combine_strict(effs), expected);
    //     }

    //     check(vec![DENY, DENY, DENY], DENY);
    //     check(vec![DENY, DENY, ALLOW], DENY);
    //     check(vec![DENY, ALLOW, DENY], DENY);
    //     check(vec![DENY, ALLOW, ALLOW], DENY);
    //     check(vec![ALLOW, DENY, DENY], DENY);
    //     check(vec![ALLOW, DENY, ALLOW], DENY);
    //     check(vec![ALLOW, ALLOW, DENY], DENY);

    //     check(vec![ALLOW, ALLOW, ALLOW], ALLOW);

    //     check(vec![], SILENT);
    //     check(vec![SILENT, SILENT], SILENT);
    //     check(vec![SILENT, DENY, SILENT, DENY, SILENT], SILENT);
    //     check(vec![SILENT, DENY, SILENT, ALLOW, SILENT], SILENT);
    //     check(vec![SILENT, ALLOW, SILENT, ALLOW, SILENT], SILENT);
    //     check(vec![ALLOW, SILENT, SILENT, ALLOW, SILENT], SILENT);
    //     check(vec![DENY, SILENT, SILENT, ALLOW, SILENT], SILENT);
    // }

    // #[test]
    // fn composite_authorized() {
    //     fn check<const N: usize>(effs: [ComputedEffect; N]) {
    //         let expected = combine_strict(effs).authorized();
    //         let effect: CompositeEffect<N> = effs.into();
    //         let actual = effect.authorized();
    //         assert_eq!(actual, expected);
    //     }

    //     check([DENY, DENY, DENY]);
    //     check([DENY, DENY, ALLOW]);
    //     check([DENY, ALLOW, DENY]);
    //     check([DENY, ALLOW, ALLOW]);
    //     check([ALLOW, DENY, DENY]);
    //     check([ALLOW, DENY, ALLOW]);
    //     check([ALLOW, ALLOW, DENY]);

    //     check([ALLOW, ALLOW, ALLOW]);

    //     check([]);
    //     check([SILENT, SILENT]);
    //     check([SILENT, DENY, SILENT, DENY, SILENT]);
    //     check([SILENT, DENY, SILENT, ALLOW, SILENT]);
    //     check([SILENT, ALLOW, SILENT, ALLOW, SILENT]);
    //     check([ALLOW, SILENT, SILENT, ALLOW, SILENT]);
    //     check([DENY, SILENT, SILENT, ALLOW, SILENT]);
    // }
}
