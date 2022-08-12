//! Authorization effects.
//!
//! Effects are the common expression of authorization with respect to a principal.
//!
//! This module defines two types of effects, [definite](Effect) and [computed](ComputedEffect).
//! Definite effects are used in policy expressions to configure authority (or denial of authority)
//! under applicable conditions. A definite effect is one of two values, [allow](Effect::ALLOW) or
//! [deny](Effect::DENY).
//!
//! Computed effects are used to capture policy evaluation results and add an additiional
//! [silence](SILENT) value resulting from cases where a configured policy does not apply under conditions.
//!
//! This module also defines how to combine [computed effects](ComputedEffect) for a principal.
//! The basic combination rules are:
//!
//! 1. Deny combined with any other effect results in Deny
//! 1. Silence combined with any other effect results in the other effect.
//! 1. Allow combined with Allow results in Allow
//!
//! Combining policies is associative and commutative. Thus folding a sequence of computed
//! effects results in the same value irrespective of the order they are combined.
//!
//! Combing a sequence of effects requires two additional rules to cover degenerate cases:
//!
//! 1. An empty sequence results in [silence](SILENT)
//! 1. A singular sequence results in the value of the sole effect in the sequence
//!
//! This folding operation is captured in the FromIterator implementation of ComputedEffect and
//! thus an iterator of ComputedEffects can be 'collect'ed' into a single ComputedEffect.
//!

use std::borrow::Borrow;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
/// Definite authorization.
pub enum Effect {
    /// Definitiely authorized.
    ALLOW,
    /// Definitely not authorized.
    DENY,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
/// Effected computed from a policy evaluation. Adds an additional value representing that a policy
/// evalutation does not apply under given conditions.
pub struct ComputedEffect(Option<Effect>);

/// Evaluated configuration does not apply under given conditions.
pub const SILENT: ComputedEffect = ComputedEffect(None);

/// Evaluated configuration definitely allows under given conditions.
pub const ALLOW: ComputedEffect = ComputedEffect(Some(Effect::ALLOW));

/// Evaluated configuration definitely denies under given conditions.
pub const DENY: ComputedEffect = ComputedEffect(Some(Effect::DENY));

impl ComputedEffect {
    pub fn effect(&self) -> Option<Effect> {
        self.0
    }
}

impl<E> From<E> for ComputedEffect
where
    E: Borrow<Effect>,
{
    fn from(effect: E) -> Self {
        match effect.borrow() {
            Effect::ALLOW => ALLOW,
            Effect::DENY => DENY,
        }
    }
}

impl Into<Option<Effect>> for &ComputedEffect {
    fn into(self) -> Option<Effect> {
        self.0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_computed() {
        fn check<const N: usize>(effs: [ComputedEffect; N], expected: ComputedEffect) {
            assert_eq!(effs.iter().collect::<ComputedEffect>(), expected);
        }

        check([DENY], DENY);
        check([ALLOW], ALLOW);
        check([SILENT], SILENT);

        check([DENY, DENY], DENY);
        check([DENY, ALLOW], DENY);
        check([DENY, SILENT], DENY);

        check([ALLOW, DENY], DENY);
        check([ALLOW, ALLOW], ALLOW);
        check([ALLOW, SILENT], ALLOW);

        check([SILENT, DENY], DENY);
        check([SILENT, ALLOW], ALLOW);
        check([SILENT, SILENT], SILENT);

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
}
