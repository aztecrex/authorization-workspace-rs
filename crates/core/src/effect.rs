//! Authorization effects.
//!
//! Effects are the common expression of authorization with respect to a principal.
//!
//! This module defines two types of effects, definite and computed. Definit effects
//! are used in policy expressions to configure authority (or denial of authority)
//! under applicable conditions. A definit effect is one of two values, Allow or Deny.
//!
//! Computed effects are used to capture policy evaluation results and add an additiional
//! silence value to account for cases where a policy does not apply to conditions.
//!
//! This module also defines how to combine computed effects for a principal. The basic
//! combination rules are:
//!
//! 1. Deny combined with any other effect results in Deny
//! 2. Silence combined with any other effect results in the other effect.
//! 3. Allow combined with Allow results in Allow
//!
//! Combining policies is associative and commutative. Thus folding a sequence of computed
//! effects results in the same value irrespective of the order they are combined.
//!
//! Combing a sequence of effects requires two additional rules to cover degenerate cases:
//!
//! 1. An empty sequence results in Silence
//! 2. A singular sequence results in the value of the sole effect in the sequence
//!
//! This folding operation is captured in the FromIterator implementation of ComputedEffect and
//! thus an iterator of ComputedEffects can be 'collect'ed' into a single ComputedEffect.
//!

use std::borrow::Borrow;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
/// Definite authorization
pub enum Effect {
    /// Definitiely authorized.
    ALLOW,
    /// Definitel not authorized.
    DENY,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct ComputedEffect(Option<Effect>);

pub const SILENT: ComputedEffect = ComputedEffect(None);

pub const ALLOW: ComputedEffect = ComputedEffect(Some(Effect::ALLOW));

pub const DENY: ComputedEffect = ComputedEffect(Some(Effect::DENY));

impl ComputedEffect {
    pub fn effect(&self) -> Option<Effect> {
        self.0
    }
}

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
