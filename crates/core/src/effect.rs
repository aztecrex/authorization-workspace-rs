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
