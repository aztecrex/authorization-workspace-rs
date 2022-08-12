//! Temporary catch-all module for authorization wrt to a principal. i.e. how to interpret
//! results from policy evaluation.
//!
//! Capture the ideas around determinig authorization deciding whether to allow access
//! Can put initial ideas for federation and other autyhority-combining mechanisms here

use crate::effect::*;

pub trait Authorized {
    fn authorized(&self) -> bool;
}

impl Authorized for Effect {
    fn authorized(&self) -> bool {
        *self == Effect::ALLOW
    }
}

impl Authorized for ComputedEffect {
    fn authorized(&self) -> bool {
        *self == ALLOW
    }
}

pub trait Silent {
    fn silent(&self) -> bool;
}

impl Silent for Effect {
    fn silent(&self) -> bool {
        false
    }
}

impl Silent for ComputedEffect {
    fn silent(&self) -> bool {
        *self == SILENT
    }
}

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
    // fn test_disjoint() {
    //     let Matchers { m_r, m_a, miss, .. } = Matchers::new();

    //     let policies = vec![
    //         Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
    //         Policy::Conditional(m_r, m_a, Effect::DENY, 19),
    //         Policy::Unconditional(m_r, m_a, Effect::ALLOW),
    //         Policy::Unconditional(m_r, m_a, Effect::DENY),
    //         Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
    //         Policy::Conditional(miss, m_a, Effect::DENY, 21),
    //         Policy::Unconditional(miss, m_a, Effect::ALLOW),
    //         Policy::Unconditional(m_r, miss, Effect::DENY),
    //         Policy::Complex(vec![Policy::Complex(vec![
    //             Policy::Conditional(m_r, m_a, Effect::ALLOW, 18),
    //             Policy::Conditional(m_r, m_a, Effect::DENY, 19),
    //             Policy::Unconditional(m_r, m_a, Effect::ALLOW),
    //             Policy::Unconditional(m_r, m_a, Effect::DENY),
    //             Policy::Conditional(m_r, miss, Effect::ALLOW, 20),
    //             Policy::Conditional(miss, m_a, Effect::DENY, 21),
    //             Policy::Unconditional(miss, m_a, Effect::ALLOW),
    //             Policy::Unconditional(m_r, miss, Effect::DENY),
    //         ])]),
    //     ];
    //     let r = "r";
    //     let a = "a";

    //     let actual = apply_disjoint(policies.clone(), &r, &a);

    //     let expected = DependentEffect::Strict(
    //         policies
    //             .iter()
    //             .map(|p| p.clone().apply(&"r", &"a"))
    //             .collect(),
    //     );
    //     assert_eq!(actual, expected);
    // }
}
