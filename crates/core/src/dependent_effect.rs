//! Authorization effects that depend on environmental conditions

use super::effect::*;
use super::environment::*;

///  A dependent authorization effect. A dependent effect is evaluated in the context of
/// an environment to produce a `authorization_core::effect::ComputedEffect`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DependentEffect<CExp> {
    /// Unconditional silence. Resolves to `SILENT` in any environment.
    Silent,

    /// Unconditional effect. Resolves by applying `Effect::into()` to the wrapped
    /// value.
    Unconditional(Effect),

    /// Basic conditional effect. With respect to an environment, Resolves to `Some(Effect)` iff its condition
    /// evaluates to `Ok(Some(true))` in the environment.
    Conditional(Effect, CExp),

    /// Combines multiple effects for single principal. It is evaluated using
    /// `authorization_core::effect::combine_non_strict(_)`
    Composite(Vec<DependentEffect<CExp>>),

    /// Combines the effects of multiple principals. It is evaluated using
    /// `authorization_core::effect::combine_strict(_)`
    Strict(Vec<DependentEffect<CExp>>),
}

impl<CExp> DependentEffect<CExp> {
    /// Evaluate dependent effect in an envionmental context.
    pub fn resolve<Env>(&self, environment: &Env) -> ComputedEffect
    where
        Env: Environment<CExp = CExp>,
    {
        use DependentEffect::*;
        match self {
            Silent => SILENT,
            Conditional(eff, cexp) => {
                let applies = environment.evaluate(cexp);
                if applies {
                    Some(*eff).into()
                } else {
                    SILENT
                }
            }
            Unconditional(eff) => Some(*eff).into(),
            Composite(perms) => {
                let resolved: Vec<ComputedEffect> =
                    perms.iter().map(|p| p.resolve(environment)).collect();

                combine_non_strict(resolved)
            }
            Strict(effs) => {
                let resolved: Vec<ComputedEffect> =
                    effs.iter().map(|p| p.resolve(environment)).collect();

                combine_strict(resolved)
            }
        }
    }
}

pub fn resolve_all<'a, CExp: 'a, Env>(
    perms: impl Iterator<Item = &'a DependentEffect<CExp>>,
    environment: &Env,
) -> Vec<ComputedEffect>
where
    Env: Environment<CExp = CExp>,
{
    perms.map(|cexp| cexp.resolve(environment)).collect()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TestExpression {
        Match,
        Miss,
    }

    struct TestEnv;

    impl Environment for TestEnv {
        type CExp = TestExpression;

        fn evaluate(&self, exp: &Self::CExp) -> bool {
            use TestExpression::*;
            match exp {
                Match => true,
                Miss => false,
            }
        }
    }

    impl Environment for u32 {
        type CExp = u32;

        fn evaluate(&self, exp: &Self::CExp) -> bool {
            self == exp
        }
    }

    #[test]
    fn resolve_silent() {
        let perm = DependentEffect::Silent;

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, SILENT);
    }

    #[test]
    fn resolve_atomic_allow_match() {
        let perm = DependentEffect::Conditional(Effect::ALLOW, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, ALLOW);
    }

    #[test]
    fn resolve_atomic_deny_match() {
        let perm = DependentEffect::Conditional(Effect::DENY, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, DENY);
    }

    #[test]
    fn resolve_atomic_allow_miss() {
        let perm = DependentEffect::Conditional(Effect::ALLOW, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, SILENT);
    }

    #[test]
    fn resolve_atomic_deny_miss() {
        let perm = DependentEffect::Conditional(Effect::DENY, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, SILENT);
    }

    #[test]
    fn resolve_fixed_allow() {
        let perm = DependentEffect::<TestExpression>::Unconditional(Effect::ALLOW);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, ALLOW);
    }

    #[test]
    fn resolve_fixed_deny() {
        let perm = DependentEffect::<TestExpression>::Unconditional(Effect::DENY);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, DENY);
    }

    fn check_aggregate(config: Vec<DependentEffect<TestExpression>>) {
        let perm = DependentEffect::Composite(config.clone());

        let actual = perm.resolve(&TestEnv);

        let expect: Vec<ComputedEffect> = config.into_iter().map(|e| e.resolve(&TestEnv)).collect();
        let expect = combine_non_strict(expect);

        assert_eq!(actual, expect);
    }

    #[test]
    fn resolve_aggregate_empty() {
        check_aggregate(vec![]);
    }

    #[test]
    fn resolve_aggregate_single_allow() {
        check_aggregate(vec![DependentEffect::Unconditional(Effect::ALLOW)]);
    }

    #[test]
    fn resolve_aggregate_single_deny() {
        check_aggregate(vec![DependentEffect::Unconditional(Effect::DENY)]);
    }

    #[test]
    fn resolve_aggregate_single_silent() {
        check_aggregate(vec![DependentEffect::Silent]);
    }

    #[test]
    fn resolve_aggregate_all_allow() {
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
    }

    #[test]
    fn resolve_aggregate_deny_priority() {
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::DENY),
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::DENY),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::DENY),
        ]);
    }

    #[test]
    fn resolve_aggregate_silence_ignored() {
        check_aggregate(vec![
            DependentEffect::Silent,
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Silent,
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Silent,
        ]);
        check_aggregate(vec![
            DependentEffect::Silent,
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::DENY),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Silent,
            DependentEffect::Unconditional(Effect::DENY),
            DependentEffect::Unconditional(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Unconditional(Effect::DENY),
            DependentEffect::Unconditional(Effect::ALLOW),
            DependentEffect::Silent,
        ]);
    }

    #[test]
    fn test_nested_condition() {
        use DependentEffect::*;

        let perm = Composite(vec![
            Conditional(Effect::DENY, 1u32),
            Conditional(Effect::DENY, 2u32),
            Composite(vec![
                Conditional(Effect::DENY, 3u32),
                Conditional(Effect::ALLOW, 4u32),
            ]),
        ]);

        let actual = perm.resolve(&3u32);
        assert_eq!(actual, DENY);

        let actual = perm.resolve(&4u32);
        assert_eq!(actual, ALLOW);

        let actual = perm.resolve(&100u32);
        assert_eq!(actual, SILENT);
    }

    #[test]
    fn test_resolve_all() {
        use DependentEffect::*;

        let perms = vec![
            Conditional(Effect::ALLOW, 1u32),
            Conditional(Effect::ALLOW, 2u32),
            Conditional(Effect::DENY, 1u32),
            Conditional(Effect::DENY, 2u32),
            Unconditional(Effect::ALLOW),
            Unconditional(Effect::DENY),
            Silent,
            Composite(vec![
                Conditional(Effect::ALLOW, 1u32),
                Conditional(Effect::DENY, 2u32),
            ]),
        ];

        let actual = resolve_all(perms.iter(), &1);
        assert_eq!(
            actual,
            vec![ALLOW, SILENT, DENY, SILENT, ALLOW, DENY, SILENT, ALLOW,]
        );

        let actual = resolve_all(perms.iter(), &2);
        assert_eq!(
            actual,
            vec![SILENT, ALLOW, SILENT, DENY, ALLOW, DENY, SILENT, DENY,]
        );
    }

    #[test]
    fn test_resolve_disjoint_empty() {
        let effect = DependentEffect::Strict(vec![]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, SILENT)
    }

    #[test]
    fn test_resolve_disjoint_all_silent() {
        let effect =
            DependentEffect::Strict(vec![DependentEffect::Silent, DependentEffect::Silent]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, SILENT)
    }

    // #[test]
    // fn test_resolve_disjoint() {
    //     use DependentEffect::*;

    //     fn check<I>(effs: I)
    //     where
    //         I: IntoIterator<Item = DependentEffect<TestExpression>> + Clone,
    //     {
    //         let eff = DependentEffect::Strict(effs.clone().into_iter().collect());

    //         let actual = eff.resolve(&TestEnv);

    //         let expected: Vec<ComputedEffect> =
    //             effs.into_iter().map(|e| e.resolve(&TestEnv)).collect();
    //         let expected = combine_strict(expected);

    //         assert_eq!(actual, expected);
    //     }

    //     check(vec![Silent, Unconditional(Effect::ALLOW)]);
    //     check(vec![Unconditional(Effect::ALLOW), Silent]);
    //     check(vec![
    //         Unconditional(Effect::ALLOW),
    //         Unconditional(Effect::ALLOW),
    //     ]);
    //     check(vec![
    //         Unconditional(Effect::ALLOW),
    //         Unconditional(Effect::DENY),
    //     ]);
    //     check(vec![
    //         Unconditional(Effect::DENY),
    //         Unconditional(Effect::ALLOW),
    //     ]);
    //     check(vec![Unconditional(Effect::DENY), Silent]);
    //     check(vec![Silent, Unconditional(Effect::DENY)]);
    //     check(vec![Conditional(Effect::ALLOW, TestExpression::Match)]);
    //     check(vec![Conditional(Effect::DENY, TestExpression::Match)]);
    //     check(vec![
    //         Conditional(Effect::DENY, TestExpression::Miss),
    //         Unconditional(Effect::ALLOW),
    //     ]);
    //     check(vec![
    //         Conditional(Effect::ALLOW, TestExpression::Miss),
    //         Unconditional(Effect::DENY),
    //     ]);
    //     check(vec![
    //         Conditional(Effect::ALLOW, TestExpression::Match),
    //         Conditional(Effect::DENY, TestExpression::Miss),
    //     ]);
    //     check(vec![
    //         Conditional(Effect::ALLOW, TestExpression::Match),
    //         Conditional(Effect::DENY, TestExpression::Match),
    //     ]);
    //     check(vec![
    //         Conditional(Effect::ALLOW, TestExpression::Match),
    //         Conditional(Effect::ALLOW, TestExpression::Match),
    //     ]);
    //     check(vec![
    //         Unconditional(Effect::ALLOW),
    //         Conditional(Effect::ALLOW, TestExpression::Miss),
    //         Unconditional(Effect::ALLOW),
    //     ]);
    // }
}
