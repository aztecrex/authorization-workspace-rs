//! Effects that depend on environmental conditions

use super::effect::*;
use super::environment::*;

///  A dependent authorization. An effect is evaluated in the context of
/// an environment to produce a `authorization_core::effect::ComputedEffect`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DependentEffect<CExp> {
    /// Unconditional silence. Resolves to `SILENT` in any environment.
    Silent,

    /// Unconditional effect. Resolves by applying `Effect::into()` to the wrapped
    /// value.
    Fixed(Effect),

    /// Basic conditional effect. With respect to an environment, Resolves to `Some(Effect)` iff its condition
    /// evaluates to `Ok(Some(true))` in the environment.
    Atomic(Effect, CExp),
    /// Combines multiple effects for  single principal. It is evaluated using
    /// `authorization_core::effect::combine_non_strict(_)`
    Aggregate(Vec<DependentEffect<CExp>>),
    /// Combines the effects of multiple principals. It is evaluated using
    /// `authorization_core::effect::combine_strict(_)`
    Disjoint(Vec<DependentEffect<CExp>>),
}

impl<CExp> DependentEffect<CExp> {
    /// Evaluate dependent effect in an envionmental context.
    pub fn resolve<Env>(&self, environment: &Env) -> Result<ComputedEffect, Env::Err>
    where
        Env: Environment<CExp = CExp>,
    {
        use DependentEffect::*;
        match self {
            Silent => Ok(SILENT),
            Atomic(eff, cexp) => {
                let matched = environment.test_condition(cexp)?;
                if matched {
                    Ok(Some(*eff).into())
                } else {
                    Ok(SILENT)
                }
            }
            Fixed(eff) => Ok(Some(*eff).into()),
            Aggregate(perms) => {
                let resolved: Result<Vec<ComputedEffect>, Env::Err> =
                    perms.iter().map(|p| p.resolve(environment)).collect();
                let resolved = resolved?;
                let resolved = combine_non_strict(resolved);
                Ok(resolved)
            }
            Disjoint(effs) => {
                let resolved: Result<Vec<ComputedEffect>, Env::Err> =
                    effs.into_iter().map(|p| p.resolve(environment)).collect();
                let resolved = resolved?;
                let resolved = combine_strict(resolved);

                Ok(resolved)
            }
        }
    }
}

pub fn resolve_all<'a, CExp: 'a, Env>(
    perms: impl Iterator<Item = &'a DependentEffect<CExp>>,
    environment: &Env,
) -> Result<Vec<ComputedEffect>, Env::Err>
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
        Error,
    }

    struct TestEnv;

    impl Environment for TestEnv {
        type Err = ();
        type CExp = TestExpression;

        fn test_condition(&self, exp: &Self::CExp) -> Result<bool, Self::Err> {
            use TestExpression::*;
            match exp {
                Match => Ok(true),
                Miss => Ok(false),
                Error => Err(()),
            }
        }
    }

    impl Environment for u32 {
        type Err = ();
        type CExp = u32;

        fn test_condition(&self, exp: &Self::CExp) -> Result<bool, Self::Err> {
            Ok(self == exp)
        }
    }

    #[test]
    fn resolve_silent() {
        let perm = DependentEffect::Silent;

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(SILENT));
    }

    #[test]
    fn resolve_atomic_allow_match() {
        let perm = DependentEffect::Atomic(Effect::ALLOW, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(ALLOW));
    }

    #[test]
    fn resolve_atomic_deny_match() {
        let perm = DependentEffect::Atomic(Effect::DENY, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(DENY));
    }

    #[test]
    fn resolve_atomic_allow_miss() {
        let perm = DependentEffect::Atomic(Effect::ALLOW, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(SILENT));
    }

    #[test]
    fn resolve_atomic_deny_miss() {
        let perm = DependentEffect::Atomic(Effect::DENY, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(SILENT));
    }

    #[test]
    fn resolve_atomic_error() {
        let perm = DependentEffect::Atomic(Effect::ALLOW, TestExpression::Error);

        let actual = perm.resolve(&TestEnv);

        assert!(actual.is_err());
        assert_eq!(
            actual.unwrap_err(),
            TestEnv.test_condition(&TestExpression::Error).unwrap_err()
        );
    }

    #[test]
    fn resolve_fixed_allow() {
        let perm = DependentEffect::<TestExpression>::Fixed(Effect::ALLOW);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(ALLOW));
    }

    #[test]
    fn resolve_fixed_deny() {
        let perm = DependentEffect::<TestExpression>::Fixed(Effect::DENY);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(DENY));
    }

    fn check_aggregate(config: Vec<DependentEffect<TestExpression>>) {
        let perm = DependentEffect::Aggregate(config.clone());

        let actual = perm.resolve(&TestEnv);

        let expect: Result<Vec<ComputedEffect>, ()> =
            config.into_iter().map(|e| e.resolve(&TestEnv)).collect();
        let expect = expect.map(combine_non_strict);

        assert_eq!(actual, expect);
    }

    #[test]
    fn resolve_aggregate_empty() {
        check_aggregate(vec![]);
    }

    #[test]
    fn resolve_aggregate_single_allow() {
        check_aggregate(vec![DependentEffect::Fixed(Effect::ALLOW)]);
    }

    #[test]
    fn resolve_aggregate_single_deny() {
        check_aggregate(vec![DependentEffect::Fixed(Effect::DENY)]);
    }

    #[test]
    fn resolve_aggregate_single_silent() {
        check_aggregate(vec![DependentEffect::Silent]);
    }

    #[test]
    fn resolve_aggregate_all_allow() {
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
    }

    #[test]
    fn resolve_aggregate_deny_priority() {
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::DENY),
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::DENY),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::DENY),
        ]);
    }

    #[test]
    fn resolve_aggregate_silence_ignored() {
        check_aggregate(vec![
            DependentEffect::Silent,
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Silent,
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Silent,
        ]);
        check_aggregate(vec![
            DependentEffect::Silent,
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::DENY),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Silent,
            DependentEffect::Fixed(Effect::DENY),
            DependentEffect::Fixed(Effect::ALLOW),
        ]);
        check_aggregate(vec![
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Fixed(Effect::DENY),
            DependentEffect::Fixed(Effect::ALLOW),
            DependentEffect::Silent,
        ]);
    }

    #[test]
    fn test_nested_condition() {
        use DependentEffect::*;

        let perm = Aggregate(vec![
            Atomic(Effect::DENY, 1u32),
            Atomic(Effect::DENY, 2u32),
            Aggregate(vec![
                Atomic(Effect::DENY, 3u32),
                Atomic(Effect::ALLOW, 4u32),
            ]),
        ]);

        let actual = perm.resolve(&3u32);
        assert_eq!(actual, Ok(DENY));

        let actual = perm.resolve(&4u32);
        assert_eq!(actual, Ok(ALLOW));

        let actual = perm.resolve(&100u32);
        assert_eq!(actual, Ok(SILENT));
    }

    #[test]
    fn test_resolve_all() {
        use DependentEffect::*;

        let perms = vec![
            Atomic(Effect::ALLOW, 1u32),
            Atomic(Effect::ALLOW, 2u32),
            Atomic(Effect::DENY, 1u32),
            Atomic(Effect::DENY, 2u32),
            Fixed(Effect::ALLOW),
            Fixed(Effect::DENY),
            Silent,
            Aggregate(vec![
                Atomic(Effect::ALLOW, 1u32),
                Atomic(Effect::DENY, 2u32),
            ]),
        ];

        let actual = resolve_all(perms.iter(), &1);
        assert_eq!(
            actual,
            Ok(vec![
                ALLOW, SILENT, DENY, SILENT, ALLOW, DENY, SILENT, ALLOW,
            ])
        );

        let actual = resolve_all(perms.iter(), &2);
        assert_eq!(
            actual,
            Ok(vec![SILENT, ALLOW, SILENT, DENY, ALLOW, DENY, SILENT, DENY,])
        );
    }

    #[test]
    fn test_resolve_all_err() {
        use DependentEffect::*;

        let perms = vec![
            Fixed(Effect::ALLOW),
            Fixed(Effect::DENY),
            Silent,
            Aggregate(vec![
                Fixed(Effect::ALLOW),
                Atomic(Effect::ALLOW, TestExpression::Error),
                Fixed(Effect::DENY),
            ]),
        ];

        let actual = resolve_all(perms.iter(), &TestEnv);

        assert_eq!(actual, Err(()));
    }

    #[test]
    fn test_resolve_disjoint_empty() {
        let effect = DependentEffect::Disjoint(vec![]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Ok(SILENT))
    }

    #[test]
    fn test_resolve_disjoint_all_silent() {
        let effect =
            DependentEffect::Disjoint(vec![DependentEffect::Silent, DependentEffect::Silent]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Ok(SILENT))
    }

    #[test]
    fn test_resolve_disjoint_error() {
        use DependentEffect::*;
        let effect = DependentEffect::Disjoint(vec![
            Fixed(Effect::ALLOW),
            Atomic(Effect::ALLOW, TestExpression::Error),
        ]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Err(()));
    }

    #[test]
    fn test_resolve_disjoint() {
        use DependentEffect::*;

        fn check<I>(effs: I)
        where
            I: IntoIterator<Item = DependentEffect<TestExpression>> + Clone,
        {
            let eff = DependentEffect::Disjoint(effs.clone().into_iter().collect());

            let actual = eff.resolve(&TestEnv);

            let expected: Result<Vec<ComputedEffect>, ()> =
                effs.into_iter().map(|e| e.resolve(&TestEnv)).collect();
            let expected = expected.map(combine_strict);

            assert_eq!(actual, expected);
        }

        check(vec![Silent, Fixed(Effect::ALLOW)]);
        check(vec![Fixed(Effect::ALLOW), Silent]);
        check(vec![Fixed(Effect::ALLOW), Fixed(Effect::ALLOW)]);
        check(vec![Fixed(Effect::ALLOW), Fixed(Effect::DENY)]);
        check(vec![Fixed(Effect::DENY), Fixed(Effect::ALLOW)]);
        check(vec![Fixed(Effect::DENY), Silent]);
        check(vec![Silent, Fixed(Effect::DENY)]);
        check(vec![Atomic(Effect::ALLOW, TestExpression::Match)]);
        check(vec![Atomic(Effect::DENY, TestExpression::Match)]);
        check(vec![
            Atomic(Effect::DENY, TestExpression::Miss),
            Fixed(Effect::ALLOW),
        ]);
        check(vec![
            Atomic(Effect::ALLOW, TestExpression::Miss),
            Fixed(Effect::DENY),
        ]);
        check(vec![
            Atomic(Effect::ALLOW, TestExpression::Match),
            Atomic(Effect::DENY, TestExpression::Miss),
        ]);
        check(vec![
            Atomic(Effect::ALLOW, TestExpression::Match),
            Atomic(Effect::DENY, TestExpression::Match),
        ]);
        check(vec![
            Atomic(Effect::ALLOW, TestExpression::Match),
            Atomic(Effect::ALLOW, TestExpression::Match),
        ]);
        check(vec![
            Fixed(Effect::ALLOW),
            Atomic(Effect::ALLOW, TestExpression::Miss),
            Fixed(Effect::ALLOW),
        ]);
    }
}
