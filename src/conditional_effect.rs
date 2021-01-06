//! Effects that depend on environmental conditions

use super::authorization::*;
use super::condition::*;

/// With respect to an environment, a conditional effect applies
/// if and only if its condition is true in the environment.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConditionalEffect<CExp> {
    /// Unconditional silence. Resolves to `None` in any environment.
    Silent,
    /// Unconditional effect. Resolves to `Some(Effect)` in any environment.
    Fixed(Effect),
    /// Basic conditional effect. With respect to an environment, Resolves to `Some(Effect)` iff its condition
    /// evaluates to `Ok(Some(true))` in the environment.
    Atomic(Effect, CExp),
    /// Multiple policy aggregate. It resolves by resolving then folding its constituents
    /// according to `effect::resolve
    Aggregate(Vec<ConditionalEffect<CExp>>),
    Disjoint(Vec<ConditionalEffect<CExp>>),
}

impl<CExp> ConditionalEffect<CExp> {
    pub fn resolve<Env>(&self, environment: &Env) -> Result<Option<Effect>, Env::Err>
    where
        Env: Environment<CExp = CExp>,
    {
        use ConditionalEffect::*;
        match self {
            Silent => Ok(None),
            Atomic(perm, cexp) => {
                let matched = environment.test_condition(cexp)?;
                if matched {
                    Ok(Some(*perm))
                } else {
                    Ok(None)
                }
            }
            Fixed(perm) => Ok(Some(*perm)),
            Aggregate(perms) => {
                let resolved: Result<Vec<Option<Effect>>, Env::Err> =
                    perms.iter().map(|p| p.resolve(environment)).collect();
                let resolved = resolved?;
                let resolved = combine_non_strict(resolved);
                Ok(resolved)
            }
            Disjoint(effs) => {
                let resolved: Result<Vec<Option<Effect>>, Env::Err> =
                    effs.into_iter().map(|p| p.resolve(environment)).collect();
                let resolved = resolved?;
                let resolved = combine_strict(resolved);

                Ok(resolved)
            }
        }
    }
}

pub fn resolve_all<'a, CExp: 'a, Env>(
    perms: impl Iterator<Item = &'a ConditionalEffect<CExp>>,
    environment: &Env,
) -> Result<Vec<Option<Effect>>, Env::Err>
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

    use Effect::*;

    #[test]
    fn resolve_silent() {
        let perm = ConditionalEffect::Silent;

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_allow_match() {
        let perm = ConditionalEffect::Atomic(Effect::ALLOW, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Effect::ALLOW)));
    }

    #[test]
    fn resolve_atomic_deny_match() {
        let perm = ConditionalEffect::Atomic(Effect::DENY, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Effect::DENY)));
    }

    #[test]
    fn resolve_atomic_allow_miss() {
        let perm = ConditionalEffect::Atomic(Effect::ALLOW, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_deny_miss() {
        let perm = ConditionalEffect::Atomic(Effect::DENY, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_error() {
        let perm = ConditionalEffect::Atomic(Effect::ALLOW, TestExpression::Error);

        let actual = perm.resolve(&TestEnv);

        assert!(actual.is_err());
        assert_eq!(
            actual.unwrap_err(),
            TestEnv.test_condition(&TestExpression::Error).unwrap_err()
        );
    }

    #[test]
    fn resolve_fixed_allow() {
        let perm = ConditionalEffect::<TestExpression>::Fixed(ALLOW);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(ALLOW)));
    }

    #[test]
    fn resolve_fixed_deny() {
        let perm = ConditionalEffect::<TestExpression>::Fixed(DENY);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(DENY)));
    }

    fn check_aggregate(config: Vec<ConditionalEffect<TestExpression>>) {
        let perm = ConditionalEffect::Aggregate(config.clone());

        let actual = perm.resolve(&TestEnv);

        let expect: Result<Vec<Option<Effect>>, ()> =
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
        check_aggregate(vec![ConditionalEffect::Fixed(ALLOW)]);
    }

    #[test]
    fn resolve_aggregate_single_deny() {
        check_aggregate(vec![ConditionalEffect::Fixed(DENY)]);
    }

    #[test]
    fn resolve_aggregate_single_silent() {
        check_aggregate(vec![ConditionalEffect::Silent]);
    }

    #[test]
    fn resolve_aggregate_all_allow() {
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
        ]);
    }

    #[test]
    fn resolve_aggregate_deny_priority() {
        check_aggregate(vec![
            ConditionalEffect::Fixed(DENY),
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(DENY),
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(DENY),
        ]);
    }

    #[test]
    fn resolve_aggregate_silence_ignored() {
        check_aggregate(vec![
            ConditionalEffect::Silent,
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Silent,
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Silent,
        ]);
        check_aggregate(vec![
            ConditionalEffect::Silent,
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(DENY),
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Silent,
            ConditionalEffect::Fixed(DENY),
            ConditionalEffect::Fixed(ALLOW),
        ]);
        check_aggregate(vec![
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Fixed(DENY),
            ConditionalEffect::Fixed(ALLOW),
            ConditionalEffect::Silent,
        ]);
    }

    #[test]
    fn test_nested_condition() {
        use ConditionalEffect::*;

        let perm = Aggregate(vec![
            Atomic(DENY, 1u32),
            Atomic(DENY, 2u32),
            Aggregate(vec![Atomic(DENY, 3u32), Atomic(ALLOW, 4u32)]),
        ]);

        let actual = perm.resolve(&3u32);
        assert_eq!(actual, Ok(Some(DENY)));

        let actual = perm.resolve(&4u32);
        assert_eq!(actual, Ok(Some(ALLOW)));

        let actual = perm.resolve(&100u32);
        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn test_resolve_all() {
        use ConditionalEffect::*;

        let perms = vec![
            Atomic(ALLOW, 1u32),
            Atomic(ALLOW, 2u32),
            Atomic(DENY, 1u32),
            Atomic(DENY, 2u32),
            Fixed(ALLOW),
            Fixed(DENY),
            Silent,
            Aggregate(vec![Atomic(ALLOW, 1u32), Atomic(DENY, 2u32)]),
        ];

        let actual = resolve_all(perms.iter(), &1);
        assert_eq!(
            actual,
            Ok(vec![
                Some(ALLOW),
                None,
                Some(DENY),
                None,
                Some(ALLOW),
                Some(DENY),
                None,
                Some(ALLOW),
            ])
        );

        let actual = resolve_all(perms.iter(), &2);
        assert_eq!(
            actual,
            Ok(vec![
                None,
                Some(ALLOW),
                None,
                Some(DENY),
                Some(ALLOW),
                Some(DENY),
                None,
                Some(DENY),
            ])
        );
    }

    #[test]
    fn test_resolve_all_err() {
        use ConditionalEffect::*;

        let perms = vec![
            Fixed(ALLOW),
            Fixed(DENY),
            Silent,
            Aggregate(vec![
                Fixed(ALLOW),
                Atomic(ALLOW, TestExpression::Error),
                Fixed(DENY),
            ]),
        ];

        let actual = resolve_all(perms.iter(), &TestEnv);

        assert_eq!(actual, Err(()));
    }

    #[test]
    fn test_resolve_disjoint_empty() {
        let effect = ConditionalEffect::Disjoint(vec![]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Ok(None))
    }

    #[test]
    fn test_resolve_disjoint_all_silent() {
        let effect =
            ConditionalEffect::Disjoint(vec![ConditionalEffect::Silent, ConditionalEffect::Silent]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Ok(None))
    }

    #[test]
    fn test_resolve_disjoint_error() {
        use ConditionalEffect::*;
        let effect =
            ConditionalEffect::Disjoint(vec![Fixed(ALLOW), Atomic(ALLOW, TestExpression::Error)]);

        let actual = effect.resolve(&TestEnv);

        assert_eq!(actual, Err(()));
    }

    #[test]
    fn test_resolve_disjoint() {
        use ConditionalEffect::*;

        fn check<I>(effs: I)
        where
            I: IntoIterator<Item = ConditionalEffect<TestExpression>> + Clone,
        {
            let eff = ConditionalEffect::Disjoint(effs.clone().into_iter().collect());

            let actual = eff.resolve(&TestEnv);

            let expected: Result<Vec<Option<Effect>>, ()> =
                effs.into_iter().map(|e| e.resolve(&TestEnv)).collect();
            let expected = expected.map(combine_strict);

            assert_eq!(actual, expected);
        }

        check(vec![Silent, Fixed(ALLOW)]);
        check(vec![Fixed(ALLOW), Silent]);
        check(vec![Fixed(ALLOW), Fixed(ALLOW)]);
        check(vec![Fixed(ALLOW), Fixed(DENY)]);
        check(vec![Fixed(DENY), Fixed(ALLOW)]);
        check(vec![Fixed(DENY), Silent]);
        check(vec![Silent, Fixed(DENY)]);
        check(vec![Atomic(ALLOW, TestExpression::Match)]);
        check(vec![Atomic(DENY, TestExpression::Match)]);
        check(vec![Atomic(DENY, TestExpression::Miss), Fixed(ALLOW)]);
        check(vec![Atomic(ALLOW, TestExpression::Miss), Fixed(DENY)]);
        check(vec![
            Atomic(ALLOW, TestExpression::Match),
            Atomic(DENY, TestExpression::Miss),
        ]);
        check(vec![
            Atomic(ALLOW, TestExpression::Match),
            Atomic(DENY, TestExpression::Match),
        ]);
        check(vec![
            Atomic(ALLOW, TestExpression::Match),
            Atomic(ALLOW, TestExpression::Match),
        ]);
        check(vec![
            Fixed(ALLOW),
            Atomic(ALLOW, TestExpression::Miss),
            Fixed(ALLOW),
        ]);
    }
}
