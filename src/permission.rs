use crate::condition::*;
// use crate::effect::*;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Effect {
    ALLOW,
    DENY,
}

pub enum ConditionalPermission<CExp> {
    Silent,
    Atomic(Effect, CExp),
    Fixed(Effect),
    Aggregate(Vec<ConditionalPermission<CExp>>),
}

impl<CExp> ConditionalPermission<CExp> {
    pub fn resolve<Env>(&self, environment: &Env) -> Result<Option<Effect>, Env::Err>
    where
        Env: Environment<CExp = CExp>,
    {
        use ConditionalPermission::*;
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
                use Effect::*;
                let resolved: Result<Vec<Option<Effect>>, Env::Err> =
                    perms.iter().map(|p| p.resolve(environment)).collect();
                let resolved = resolved?;
                let resolved = resolved
                    .iter()
                    .fold(None, |a: Option<Effect>, v| match (a, v) {
                        (None, x) => *x,
                        (x, None) => x,
                        (Some(ALLOW), Some(ALLOW)) => Some(ALLOW),
                        _ => Some(DENY),
                    });
                Ok(resolved)
            }
        }
    }
}

pub fn resolve_all<'a, CExp: 'a, Env>(
    perms: impl Iterator<Item = &'a ConditionalPermission<CExp>>,
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
        let perm = ConditionalPermission::Silent;

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_allow_match() {
        let perm = ConditionalPermission::Atomic(Effect::ALLOW, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Effect::ALLOW)));
    }

    #[test]
    fn resolve_atomic_deny_match() {
        let perm = ConditionalPermission::Atomic(Effect::DENY, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Effect::DENY)));
    }

    #[test]
    fn resolve_atomic_allow_miss() {
        let perm = ConditionalPermission::Atomic(Effect::ALLOW, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_deny_miss() {
        let perm = ConditionalPermission::Atomic(Effect::DENY, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_error() {
        let perm = ConditionalPermission::Atomic(Effect::ALLOW, TestExpression::Error);

        let actual = perm.resolve(&TestEnv);

        assert!(actual.is_err());
        assert_eq!(
            actual.unwrap_err(),
            TestEnv.test_condition(&TestExpression::Error).unwrap_err()
        );
    }

    #[test]
    fn resolve_fixed_allow() {
        let perm = ConditionalPermission::<TestExpression>::Fixed(ALLOW);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(ALLOW)));
    }

    #[test]
    fn resolve_fixed_deny() {
        let perm = ConditionalPermission::<TestExpression>::Fixed(DENY);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(DENY)));
    }

    fn check_aggregate(
        config: Vec<ConditionalPermission<TestExpression>>,
        expect: Result<Option<Effect>, ()>,
    ) {
        let perm = ConditionalPermission::Aggregate(config);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, expect);
    }

    #[test]
    fn resolve_aggregate_empty() {
        check_aggregate(vec![], Ok(None));
    }

    #[test]
    fn resolve_aggregate_single_allow() {
        check_aggregate(vec![ConditionalPermission::Fixed(ALLOW)], Ok(Some(ALLOW)));
    }

    #[test]
    fn resolve_aggregate_single_deny() {
        check_aggregate(vec![ConditionalPermission::Fixed(DENY)], Ok(Some(DENY)));
    }

    #[test]
    fn resolve_aggregate_single_silent() {
        check_aggregate(vec![ConditionalPermission::Silent], Ok(None));
    }

    #[test]
    fn resolve_aggregate_all_allow() {
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(ALLOW)),
        );
    }

    #[test]
    fn resolve_aggregate_deny_priority() {
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(DENY),
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(DENY)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(DENY),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(DENY)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(DENY),
            ],
            Ok(Some(DENY)),
        );
    }

    #[test]
    fn resolve_aggregate_silence_ignored() {
        check_aggregate(
            vec![
                ConditionalPermission::Silent,
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(ALLOW)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Silent,
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(ALLOW)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Silent,
            ],
            Ok(Some(ALLOW)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Silent,
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(DENY),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(DENY)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Silent,
                ConditionalPermission::Fixed(DENY),
                ConditionalPermission::Fixed(ALLOW),
            ],
            Ok(Some(DENY)),
        );
        check_aggregate(
            vec![
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Fixed(DENY),
                ConditionalPermission::Fixed(ALLOW),
                ConditionalPermission::Silent,
            ],
            Ok(Some(DENY)),
        );
    }

    #[test]
    fn test_nested_condition() {
        use ConditionalPermission::*;

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
        use ConditionalPermission::*;

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
        use ConditionalPermission::*;

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
}
