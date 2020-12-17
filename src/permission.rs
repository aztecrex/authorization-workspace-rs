use crate::condition::*;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Permission {
    ALLOW,
    DENY,
}

pub enum ConditionalPermission<CExp> {
    Silent,
    Atomic(Permission, CExp),
    Fixed(Permission),
    Aggregate(Vec<ConditionalPermission<CExp>>),
}

impl<CExp> ConditionalPermission<CExp> {
    pub fn resolve<Env>(&self, environment: &Env) -> Result<Option<Permission>, Env::Err>
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
                if perms.is_empty() {
                    Ok(None)
                } else {
                    perms.get(0).unwrap().resolve(environment)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TestExpression {
        Match,
        Miss,
        _Error,
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
                _Error => Err(()),
            }
        }
    }

    use Permission::*;

    #[test]
    fn resolve_silent() {
        let perm = ConditionalPermission::<TestExpression>::Silent;

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_allow_match() {
        let perm = ConditionalPermission::Atomic(Permission::ALLOW, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Permission::ALLOW)));
    }

    #[test]
    fn resolve_atomic_deny_match() {
        let perm = ConditionalPermission::Atomic(Permission::DENY, TestExpression::Match);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(Some(Permission::DENY)));
    }

    #[test]
    fn resolve_atomic_allow_miss() {
        let perm = ConditionalPermission::Atomic(Permission::ALLOW, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_deny_miss() {
        let perm = ConditionalPermission::Atomic(Permission::DENY, TestExpression::Miss);

        let actual = perm.resolve(&TestEnv);

        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn resolve_atomic_error() {
        let perm = ConditionalPermission::Atomic(Permission::ALLOW, TestExpression::_Error);

        let actual = perm.resolve(&TestEnv);

        assert!(actual.is_err());
        assert_eq!(
            actual.unwrap_err(),
            TestEnv.test_condition(&TestExpression::_Error).unwrap_err()
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
        expect: Result<Option<Permission>, ()>,
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
}
