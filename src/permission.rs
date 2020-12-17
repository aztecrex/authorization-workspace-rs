

// pub enum Policy {
//     Silent,
// }

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Permission {
    ALLOW, DENY
}

pub enum ConditionalPermission<CExp> {
    Silent,
    Atomic(Permission, CExp),
}

pub trait ConditionExpression {
    type Err;
    fn evaluate(&self) -> Result<bool, Self::Err>;
}


impl <CExp: ConditionExpression> ConditionalPermission<CExp> {
    pub fn resolve(&self) -> Option<Permission> {
        use ConditionalPermission::*;
        match self {
            Silent => None,
            Atomic(_perm, cexp) => {
                let matched = cexp.evaluate().ok().unwrap();
                if matched {
                    Some(*_perm)
                } else {
                    None
                }
            },
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    enum TestExpression {
        Match, Miss, Error
    }

    impl ConditionExpression for TestExpression {
        type Err = ();

        fn evaluate(&self) -> Result<bool, ()> {
            use TestExpression::*;
            match self {
                Match => Ok(true),
                Miss => Ok(false),
                Error => Err(()),
            }
        }
    }


    #[test]
    fn resolve_silent() {

        // g
        let perm = ConditionalPermission::<TestExpression>::Silent;

        // w
        let actual = perm.resolve();

        // t
        assert_eq!(actual, None);
    }

    #[test]
    fn resolve_atomic_allow_match() {

        let perm = ConditionalPermission::Atomic(Permission::ALLOW, TestExpression::Match);

        let actual = perm.resolve();

        assert_eq!(actual, Some(Permission::ALLOW));

    }

    #[test]
    fn resolve_atomic_deny_match() {

        let perm = ConditionalPermission::Atomic(Permission::DENY, TestExpression::Match);

        let actual = perm.resolve();

        assert_eq!(actual, Some(Permission::DENY));

    }

    #[test]
    fn resolve_atomic_allow_miss() {

        let perm = ConditionalPermission::Atomic(Permission::ALLOW, TestExpression::Miss);

        let actual = perm.resolve();

        assert_eq!(actual, None);

    }

    #[test]
    fn resolve_atomic_deny_miss() {

        let perm = ConditionalPermission::Atomic(Permission::DENY, TestExpression::Miss);

        let actual = perm.resolve();

        assert_eq!(actual, None);

    }


}
