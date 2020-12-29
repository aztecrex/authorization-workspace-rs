#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    ALLOW,
    DENY,
}

pub fn reduce_effects(e1: Effect, e2: Effect) -> Effect {
    use Effect::*;

    if e1 == ALLOW {
        e2
    } else {
        DENY
    }
}

pub fn reduce_optional_effects(e1: Option<Effect>, e2: Option<Effect>) -> Option<Effect> {
    match (e1, e2) {
        (None, x) => x,
        (x, None) => x,
        (Some(x), Some(y)) => Some(reduce_effects(x, y)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Effect::*;

    #[test]
    fn test_reduce() {
        assert_eq!(reduce_effects(ALLOW, DENY), DENY);
        assert_eq!(reduce_effects(ALLOW, ALLOW), ALLOW);
        assert_eq!(reduce_effects(DENY, DENY), DENY);
        assert_eq!(reduce_effects(DENY, ALLOW), DENY);
    }

    #[test]
    fn test_reduce_optional() {
        fn check_reduce_optional(e1: Effect, e2: Effect) {
            assert_eq!(
                reduce_optional_effects(Some(e1), Some(e2)),
                Some(reduce_effects(e1, e2))
            );
        }

        check_reduce_optional(ALLOW, DENY);
        check_reduce_optional(ALLOW, ALLOW);
        check_reduce_optional(DENY, ALLOW);
        check_reduce_optional(DENY, DENY);

        assert_eq!(reduce_optional_effects(Some(DENY), None), Some(DENY));
        assert_eq!(reduce_optional_effects(Some(ALLOW), None), Some(ALLOW));
        assert_eq!(reduce_optional_effects(None, Some(DENY)), Some(DENY));
        assert_eq!(reduce_optional_effects(None, Some(ALLOW)), Some(ALLOW));

        assert_eq!(reduce_optional_effects(None, None), None);
    }
}
