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
}
