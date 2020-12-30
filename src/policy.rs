use crate::effect::*;

pub trait ResourceMatch {
    type Resource;
    fn test(&self, resource: &Self::Resource) -> bool;
}

pub trait ActionMatch {
    type Action;
    fn test(&self, action: &Self::Action) -> bool;
}

pub enum Policy<RMatch, AMatch> {
    Unconditional(RMatch, AMatch, Effect),
}

impl<R, RMatch, A, AMatch> Policy<RMatch, AMatch>
where
    RMatch: ResourceMatch<Resource = R>,
    AMatch: ActionMatch<Action = A>,
{
    pub fn apply(&self, resource: R, action: A) -> Option<Effect> {
        use Policy::*;

        match self {
            Unconditional(rmatch, amatch, eff) => {
                if rmatch.test(&resource) && amatch.test(&action) {
                    Some(*eff)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use Effect::*;

    pub struct Resource(&'static str);
    pub struct Action(&'static str);

    impl ResourceMatch for &str {
        type Resource = Resource;
        fn test(&self, resource: &Self::Resource) -> bool {
            let Resource(v) = resource;
            v == self
        }
    }

    impl ActionMatch for &str {
        type Action = Action;
        fn test(&self, action: &Self::Action) -> bool {
            let Action(a) = action;
            a == self
        }
    }

    #[test]
    fn test_unconditional_match_allow() {
        let policy = Policy::Unconditional("r", "a", ALLOW);

        let actual = policy.apply(Resource("r"), Action("a"));

        assert_eq!(actual, Some(ALLOW));
    }

    #[test]
    fn test_unconditional_match_deny() {
        let policy = Policy::Unconditional("r", "a", DENY);

        let actual = policy.apply(Resource("r"), Action("a"));

        assert_eq!(actual, Some(DENY));
    }

    #[test]
    fn test_unconditional_unmatched_resource() {
        let policy = Policy::Unconditional("miss", "a", DENY);

        let actual = policy.apply(Resource("r"), Action("a"));

        assert_eq!(actual, None);
    }

    #[test]
    fn test_unconditional_unmatched_action() {
        let policy = Policy::Unconditional("r", "miss", DENY);

        let actual = policy.apply(Resource("r"), Action("a"));

        assert_eq!(actual, None);
    }
}

// #[derive(PartialEq, Eq)]
// struct Authority(String);

// #[derive(PartialEq, Eq)]
// struct ResourcePath(Vec<String>);

// #[derive(PartialEq, Eq)]
// struct Resource(Authority, ResourcePath);

// #[derive(PartialEq, Eq)]
// struct ActionName(String);

// #[derive(PartialEq, Eq)]
// struct Action(Authority, ActionName);

// trait ResourceMatch {

//     fn all() -> Self;
//     fn none() -> Self;

//     fn test(&self, resource: &ResourcePath) -> bool;
// }
// trait ActionMatch {

//     fn all() -> Self;
//     fn none() -> Self;

//     fn test(&self, action: &ActionName) -> bool;
// }

// pub enum ConditionalPermission<Cond: Sized>{

//     Atomic(Effect, Cond),
//     Aggregate(Vec<ConditionalPermission<Cond>>),
//     Disjoint(Vec<ConditionalPermission<Cond>>),
//     Silent,
// }

//  impl <Cond> ConditionalPermission<Cond> {

//     pub  fn apply<Env: Environment<Cond>> (&self, environment: &Env) -> Result<Option<Effect>, Env::Error> {
//         match self {
//             ConditionalPermission::Atomic(effect, cond) => {
//                 environment.test(cond)
//                     .map(|r| if r  {Some(*effect)} else {None})
//             },
//             ConditionalPermission::Aggregate(constituents) => {

//                 // note: if any evaluation fails, this result will reflect
//                 // the failed item application
//                 let results : Result<Vec<Option<Effect>>, Env::Error> =
//                     constituents.iter()
//                     .map(|p| p.apply(environment))
//                     .filter(|r| {
//                         r.and_then(|e| e.is_some())

//                         // if r.is_ok() {

//                         //     unimplemented!();
//                         // } else {
//                         //     true
//                         // }
//                     })
//                     .collect();

//                 unimplemented!();
//             },
//             ConditionalPermission::Disjoint(constituents) => {
//                 unimplemented!();
//             },
//             ConditionalPermission::Silent => Ok(None),
//         }
//     }

// }

// pub enum Policy<Cond: Sized, RMatch: Sized, AMatch: Sized>
// {
//     Unconditional(Effect, Authority, AMatch, RMatch),
//     Conditional(Effect, Authority, AMatch, RMatch, Cond),
//     Aggregate(Vec<Policy<Cond, RMatch, AMatch>>),
//     Disjoint(Vec<Policy<Cond, RMatch, AMatch>>),
//     Silent,
// }

// impl <Cond: Sized, RMatch: Sized, AMatch: Sized> Policy<Cond, RMatch, AMatch>
//     where
//     Cond: Condition,
//     RMatch: ResourceMatch,
//     AMatch: ActionMatch,
//  {

//     pub fn evaluate(&self, authority: Authority, action: ActionName, resource: ResourcePath) -> ConditionalPermission<Cond> {
//        match self {

//            Policy::Unconditional(effect, self_authority, amatch, rmatch) => {
//             if Self::applies(authority, action, resource, *self_authority, &amatch, &rmatch) {
//                 ConditionalPermission::Atomic(*effect, Cond::always())
//             } else {
//                 ConditionalPermission::Silent
//             }
//            },
//            Policy::Conditional(effect, self_authority, amatch, rmatch, cond) => {
//             if Self::applies(authority, action, resource, *self_authority, &amatch, &rmatch) {
//                 ConditionalPermission::Atomic(*effect, *cond)
//             } else {
//                 ConditionalPermission::Silent
//             }
//            },
//            Policy::Aggregate(constituents) => {
//                let perms = constituents.iter()
//                 .map(|&p| p.evaluate(authority, action, resource))
//                 .collect();
//                ConditionalPermission::Aggregate(perms)
//            },
//            Policy::Disjoint(constituents) => {
//             let perms = constituents.iter()
//                 .map(|&p| p.evaluate(authority, action, resource))
//                 .collect();
//            ConditionalPermission::Disjoint(perms)
//        },
//         Policy::Silent => ConditionalPermission::Silent,
//        }
//     }

//     fn applies(authority: Authority, action: ActionName, resource: ResourcePath, self_authority: Authority, amatch: &AMatch, rmatch: &RMatch) -> bool {
//         authority == self_authority &&
//         amatch.test(&action) &&
//         rmatch.test(&resource)
//     }

// }
