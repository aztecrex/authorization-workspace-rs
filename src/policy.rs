

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

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Effect {ALLOW, DENY}



pub trait Environment<Cond> {

    type Error;

    fn test(&self, condition: &Cond) -> Result<bool, Self::Error>;
}


pub trait Condition {

    fn always() -> Self;
    fn never() -> Self;

}

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

pub enum ConditionalPermission<Cond: Sized>{

    Atomic(Effect, Cond),
    Aggregate(Vec<ConditionalPermission<Cond>>),
    Disjoint(Vec<ConditionalPermission<Cond>>),
    Silent,
}


 impl <Cond> ConditionalPermission<Cond> {

    pub  fn apply<Env: Environment<Cond>> (&self, environment: &Env) -> Result<Option<Effect>, Env::Error> {
        match self {
            ConditionalPermission::Atomic(effect, cond) => {
                environment.test(cond)
                    .map(|r| if r  {Some(*effect)} else {None})
            },
            ConditionalPermission::Aggregate(constituents) => {

                // note: if any evaluation fails, this result will reflect
                // the failed item application
                let results : Result<Vec<Option<Effect>>, Env::Error> =
                    constituents.iter()
                    .map(|p| p.apply(environment))
                    .filter(|r| {
                        r.and_then(|e| e.is_some())

                        // if r.is_ok() {

                        //     unimplemented!();
                        // } else {
                        //     true
                        // }
                    })
                    .collect();


                unimplemented!();
            },
            ConditionalPermission::Disjoint(constituents) => {
                unimplemented!();
            },
            ConditionalPermission::Silent => Ok(None),
        }
    }

}


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


