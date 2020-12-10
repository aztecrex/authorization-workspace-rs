

#[derive(PartialEq, Eq)]
struct Authority(String);

#[derive(PartialEq, Eq)]
struct ResourcePath(Vec<String>);

#[derive(PartialEq, Eq)]
struct Resource(Authority, ResourcePath);

#[derive(PartialEq, Eq)]
struct ActionName(String);

#[derive(PartialEq, Eq)]
struct Action(Authority, ActionName);

#[derive(PartialEq, Eq)]
enum Effect {ALLOW, DENY}

trait Condition  {
    type Env;
    fn test(&self, env: &Self::Env) -> bool;
}

trait ResourceMatch {
    fn test(&self, resouorce: &Resource) -> bool;
}
trait ActionMatch {
    fn test(&self, action: &Action) -> bool;
}

enum Policy<Cond: Sized, RMatch: Sized, AMatch: Sized>
    where
        Cond: Condition,
        RMatch: ResourceMatch,
        AMatch: ActionMatch,
{
    Unconditional(Effect, AMatch, RMatch),
    Conditional(Effect, AMatch, RMatch, Cond),
    Aggregate(Vec<Policy<Cond, RMatch, AMatch>>),
    Disjoint(Vec<Policy<Cond, RMatch, AMatch>>),
    Silent,
}



struct Inquiry(Authority, ActionName, ResourcePath);


enum Permission<Env> {

}

trait Permission<Env> {
    fn allow(&self, environment: &Env) -> bool;
}


impl<Cond: Condition, RMatch: ResourceMatch, AMatch: ActionMatch> Policy<Cond, RMatch, AMatch> {


    fn evaluate(&self, inquiry: &Inquiry) -> Permission<Cond::Env> {
        unimplemented!()
    }

}
