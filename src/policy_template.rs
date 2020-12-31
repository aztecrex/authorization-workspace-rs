use super::effect::Effect;
use super::policy::*;

pub trait Template<T> {
    type Param;
    fn apply(self, p: Self::Param) -> T;
}

pub enum PolicyTemplate<RMatchTpl, AMatch, CExp> {
    Unconditional(RMatchTpl, AMatch, Effect),
    Conditional(RMatchTpl, AMatch, Effect, CExp),
    Aggregate(Vec<Policy<RMatchTpl, AMatch, CExp>>),
}

impl<R, A, Param, RMatchTpl, RMatch, AMatch, CExp> Template<Policy<RMatch, AMatch, CExp>>
    for PolicyTemplate<RMatchTpl, AMatch, CExp>
where
    RMatch: ResourceMatch<Resource = R>,
    AMatch: ActionMatch<Action = A>,
    RMatchTpl: Template<RMatch, Param = Param>
{
    type Param = Param;
    fn apply(self, _p: Self::Param) -> Policy<RMatch, AMatch, CExp> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {



}
