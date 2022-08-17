pub struct Authorization<Subj, Prin>(Prin, Subj, bool);

impl<Subj, Prin> Authorization<Subj, Prin> {
    pub fn authorized(&self) -> bool {
        self.2
    }

    pub fn subject(&self) -> &Subj {
        &self.1
    }

    pub fn principal(&self) -> &Prin {
        &self.0
    }
}

pub struct Authorizations<Azn>(Vec<Azn>);

impl<Subj, Prin> Authorizations<Authorization<Subj, Prin>> {
    pub fn authorized(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(Authorization::authorized)
    }

    pub fn as_slice(&self) -> &[Authorization<Subj, Prin>] {
        self.0.as_slice()
    }

    pub fn as_slice_mut(&mut self) -> &mut [Authorization<Subj, Prin>] {
        self.0.as_mut_slice()
    }
}

impl<Subj, Prin> FromIterator<Authorization<Subj, Prin>>
    for Authorizations<Authorization<Subj, Prin>>
{
    fn from_iter<T: IntoIterator<Item = Authorization<Subj, Prin>>>(items: T) -> Self {
        Authorizations(items.into_iter().collect())
    }
}

impl<Subj, Prin> IntoIterator for Authorizations<Authorization<Subj, Prin>> {
    type Item = Authorization<Subj, Prin>;

    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub trait AuthorizationOracle {
    type Principal;
    type Subject;
    type Err;

    fn authorized(
        &self,
        principal: &Self::Principal,
        subjects: &[Self::Subject],
    ) -> Result<Authorizations<Authorization<Self::Subject, Self::Principal>>, Self::Err>;
}
