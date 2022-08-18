pub struct Authorization<Subj>(Subj, bool);

impl<Subj> Authorization<Subj> {
    pub fn authorized(&self) -> bool {
        self.1
    }

    pub fn subject(&self) -> &Subj {
        &self.0
    }
}

pub struct Authorizations<Azn, Prin>(Prin, Vec<Azn>);

impl<Subj, Prin> Authorizations<Authorization<Subj>, Prin> {
    fn new<T: IntoIterator<Item = Authorization<Subj>>>(principal: Prin, items: T) -> Self {
        Authorizations(principal, items.into_iter().collect())
    }
    pub fn authorized(&self) -> bool {
        !self.1.is_empty() && self.1.iter().all(Authorization::authorized)
    }

    pub fn principal(&self) -> &Prin {
        &self.0
    }

    pub fn as_slice(&self) -> &[Authorization<Subj>] {
        self.1.as_slice()
    }

    pub fn as_slice_mut(&mut self) -> &mut [Authorization<Subj>] {
        self.1.as_mut_slice()
    }
}

// impl<Subj, Prin> FromIterator<Authorization<Subj>> for Authorizations<Authorization<Subj>, Prin> {
//     fn from_iter<T: IntoIterator<Item = Authorization<Subj>>>(items: T) -> Self {
//         Authorizations(items.into_iter().collect())
//     }
// }

impl<Subj, Prin> IntoIterator for Authorizations<Authorization<Subj>, Prin> {
    type Item = Authorization<Subj>;

    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.1.into_iter()
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
    ) -> Result<Authorizations<Authorization<Self::Subject>, Self::Principal>, Self::Err>;
}
