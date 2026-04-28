use std::collections::BTreeMap;

use super::lexer::{lex as dsl_lex, Token as DslToken};

pub(super) struct DslParser<'a> {
    pub(super) input: &'a str,
    pub(super) tokens: Vec<DslToken>,
    pub(super) pos: usize,
    pub(super) local_scopes: Vec<BTreeMap<String, String>>,
    pub(super) next_local_id: usize,
}

impl<'a> DslParser<'a> {
    pub(super) fn new(input: &'a str) -> Result<Self, String> {
        Ok(Self {
            input,
            tokens: dsl_lex(input)?,
            pos: 0,
            local_scopes: vec![BTreeMap::new()],
            next_local_id: 0,
        })
    }
}
