/*
 * TODO: Replace with lex.rs from github.com/cloudflare/wirefilter/
 *
 */

pub enum ParseError {
    Ouch(),
}

pub trait Lex<'i>: Sized {
    fn lex(input: &'i str) -> Result<(Self, &'i str), ParseError>;
}

pub trait LexWith<'i, C>: Sized {
    fn lex(input: &'i str, ctx: C) -> Result<(Self, &'i str), ParseError>;
}

impl<'i, T: Lex<'i>, C> LexWith<'i, C> for T {
    fn lex(input: &'i str, _ctx: C) -> Result<(Self, &'i str), ParseError> {
        Self::lex(input)
    }
}
