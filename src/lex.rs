/*
 * TODO: Replace with lex.rs from github.com/cloudflare/wirefilter/
 *
 */

pub enum LexErrorKind {
    Ouch(),
}

pub type LexError<'i> = (LexErrorKind, &'i str);

pub type LexResult<'i, T> = Result<(T, &'i str), LexError<'i>>;

pub trait Lex<'i>: Sized {
    fn lex(input: &'i str) -> LexResult<'i, Self>;
}

pub trait LexWith<'i, C>: Sized {
    fn lex(input: &'i str, ctx: C) -> LexResult<'i, Self>;
}

impl<'i, T: Lex<'i>, C> LexWith<'i, C> for T {
    fn lex(input: &'i str, _ctx: C) -> LexResult<'i, Self> {
        Self::lex(input)
    }
}

pub fn expect<'i>(input: &'i str, s: &'static str) -> Result<&'i str, LexError<'i>> {
    if input.starts_with(s) {
        Ok(&input[s.len()..])
    } else {
        Err((LexErrorKind::Ouch(), input))
    }
}
