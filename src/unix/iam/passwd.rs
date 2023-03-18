#[derive(Debug)]
pub struct PasswdEntry<'a> {
    pub name: &'a [u8],
    pub password: Option<&'a [u8]>,
    pub uid: u32,
    pub gid: u32,
    pub comment: Option<&'a [u8]>,
    pub home: Option<&'a [u8]>,
    pub shell: Option<&'a [u8]>,
}

fn parse_line(line: &[u8]) -> Option<PasswdEntry> {
    fn next_field(offset: usize, line: &[u8]) -> Option<(&[u8], usize)> {
        let i = memchr::memchr(b':', &line[offset..])? + offset;
        Some((unsafe { line.get_unchecked(offset..i) }, i + 1))
    }

    fn next_field_optional(offset: usize, line: &[u8]) -> Option<(Option<&[u8]>, usize)> {
        let (field, offset) = next_field(offset, line)?;
        if field.is_empty() {
            Some((None, offset))
        } else {
            Some((Some(field), offset))
        }
    }

    fn next_field_u32(offset: usize, line: &[u8]) -> Option<(u32, usize)> {
        let (field, offset) = next_field(offset, line)?;
        Some((atoi::atoi(field)?, offset))
    }

    let (name, offset) = next_field(0, line)?;
    let (password, offset) = {
        let (field, offset) = next_field(offset, line)?;

        if field.len() == 1 && unsafe { *field.get_unchecked(0) } == b'x' {
            (None, offset)
        } else {
            (Some(field), offset)
        }
    };
    let (uid, offset) = next_field_u32(offset, line)?;
    let (gid, offset) = next_field_u32(offset, line)?;
    let (comment, offset) = next_field_optional(offset, line)?;
    let (home, offset) = next_field_optional(offset, line)?;
    let shell = match &line[offset..] {
        shell if shell.is_empty() => None,
        shell => Some(shell),
    };

    Some(PasswdEntry {
        name,
        password,
        uid,
        gid,
        comment,
        home,
        shell,
    })
}

pub fn parse_content(content: &[u8]) -> impl Iterator<Item = Option<PasswdEntry>> {
    super::Lines::new(content).map(parse_line)
}
