use std::{
    io::BufRead,
    iter::Peekable,
    str::{Chars, FromStr},
    time::Duration,
};

// TODO: encode the error as another variant
#[derive(Debug)]
enum Event {
    Version(Version),
    Debuggee(String),
    SystemInfo(SystemInfo),
    Timestamp { time: u64, rss: u64 },
    Comment(String),
    // TODO: this one needs to be more flexible
    StackTrace(Foo),
    // ...
}

#[derive(Debug)]
struct Foo {
    stackframes: Vec<String>,
    bars: Vec<Bar>,
}

#[derive(Debug)]
struct Bar {
    instruction_pointer: InstructionPointer,
    trace: Trace,
    bazes: Vec<Baz>,
}

#[derive(Debug)]
struct Baz {
    allocation_info: AllocationInfo,
    quoxs: Vec<Quox>,
}

#[derive(Debug)]
enum Quox {
    Alloc(usize),
    Dealloc(usize),
}

struct Emitter<Src: BufRead> {
    lines: Peekable<Lines<Src>>,
}

impl<Src: BufRead> Iterator for Emitter<Src> {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        let line = match self.lines.next()? {
            Ok(line) => line,
            Err(e) => return Some(Err(e)),
        };

        let event = match line {
            Line::Version(version) => Event::Version(version),
            Line::Debuggee(debuggee) => Event::Debuggee(debuggee),
            Line::SystemInfo(system_info) => Event::SystemInfo(system_info),
            Line::Comment(comment) => Event::Comment(comment),
            Line::Timestamp(time) => {
                if let Some(Ok(Line::RssTimestamp(rss))) = self.lines.next() {
                    Event::Timestamp { time, rss }
                } else {
                    todo!();
                }
            }
            // Modes go as follows:
            // s+(it(a(\+\-)*)*)+
            // TODO: It looks like it may be
            // s+(i(t(a(\+\-)*)*)+)+
            // TODO: Is this too structured? Should it be loosened up?
            Line::Stackframe(frame) => {
                // s+
                let mut frames = vec![frame];
                loop {
                    match self.lines.peek() {
                        None => todo!(),
                        Some(Err(e)) => todo!(),
                        Some(Ok(line)) => match line {
                            Line::Stackframe(_) => {
                                let Some(Ok(Line::Stackframe(frame))) =
                                    self.lines.next() else { unreachable!() };
                                frames.push(frame);
                            }
                            Line::InstructionPointer(_) => break,
                            _ => todo!(),
                        },
                    }
                }

                // (it(a(\+\-)*)*)+
                let mut bars = Vec::new();
                loop {
                    if !matches!(self.lines.peek(), Some(Ok(Line::InstructionPointer(_)))) {
                        break;
                    }
                    let Some(Ok(Line::InstructionPointer(instruction_pointer))) =
                        self.lines.next() else { todo!(); };
                    let Some(Ok(Line::Trace(trace))) = self.lines.next() else { todo!() };
                    let mut bar = Bar {
                        instruction_pointer,
                        trace,
                        bazes: Vec::new(),
                    };

                    // (a(\+\-)*)*
                    while let Some(Ok(Line::AllocationInfo(_))) = self.lines.peek() {
                        let Some(Ok(Line::AllocationInfo(alloc_info))) =
                            self.lines.next() else { unreachable!() };
                        let mut baz = Baz {
                            allocation_info: alloc_info,
                            quoxs: Vec::new(),
                        };

                        // (\+\-)*
                        while let Some(Ok(Line::Allocation(_) | Line::Deallocation(_))) =
                            self.lines.peek()
                        {
                            match self.lines.next().unwrap().unwrap() {
                                Line::Allocation(Allocation { index }) => {
                                    baz.quoxs.push(Quox::Alloc(index))
                                }
                                Line::Deallocation(Deallocation { index }) => {
                                    baz.quoxs.push(Quox::Dealloc(index))
                                }
                                _ => unreachable!(),
                            }
                        }

                        bar.bazes.push(baz);
                    }

                    bars.push(bar);
                }

                Event::StackTrace(Foo {
                    stackframes: frames,
                    bars,
                })
            }
            Line::FromAttached(_) => todo!(),
            Line::EmbeddedSuppression(_) => todo!(),
            Line::Unknown(_) => todo!(),

            Line::RssTimestamp(_)
            | Line::Trace(_)
            | Line::InstructionPointer(_)
            | Line::AllocationInfo(_)
            | Line::Allocation(_)
            | Line::Deallocation(_) => todo!(),
        };

        Some(Ok(event))
    }
}

struct Lines<Src> {
    version: u32,
    source: Src,
    buffer: String,
}

impl<Src: BufRead> Iterator for Lines<Src> {
    type Item = Result<Line>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.buffer.clear();

            match self.source.read_line(&mut self.buffer) {
                Ok(0) => break None,
                Ok(_) => {
                    let mut line = &*self.buffer;
                    // Trim off the trailing newline if there is one
                    if line.ends_with('\n') {
                        line = &line[..line.len() - 1];
                    }

                    if !line.is_empty() {
                        break Some(line.parse());
                    }
                }
                Err(_) => todo!(),
            }
        }
    }
}

// TODO: encode the error as another variant
#[derive(Debug)]
enum Line {
    Stackframe(String),
    Trace(Trace),
    InstructionPointer(InstructionPointer),
    Allocation(Allocation),
    Deallocation(Deallocation),
    AllocationInfo(AllocationInfo),
    Comment(String),
    Timestamp(u64),
    RssTimestamp(u64),
    Debuggee(String),
    FromAttached(FromAttached),
    Version(Version),
    SystemInfo(SystemInfo),
    EmbeddedSuppression(EmbeddedSuppression),
    Unknown(String),
}

// TODO: add a reason?
#[derive(Debug)]
struct Error {
    mode: Mode,
    line: String,
}

// Lines are all in the form:
// <mode_char> <info>
impl FromStr for Line {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self> {
        use Line as L;
        use Mode as M;

        let mut chars = line.chars();

        let mode = Mode::from(chars.next().expect("Empty lines are filtered"));
        if chars.next() != Some(' ') {
            return Err(Error {
                mode,
                line: line.to_owned(),
            });
        }

        let modeless_line = &line[2..];
        match mode {
            M::Stackframe => stack_frame(modeless_line).map(L::Stackframe),
            M::Trace => trace(modeless_line).map(L::Trace),
            M::InstructionPointer => instruction_pointer(modeless_line).map(L::InstructionPointer),
            M::Allocation => allocation(modeless_line).map(L::Allocation),
            M::Deallocation => deallocation(modeless_line).map(L::Deallocation),
            M::AllocationInfo => allocation_info(modeless_line).map(L::AllocationInfo),
            M::Comment => comment(modeless_line).map(L::Comment),
            M::Timestamp => timestamp(modeless_line).map(L::Timestamp),
            M::RssTimestamp => rss_timestamp(modeless_line).map(L::RssTimestamp),
            M::Debuggee => debuggee(modeless_line).map(L::Debuggee),
            M::FromAttached => from_attached(modeless_line).map(L::FromAttached),
            M::Version => version(modeless_line).map(L::Version),
            M::SystemInfo => system_info(modeless_line).map(L::SystemInfo),
            M::EmbeddedSuppression => {
                embedded_suppression(modeless_line).map(L::EmbeddedSuppression)
            }
            M::Unknown(_) => Some(L::Unknown(line.to_owned())),
        }
        .ok_or_else(|| Error {
            mode,
            line: line.to_owned(),
        })
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct Trace {
    instruction_pointer_index: usize,
    parent_index: usize,
}

#[derive(Debug)]
struct InstructionPointer {
    pointer: usize,
    module_index: usize,
    frame: Frame,
    inlined: Vec<InlineFrame>,
}

#[derive(Debug, Default)]
struct Frame {
    function_index: Option<usize>,
    file_index: Option<usize>,
    line: Option<usize>,
}

#[derive(Debug)]
struct InlineFrame {
    function_index: usize,
    file_index: usize,
    line: usize,
}

impl InlineFrame {
    fn new(frame: Frame) -> Option<Self> {
        match (frame.function_index, frame.file_index, frame.line) {
            (Some(function_index), Some(file_index), Some(line)) => Some(InlineFrame {
                function_index,
                file_index,
                line,
            }),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Allocation {
    index: usize,
}

#[derive(Debug)]
struct Deallocation {
    index: usize,
}

#[derive(Debug)]
struct AllocationInfo {
    size: u64,
    trace_index: usize,
}

#[derive(Debug)]
struct FromAttached;

#[derive(Debug)]
struct Version {
    heaptrack: u64,
    file: u64,
}

#[derive(Debug)]
struct SystemInfo {
    page_size: u64,
    pages: u64,
}

#[derive(Debug)]
struct EmbeddedSuppression;

trait FromHex {
    fn from_hex(s: &str) -> Option<Self>
    where
        Self: Sized;
}

impl FromHex for usize {
    fn from_hex(s: &str) -> Option<Self> {
        usize::from_str_radix(s, 16).ok()
    }
}

impl FromHex for u64 {
    fn from_hex(s: &str) -> Option<Self> {
        u64::from_str_radix(s, 16).ok()
    }
}

fn parse_hex<T: FromHex>(s: &str) -> Option<T> {
    T::from_hex(s)
}

fn parse_hex_pair<T: FromHex, U: FromHex>(s: &str) -> Option<(T, U)> {
    let mut parts = s.split(' ');
    match (
        parts.next().and_then(FromHex::from_hex),
        parts.next().and_then(FromHex::from_hex),
        parts.next(),
    ) {
        (Some(left), Some(right), None) => Some((left, right)),
        _ => None,
    }
}

// s <len> <string>
fn stack_frame(line: &str) -> Option<String> {
    if let Some((len, s)) = line.split_once(' ') {
        let len: usize = parse_hex(len)?;
        if len == s.len() {
            Some(s.to_owned())
        } else {
            None
        }
    } else {
        None
    }
}

// t <instruction_pointer_index> <parent_index>
fn trace(line: &str) -> Option<Trace> {
    parse_hex_pair(line).map(|(instruction_pointer_index, parent_index)| Trace {
        instruction_pointer_index,
        parent_index,
    })
}

// i <pointer> <module_index> [<inlined_frame> ...]
fn instruction_pointer(line: &str) -> Option<InstructionPointer> {
    fn read_frame(parts: &mut impl Iterator<Item = usize>, frame: &mut Frame) {
        frame.function_index = parts.next();
        frame.file_index = parts.next();
        frame.line = parts.next();
    }

    let mut parts = line.split(' ').filter_map(parse_hex);
    let mut ip = match (parts.next(), parts.next()) {
        (Some(pointer), Some(module_index)) => InstructionPointer {
            pointer,
            module_index,
            frame: Frame::default(),
            inlined: Vec::new(),
        },
        _ => return None,
    };

    // TODO: why does this allow for a partial frame here, but the inlined frames have to be
    // complete?
    read_frame(&mut parts, &mut ip.frame);
    loop {
        let mut frame = Frame::default();
        read_frame(&mut parts, &mut frame);
        if let Some(inline_frame) = InlineFrame::new(frame) {
            ip.inlined.push(inline_frame);
        } else {
            break;
        }
    }

    Some(ip)
}

// + <index>
fn allocation(line: &str) -> Option<Allocation> {
    parse_hex(line).map(|index| Allocation { index })
}

// - <index>
fn deallocation(line: &str) -> Option<Deallocation> {
    parse_hex(line).map(|index| Deallocation { index })
}

// a <size> <trace_index>
fn allocation_info(line: &str) -> Option<AllocationInfo> {
    parse_hex_pair(line).map(|(size, trace_index)| AllocationInfo { size, trace_index })
}

// # <anything>...
fn comment(line: &str) -> Option<String> {
    Some(line.to_owned())
}

// c <timestamp>
fn timestamp(line: &str) -> Option<u64> {
    parse_hex(line)
}

// R <rss>
fn rss_timestamp(line: &str) -> Option<u64> {
    parse_hex(line)
}

// X <debuggee>
fn debuggee(line: &str) -> Option<String> {
    Some(line.to_owned())
}

// A ???
fn from_attached(line: &str) -> Option<FromAttached> {
    todo!();
}

// v <heaptrack_version> <file_version>
fn version(line: &str) -> Option<Version> {
    parse_hex_pair(line).map(|(heaptrack, file)| Version { heaptrack, file })
}

// I <page_size> <pages>
fn system_info(line: &str) -> Option<SystemInfo> {
    parse_hex_pair(line).map(|(page_size, pages)| SystemInfo { page_size, pages })
}

// S ???
fn embedded_suppression(line: &str) -> Option<EmbeddedSuppression> {
    todo!("What does `parseSuppression` do?");
}

type HowToParse = ();

#[derive(Debug)]
enum Mode {
    Stackframe,
    Trace,
    InstructionPointer,
    Allocation,
    Deallocation,
    AllocationInfo,
    Comment,
    Timestamp,
    RssTimestamp,
    Debuggee,
    FromAttached,
    Version,
    SystemInfo,
    EmbeddedSuppression,
    Unknown(char),
}

impl From<char> for Mode {
    fn from(c: char) -> Self {
        match c {
            's' => Self::Stackframe,
            't' => Self::Trace,
            'i' => Self::InstructionPointer,
            '+' => Self::Allocation,
            '-' => Self::Deallocation,
            'a' => Self::AllocationInfo,
            '#' => Self::Comment,
            'c' => Self::Timestamp,
            'R' => Self::RssTimestamp,
            'X' => Self::Debuggee,
            'A' => Self::FromAttached,
            'v' => Self::Version,
            'I' => Self::SystemInfo,
            'S' => Self::EmbeddedSuppression,
            unknown => Self::Unknown(unknown),
        }
    }
}

#[test]
fn blah() {
    let source = std::io::BufReader::new(std::fs::File::open("/tmp/sample").unwrap());
    let parser = Lines {
        version: 0,
        source,
        buffer: String::new(),
    };

    let emitter = Emitter {
        lines: parser.peekable(),
    };

    let start = std::time::Instant::now();
    for event in emitter {
        // line.unwrap();
        println!("{:#?}", event.unwrap());
    }

    panic!("{:?}", start.elapsed());
}
