//! Interactive browser: region list on the left, typed memory view on the right.

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::commands::describe_region;
use crate::decode::{self, read_uint, DataType};
use crate::format::{self, human_size};
use crate::infer::{self, Confidence, InferCtx};
use crate::model::MemState;
use crate::search;
use crate::session::Session;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Hex,
    Auto,
    Typed(DataType),
}

const MODES: [Mode; 12] = [
    Mode::Hex,
    Mode::Auto,
    Mode::Typed(DataType::U8),
    Mode::Typed(DataType::U16),
    Mode::Typed(DataType::U32),
    Mode::Typed(DataType::I32),
    Mode::Typed(DataType::U64),
    Mode::Typed(DataType::F32),
    Mode::Typed(DataType::F64),
    Mode::Typed(DataType::Ptr),
    Mode::Typed(DataType::CStr),
    Mode::Typed(DataType::WStr),
];

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Hex => "hex",
            Mode::Auto => "auto",
            Mode::Typed(t) => t.name(),
        }
    }
}

#[derive(PartialEq)]
enum Focus {
    Regions,
    View,
}

enum Prompt {
    Goto,
    Search,
}

struct App<'a> {
    s: &'a mut Session,
    focus: Focus,
    show_all: bool,
    visible: Vec<usize>,
    list: ListState,
    addr: u64,
    cursor: usize,
    mode: usize,
    history: Vec<u64>,
    prompt: Option<(Prompt, String)>,
    status: String,
    rows: Vec<u64>,
    view_h: usize,
    quit: bool,
}

pub fn run(s: &mut Session, start: Option<u64>) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App {
        s,
        focus: Focus::Regions,
        show_all: false,
        visible: Vec::new(),
        list: ListState::default(),
        addr: 0,
        cursor: 0,
        mode: 1,
        history: Vec::new(),
        prompt: None,
        status: String::new(),
        rows: Vec::new(),
        view_h: 20,
        quit: false,
    };
    app.rebuild_list();
    match start {
        Some(a) => app.goto(a, false),
        None => {
            if let Some(&i) = app.visible.first() {
                app.addr = app.s.map.regions()[i].base;
                app.list.select(Some(0));
            }
        }
    }
    let res = app.run(&mut terminal);
    ratatui::restore();
    res
}

impl App<'_> {
    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    self.on_key(k);
                }
            }
        }
        Ok(())
    }

    fn mode(&self) -> Mode {
        MODES[self.mode]
    }

    fn step(&self) -> u64 {
        let ps = self.s.ptr_size();
        match self.mode() {
            Mode::Hex => 16,
            Mode::Auto => ps as u64,
            Mode::Typed(t) if t.is_string() => 16,
            Mode::Typed(t) => t.size(ps) as u64,
        }
    }

    fn rebuild_list(&mut self) {
        self.visible = self
            .s
            .map
            .regions()
            .iter()
            .enumerate()
            .filter(|(_, r)| if self.show_all { r.state != MemState::Free } else { r.is_readable() })
            .map(|(i, _)| i)
            .collect();
        self.sync_selection();
    }

    fn sync_selection(&mut self) {
        let idx = self.s.map.index_of(self.addr);
        let pos = idx.and_then(|i| self.visible.iter().position(|&v| v == i));
        if pos.is_some() {
            self.list.select(pos);
        }
    }

    fn goto(&mut self, a: u64, remember: bool) {
        if remember && a != self.addr {
            self.history.push(self.addr);
        }
        self.addr = a;
        self.cursor = 0;
        self.sync_selection();
    }

    fn on_key(&mut self, k: KeyEvent) {
        if let Some((kind, mut text)) = self.prompt.take() {
            match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.submit(kind, text),
                KeyCode::Backspace => {
                    text.pop();
                    self.prompt = Some((kind, text));
                }
                KeyCode::Char(c) => {
                    text.push(c);
                    self.prompt = Some((kind, text));
                }
                _ => self.prompt = Some((kind, text)),
            }
            return;
        }
        self.status.clear();
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Tab => {
                self.focus = if self.focus == Focus::Regions { Focus::View } else { Focus::Regions };
            }
            KeyCode::Char('g') => self.prompt = Some((Prompt::Goto, String::new())),
            KeyCode::Char('/') => self.prompt = Some((Prompt::Search, String::new())),
            KeyCode::Char('t') => self.mode = (self.mode + 1) % MODES.len(),
            KeyCode::Char('T') => self.mode = (self.mode + MODES.len() - 1) % MODES.len(),
            KeyCode::Char('a') => {
                self.show_all = !self.show_all;
                self.rebuild_list();
            }
            KeyCode::Char('r') => match self.s.refresh() {
                Ok(()) => {
                    self.rebuild_list();
                    self.status = "refreshed".into();
                }
                Err(e) => self.status = format!("refresh failed: {e:#}"),
            },
            KeyCode::Char('b') => match self.history.pop() {
                Some(a) => self.goto(a, false),
                None => self.status = "history is empty".into(),
            },
            KeyCode::Char('f') => self.follow(),
            _ if self.focus == Focus::Regions => self.on_region_key(k.code),
            _ => self.on_view_key(k.code),
        }
    }

    fn on_region_key(&mut self, code: KeyCode) {
        let n = self.visible.len();
        if n == 0 {
            return;
        }
        let cur = self.list.selected().unwrap_or(0);
        let page = self.view_h.max(1);
        let next = match code {
            KeyCode::Up => cur.saturating_sub(1),
            KeyCode::Down => (cur + 1).min(n - 1),
            KeyCode::PageUp => cur.saturating_sub(page),
            KeyCode::PageDown => (cur + page).min(n - 1),
            KeyCode::Home => 0,
            KeyCode::End => n - 1,
            KeyCode::Enter => {
                let base = self.s.map.regions()[self.visible[cur]].base;
                self.goto(base, true);
                self.focus = Focus::View;
                return;
            }
            _ => return,
        };
        self.list.select(Some(next));
        self.addr = self.s.map.regions()[self.visible[next]].base;
        self.cursor = 0;
    }

    fn on_view_key(&mut self, code: KeyCode) {
        let step = self.step();
        let h = self.view_h.max(1);
        match code {
            KeyCode::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                } else {
                    self.addr = self.addr.saturating_sub(step);
                }
            }
            KeyCode::Down => {
                if self.cursor + 1 < self.rows.len().min(h) {
                    self.cursor += 1;
                } else if let Some(&next) = self.rows.get(1) {
                    self.addr = next;
                } else {
                    self.addr += step;
                }
            }
            KeyCode::PageUp => self.addr = self.addr.saturating_sub(step * h as u64),
            KeyCode::PageDown => self.addr = self.rows.last().copied().unwrap_or(self.addr + step * h as u64),
            KeyCode::Home => {
                if let Some(r) = self.s.map.find(self.addr) {
                    self.addr = r.base;
                    self.cursor = 0;
                }
            }
            KeyCode::Enter => self.follow(),
            _ => {}
        }
        self.sync_selection();
    }

    fn follow(&mut self) {
        let ps = self.s.ptr_size();
        let at = self.rows.get(self.cursor).copied().unwrap_or(self.addr);
        let r = self.s.read(at, ps);
        if !r.all_valid() {
            self.status = "cursor is not readable".into();
            return;
        }
        let p = read_uint(&r.bytes, ps);
        if self.s.map.is_committed(p) {
            self.goto(p, true);
            self.focus = Focus::View;
        } else {
            self.status = format!("{} is not a pointer to committed memory", decode::fmt_ptr(p, ps));
        }
    }

    fn submit(&mut self, kind: Prompt, text: String) {
        match kind {
            Prompt::Goto => match self.s.resolve_addr(&text) {
                Ok(a) => {
                    self.goto(a, true);
                    self.focus = Focus::View;
                }
                Err(e) => self.status = format!("{e:#}"),
            },
            Prompt::Search => {
                let pat: Vec<Option<u8>> = if let Some(h) = text.strip_prefix("hex:") {
                    match search::parse_hex_pattern(h) {
                        Ok(p) => p,
                        Err(e) => {
                            self.status = format!("{e:#}");
                            return;
                        }
                    }
                } else if let Some(w) = text.strip_prefix("w:") {
                    w.encode_utf16().flat_map(|u| u.to_le_bytes()).map(Some).collect()
                } else {
                    text.bytes().map(Some).collect()
                };
                let from = self.rows.get(self.cursor).copied().unwrap_or(self.addr) + 1;
                match search::search(&*self.s.proc, &self.s.map, &pat, 1, from, 1).first() {
                    Some(&a) => {
                        self.goto(a, true);
                        self.focus = Focus::View;
                        self.status = format!("found at {}", decode::fmt_ptr(a, self.s.ptr_size()));
                    }
                    None => self.status = "not found".into(),
                }
            }
        }
    }

    fn view_lines(&mut self, h: usize) -> Vec<Line<'static>> {
        let ps = self.s.ptr_size();
        let mut lines = Vec::new();
        self.rows.clear();
        match self.mode() {
            Mode::Hex => {
                let r = self.s.read(self.addr, 16 * h);
                for (i, l) in format::hexdump_lines(&r, ps).into_iter().enumerate() {
                    self.rows.push(self.addr + 16 * i as u64);
                    lines.push(Line::from(l));
                }
            }
            Mode::Auto => {
                let r = self.s.read(self.addr, (16 * h).max(64));
                let anns = infer::annotate(self.s, &r, true);
                for a in anns.into_iter().take(h) {
                    self.rows.push(a.addr);
                    let color = match (a.ty.as_str(), a.confidence) {
                        ("unreadable" | "zero", _) => Color::DarkGray,
                        (_, Confidence::High) => Color::Green,
                        (_, Confidence::Medium) => Color::Yellow,
                        (_, Confidence::Low) => Color::Gray,
                    };
                    let ty = match &a.field {
                        Some(f) => format!("{f}: {}", a.ty),
                        None => a.ty.clone(),
                    };
                    lines.push(Line::from(vec![
                        Span::raw(format!("{}  ", format::addr(a.addr, ps))),
                        Span::styled(format!("{ty:<12} "), Style::new().fg(color)),
                        Span::raw(a.value),
                    ]));
                }
            }
            Mode::Typed(t) => {
                let step = self.step() as usize;
                let read_len = if t.is_string() { 16 * h + 512 } else { step * h };
                let r = self.s.read(self.addr, read_len);
                for i in 0..h {
                    let o = i * step;
                    if o + step > r.bytes.len() {
                        break;
                    }
                    let a = self.addr + o as u64;
                    self.rows.push(a);
                    let valid = r.valid[o..o + step].iter().all(|&v| v);
                    let mut text = if !valid {
                        "??".to_string()
                    } else if t.is_string() {
                        let end = r.valid[o..].iter().position(|v| !v).map_or(r.bytes.len(), |p| o + p);
                        decode::decode(t, &r.bytes[o..end], ps).unwrap_or_default()
                    } else {
                        decode::decode(t, &r.bytes[o..], ps).unwrap_or_default()
                    };
                    if valid && t == DataType::Ptr {
                        let p = read_uint(&r.bytes[o..], ps);
                        if self.s.map.is_committed(p) {
                            text.push_str(&format!("  -> {}", self.s.describe(p)));
                        }
                    }
                    lines.push(Line::from(format!("{}  {text}", format::addr(a, ps))));
                }
            }
        }
        lines
    }

    fn draw(&mut self, f: &mut Frame) {
        let [main, status] = Layout::vertical([Constraint::Min(3), Constraint::Length(2)]).areas(f.area());
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)]).areas(main);
        let ps = self.s.ptr_size();
        let focus_style = |on: bool| if on { Style::new().fg(Color::Cyan) } else { Style::new() };

        let items: Vec<ListItem> = self
            .visible
            .iter()
            .map(|&i| {
                let r = &self.s.map.regions()[i];
                ListItem::new(format!(
                    "{} {:>9} {:<4} {}",
                    format::addr(r.base, ps),
                    human_size(r.size),
                    r.protect.to_string(),
                    self.s.region_label(r)
                ))
            })
            .collect();
        let title = format!(
            " {} pid {} - {} regions{} ",
            self.s.info().name,
            self.s.info().pid,
            self.visible.len(),
            if self.show_all { " (all)" } else { " (readable)" }
        );
        let list = List::new(items)
            .block(Block::bordered().title(title).border_style(focus_style(self.focus == Focus::Regions)))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(list, left, &mut self.list);

        let h = right.height.saturating_sub(2) as usize;
        self.view_h = h;
        let mut lines = self.view_lines(h);
        if self.cursor >= lines.len() {
            self.cursor = lines.len().saturating_sub(1);
        }
        if self.focus == Focus::View {
            if let Some(l) = lines.get_mut(self.cursor) {
                *l = l.clone().style(Style::new().add_modifier(Modifier::REVERSED));
            }
        }
        let title = format!(
            " [{}] {} - {} ",
            self.mode().name(),
            decode::fmt_ptr(self.addr, ps),
            describe_region(self.s, self.addr)
        );
        let view = Paragraph::new(lines)
            .block(Block::bordered().title(title).border_style(focus_style(self.focus == Focus::View)));
        f.render_widget(view, right);

        let first = match &self.prompt {
            Some((Prompt::Goto, t)) => format!("goto (0x…, module+off, module!symbol): {t}_"),
            Some((Prompt::Search, t)) => format!("search (text | w:wide text | hex:de ad ?? ef): {t}_"),
            None if !self.status.is_empty() => self.status.clone(),
            None => {
                let at = self.rows.get(self.cursor).copied().unwrap_or(self.addr);
                format!("cursor {}  {}", decode::fmt_ptr(at, ps), self.s.describe(at))
            }
        };
        let help = "Tab focus  ↑↓ PgUp/PgDn move  Enter open/follow  g goto  / search  t/T type  f follow  b back  a all  r refresh  q quit";
        f.render_widget(
            Paragraph::new(vec![
                Line::from(first),
                Line::from(Span::styled(help, Style::new().fg(Color::DarkGray))),
            ]),
            status,
        );
    }
}
