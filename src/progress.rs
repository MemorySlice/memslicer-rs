use std::collections::VecDeque;
use std::io::Write;
use std::time::Instant;

pub struct ProgressUI {
    total: u32,
    current: u32,
    bytes: u64,
    in_progress_bytes: u64,
    skipped: u32,
    start: Instant,
    messages: VecDeque<String>,
    max_messages: usize,
    lines_drawn: usize,
    bar_width: usize,
}

impl ProgressUI {
    pub fn new(total: u32) -> Self {
        Self {
            total,
            current: 0,
            bytes: 0,
            in_progress_bytes: 0,
            skipped: 0,
            start: Instant::now(),
            messages: VecDeque::with_capacity(3),
            max_messages: 3,
            lines_drawn: 0,
            bar_width: 30,
        }
    }

    pub fn set_progress(&mut self, current: u32, bytes: u64, skipped: u32) {
        self.current = current;
        self.bytes = bytes;
        self.skipped = skipped;
    }

    pub fn set_in_progress_bytes(&mut self, bytes: u64) {
        self.in_progress_bytes = bytes;
    }

    pub fn log(&mut self, msg: String) {
        if self.messages.len() >= self.max_messages {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
        self.render();
    }

    pub fn render(&mut self) {
        let mut out = std::io::stderr().lock();

        // Move cursor up to overwrite previous output
        if self.lines_drawn > 0 {
            let _ = write!(out, "\x1b[{}A", self.lines_drawn);
        }

        // Build progress bar
        let pct = if self.total > 0 {
            self.current as f64 / self.total as f64
        } else {
            0.0
        };
        let filled = (pct * self.bar_width as f64) as usize;
        let empty = self.bar_width - filled;
        let bar: String = "█".repeat(filled) + &"░".repeat(empty);
        let elapsed = self.start.elapsed().as_secs_f64();

        let _ = writeln!(
            out,
            "  [{}] {:5.1}% | Regions: {}/{} | {} | {:.1}s\x1b[K",
            bar,
            pct * 100.0,
            self.current,
            self.total,
            format_bytes(self.bytes + self.in_progress_bytes),
            elapsed,
        );

        // Print message lines
        for i in 0..self.max_messages {
            if let Some(msg) = self.messages.get(i) {
                let _ = writeln!(out, "  {}\x1b[K", msg);
            } else {
                let _ = writeln!(out, "\x1b[K");
            }
        }

        self.lines_drawn = 1 + self.max_messages;
        let _ = out.flush();
    }

    pub fn finish(&mut self) {
        self.render();
        eprintln!();
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
