use ratatui::style::Color;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub name: &'static str,
    pub accent: Color,
    pub dim: Color,
    pub border: Color,
    pub text: Color,
    pub danger: Color,
    pub warn: Color,
    pub ok: Color,
    pub selection_bg: Color,
}

pub const DARK: Theme = Theme {
    name: "dark",
    accent: Color::Rgb(61, 214, 198),
    dim: Color::Rgb(144, 166, 185),
    border: Color::Rgb(60, 80, 98),
    text: Color::Rgb(237, 246, 251),
    danger: Color::Rgb(251, 113, 133),
    warn: Color::Rgb(245, 182, 77),
    ok: Color::Rgb(110, 231, 183),
    selection_bg: Color::Rgb(18, 42, 54),
};

pub const SOLARIZED: Theme = Theme {
    name: "solarized",
    accent: Color::Rgb(42, 161, 152),
    dim: Color::Rgb(88, 110, 117),
    border: Color::Rgb(88, 110, 117),
    text: Color::Rgb(147, 161, 161),
    danger: Color::Rgb(220, 50, 47),
    warn: Color::Rgb(181, 137, 0),
    ok: Color::Rgb(133, 153, 0),
    selection_bg: Color::Rgb(7, 54, 66),
};

pub const DRACULA: Theme = Theme {
    name: "dracula",
    accent: Color::Rgb(139, 233, 253),
    dim: Color::Rgb(98, 114, 164),
    border: Color::Rgb(68, 71, 90),
    text: Color::Rgb(248, 248, 242),
    danger: Color::Rgb(255, 85, 85),
    warn: Color::Rgb(241, 250, 140),
    ok: Color::Rgb(80, 250, 123),
    selection_bg: Color::Rgb(68, 71, 90),
};

pub const NORD: Theme = Theme {
    name: "nord",
    accent: Color::Rgb(136, 192, 208),
    dim: Color::Rgb(76, 86, 106),
    border: Color::Rgb(59, 66, 82),
    text: Color::Rgb(236, 239, 244),
    danger: Color::Rgb(191, 97, 106),
    warn: Color::Rgb(235, 203, 139),
    ok: Color::Rgb(163, 190, 140),
    selection_bg: Color::Rgb(67, 76, 94),
};

pub const GRUVBOX: Theme = Theme {
    name: "gruvbox",
    accent: Color::Rgb(131, 165, 152),
    dim: Color::Rgb(146, 131, 116),
    border: Color::Rgb(80, 73, 69),
    text: Color::Rgb(235, 219, 178),
    danger: Color::Rgb(251, 73, 52),
    warn: Color::Rgb(250, 189, 47),
    ok: Color::Rgb(184, 187, 38),
    selection_bg: Color::Rgb(60, 56, 54),
};

pub const ALL: &[Theme] = &[DARK, SOLARIZED, DRACULA, NORD, GRUVBOX];

pub fn by_name(name: &str) -> Theme {
    let lower = name.trim().to_ascii_lowercase();
    for t in ALL {
        if t.name == lower {
            return *t;
        }
    }
    DARK
}

pub fn next(current: &str) -> Theme {
    let idx = ALL.iter().position(|t| t.name == current).unwrap_or(0);
    ALL[(idx + 1) % ALL.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_returns_known_theme() {
        assert_eq!(by_name("dark").name, "dark");
        assert_eq!(by_name("Dracula").name, "dracula");
        assert_eq!(by_name("NORD").name, "nord");
    }

    #[test]
    fn by_name_falls_back_to_dark() {
        assert_eq!(by_name("nonexistent").name, "dark");
    }

    #[test]
    fn next_cycles_through_all_themes() {
        let mut seen: Vec<&str> = Vec::new();
        let mut current = "dark";
        for _ in 0..ALL.len() {
            seen.push(current);
            current = next(current).name;
        }
        assert_eq!(seen.len(), ALL.len());
        // Should cycle back to start after going through all.
        assert_eq!(next("gruvbox").name, "dark");
    }
}
