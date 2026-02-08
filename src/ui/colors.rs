use ratatui::style::Color;

pub struct GruvboxColors;

impl GruvboxColors {
    pub fn bg0() -> Color {
        Color::Rgb(40, 40, 40)
    }

    pub fn fg() -> Color {
        Color::Rgb(235, 219, 178)
    }

    pub fn red() -> Color {
        Color::Rgb(251, 73, 52)
    }

    pub fn green() -> Color {
        Color::Rgb(184, 187, 38)
    }

    pub fn yellow() -> Color {
        Color::Rgb(250, 189, 47)
    }

    pub fn blue() -> Color {
        Color::Rgb(131, 165, 152)
    }

    pub fn purple() -> Color {
        Color::Rgb(211, 134, 155)
    }

    pub fn aqua() -> Color {
        Color::Rgb(142, 192, 124)
    }

    pub fn orange() -> Color {
        Color::Rgb(254, 128, 25)
    }

    pub fn gray() -> Color {
        Color::Rgb(146, 131, 116)
    }
}
