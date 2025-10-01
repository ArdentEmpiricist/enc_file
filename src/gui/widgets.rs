use eframe::egui;
use std::path::PathBuf;

pub fn file_picker_button(
    ui: &mut egui::Ui,
    text: &str,
    current_path: &mut Option<PathBuf>,
) -> bool {
    let mut changed = false;
    
    if ui.button(text).clicked()
        && let Some(path) = rfd::FileDialog::new().pick_file()
    {
        *current_path = Some(path);
        changed = true;
    }
    
    changed
}

pub fn advanced_options_panel(ui: &mut egui::Ui, show_advanced: &mut bool) -> bool {
    ui.horizontal(|ui| {
        let button_text = if *show_advanced { "▼ Advanced" } else { "▶ Advanced" };
        
        if ui.button(button_text).clicked() {
            *show_advanced = !*show_advanced;
        }
        
        if !*show_advanced {
            ui.label("Click to show advanced options");
        }
    });
    
    *show_advanced
}