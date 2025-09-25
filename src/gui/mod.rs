mod app;
mod operations;
mod progress;
mod widgets;

pub use app::EncFileApp;

#[cfg(test)]
mod tests {
    use crate::gui::app::AppMode;
    use crate::gui::progress::ProgressState;
    
    #[test]
    fn test_app_creation() {
        // We can't fully test the app without an actual egui context,
        // but we can test that it compiles and basic structures work
        let app_mode = AppMode::default();
        assert_eq!(app_mode, AppMode::Encrypt);
    }
    
    #[test] 
    fn test_progress_state() {
        let mut progress = ProgressState::default();
        assert!(!progress.is_running());
        
        progress.start("Testing");
        assert!(progress.is_running());
        assert_eq!(progress.message, "Testing");
        
        progress.reset();
        assert!(!progress.is_running());
    }
}