mod app;
mod operations;
mod progress;
mod widgets;

pub use app::EncFileApp;

#[cfg(test)]
mod tests {
    use crate::gui::app::{AppMode, EncFileApp};
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
    
    #[test]
    fn test_hash_extraction() {
        let app = EncFileApp::default();
        
        // Test successful hash extraction
        let result = "Hash calculated successfully!\n\nAlgorithm: Blake3\nFile: /path/to/file.txt\nHash: 8e3d0e03b2a56699b6f40000b6f3c48dbe7a8d347be15f57993cce6aa075a891";
        let extracted = app.extract_hash_from_result(result);
        assert_eq!(extracted, Some("8e3d0e03b2a56699b6f40000b6f3c48dbe7a8d347be15f57993cce6aa075a891".to_string()));
        
        // Test with different algorithm
        let result2 = "Hash calculated successfully!\n\nAlgorithm: Sha256\nFile: /another/file.txt\nHash: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let extracted2 = app.extract_hash_from_result(result2);
        assert_eq!(extracted2, Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()));
        
        // Test with invalid format (should return None)
        let invalid_result = "Some other result without hash line";
        let extracted3 = app.extract_hash_from_result(invalid_result);
        assert_eq!(extracted3, None);
        
        // Test with empty string
        let empty_result = "";
        let extracted4 = app.extract_hash_from_result(empty_result);
        assert_eq!(extracted4, None);
    }
}