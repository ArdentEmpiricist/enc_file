#[derive(Default)]
pub struct ProgressState {
    pub message: String,
    pub progress: Option<f32>, // None for indeterminate, Some(0.0-1.0) for determinate
    running: bool,
}

impl ProgressState {
    pub fn start(&mut self, message: &str) {
        self.message = message.to_string();
        self.progress = None;
        self.running = true;
    }
    
    pub fn reset(&mut self) {
        self.message.clear();
        self.progress = None;
        self.running = false;
    }
    
    pub fn is_running(&self) -> bool {
        self.running
    }
}