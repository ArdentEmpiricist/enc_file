use eframe::egui;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::gui::operations::{Operation, OperationMessage};
use crate::gui::progress::ProgressState;
use crate::gui::widgets::{file_picker_button, advanced_options_panel};

use enc_file::{AeadAlg, EncryptOptions, HashAlg, KdfAlg, KdfParams};
use secrecy::SecretString;

#[derive(Default)]
pub struct EncFileApp {
    // Current operation mode
    mode: AppMode,
    
    // File paths
    input_file: Option<PathBuf>,
    output_file: Option<PathBuf>,
    
    // Password
    password: String,
    confirm_password: String,
    
    // Basic options
    algorithm: AeadAlg,
    hash_algorithm: HashAlg,
    
    // Advanced options
    show_advanced: bool,
    use_streaming: bool,
    chunk_size: String,
    armor: bool,
    force_overwrite: bool,
    kdf_params: KdfParams,
    
    // Progress and results
    progress: ProgressState,
    operation_result: Option<String>,
    error_message: Option<String>,
    last_completed_operation: Option<AppMode>,
    
    // Runtime state
    operation_handle: Option<tokio::task::JoinHandle<()>>,
    result_receiver: Option<mpsc::UnboundedReceiver<OperationMessage>>,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    Encrypt,
    Decrypt,
    Hash,
}

impl Default for AppMode {
    fn default() -> Self {
        AppMode::Encrypt
    }
}

impl EncFileApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        
        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .expect("Failed to create Tokio runtime")
        );
        
        Self {
            runtime: Some(runtime),
            chunk_size: "0".to_string(), // 0 means auto-sizing
            kdf_params: KdfParams::default(),
            ..Default::default()
        }
    }
}

impl eframe::App for EncFileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle incoming messages from operations
        self.handle_operation_messages();
        
        // Request repaint if operation is running
        if self.progress.is_running() {
            ctx.request_repaint();
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            self.draw_ui(ui);
        });
    }
}

impl EncFileApp {
    fn draw_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔐 EncFile - Secure File Encryption");
        
        ui.add_space(10.0);
        
        // Mode selection
        ui.horizontal(|ui| {
            ui.label("Mode:");
            ui.selectable_value(&mut self.mode, AppMode::Encrypt, "🔒 Encrypt");
            ui.selectable_value(&mut self.mode, AppMode::Decrypt, "🔓 Decrypt");
            ui.selectable_value(&mut self.mode, AppMode::Hash, "🔍 Hash");
        });
        
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);
        
        match self.mode {
            AppMode::Encrypt => self.draw_encrypt_ui(ui),
            AppMode::Decrypt => self.draw_decrypt_ui(ui),
            AppMode::Hash => self.draw_hash_ui(ui),
        }
        
        ui.add_space(20.0);
        
        // Progress and results
        self.draw_progress_ui(ui);
        
        // Results display
        self.draw_results_ui(ui);
    }
    
    fn draw_encrypt_ui(&mut self, ui: &mut egui::Ui) {
        // File selection
        ui.horizontal(|ui| {
            ui.label("Input file:");
            if file_picker_button(ui, "Select file to encrypt", &mut self.input_file) {
                // Auto-suggest output file
                if let Some(ref input) = self.input_file {
                    let mut output = input.clone();
                    output.set_extension("enc");
                    self.output_file = Some(output);
                }
            }
        });
        
        if let Some(ref path) = self.input_file {
            ui.label(format!("📁 {}", path.display()));
        }
        
        ui.add_space(5.0);
        
        ui.horizontal(|ui| {
            ui.label("Output file:");
            file_picker_button(ui, "Choose output location", &mut self.output_file);
        });
        
        if let Some(ref path) = self.output_file {
            ui.label(format!("💾 {}", path.display()));
        }
        
        ui.add_space(10.0);
        
        // Password
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password)
                .password(true)
                .desired_width(200.0));
        });
        
        ui.horizontal(|ui| {
            ui.label("Confirm:");
            ui.add(egui::TextEdit::singleline(&mut self.confirm_password)
                .password(true)
                .desired_width(200.0));
        });
        
        // Password strength indicator
        if !self.password.is_empty() {
            let strength = self.get_password_strength();
            ui.horizontal(|ui| {
                ui.label("Strength:");
                match strength {
                    0..=20 => ui.colored_label(egui::Color32::RED, "Very Weak"),
                    21..=40 => ui.colored_label(egui::Color32::from_rgb(255, 165, 0), "Weak"),
                    41..=60 => ui.colored_label(egui::Color32::YELLOW, "Fair"),
                    61..=80 => ui.colored_label(egui::Color32::from_rgb(173, 255, 47), "Good"),
                    _ => ui.colored_label(egui::Color32::GREEN, "Strong"),
                };
            });
        }
        
        ui.add_space(10.0);
        
        // Basic algorithm selection
        ui.horizontal(|ui| {
            ui.label("Algorithm:");
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", self.algorithm))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.algorithm, AeadAlg::XChaCha20Poly1305, "XChaCha20-Poly1305 (Recommended)");
                    ui.selectable_value(&mut self.algorithm, AeadAlg::Aes256GcmSiv, "AES-256-GCM-SIV");
                });
        });
        
        ui.add_space(10.0);
        
        // Advanced options
        if advanced_options_panel(ui, &mut self.show_advanced) {
            self.draw_advanced_encrypt_options(ui);
        }
        
        ui.add_space(15.0);
        
        // Action button
        let can_encrypt = self.input_file.is_some() 
            && !self.password.is_empty() 
            && self.password == self.confirm_password
            && !self.progress.is_running();
            
        ui.horizontal(|ui| {
            if ui.add_enabled(can_encrypt, egui::Button::new("🔒 Encrypt File").min_size(egui::vec2(120.0, 30.0))).clicked() {
                self.start_encrypt_operation();
            }
            
            if !can_encrypt && !self.progress.is_running() {
                let reason = if self.input_file.is_none() {
                    "Select an input file"
                } else if self.password.is_empty() {
                    "Enter a password"
                } else if self.password != self.confirm_password {
                    "Passwords don't match"
                } else {
                    "Check all fields"
                };
                ui.label(egui::RichText::new(reason).color(egui::Color32::GRAY));
            }
        });
    }
    
    fn draw_decrypt_ui(&mut self, ui: &mut egui::Ui) {
        // File selection
        ui.horizontal(|ui| {
            ui.label("Encrypted file:");
            if file_picker_button(ui, "Select encrypted file", &mut self.input_file) {
                // Auto-suggest output file (remove .enc or add .dec)
                if let Some(ref input) = self.input_file {
                    let output = enc_file::default_decrypt_output_path(input);
                    self.output_file = Some(output);
                }
            }
        });
        
        if let Some(ref path) = self.input_file {
            ui.label(format!("🔒 {}", path.display()));
        }
        
        ui.add_space(5.0);
        
        ui.horizontal(|ui| {
            ui.label("Output file:");
            file_picker_button(ui, "Choose output location", &mut self.output_file);
        });
        
        if let Some(ref path) = self.output_file {
            ui.label(format!("💾 {}", path.display()));
        }
        
        ui.add_space(10.0);
        
        // Password
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password)
                .password(true)
                .desired_width(200.0));
        });
        
        ui.add_space(10.0);
        
        // Advanced options
        if advanced_options_panel(ui, &mut self.show_advanced) {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.force_overwrite, "Force overwrite existing files");
            });
        }
        
        ui.add_space(15.0);
        
        // Action button
        let can_decrypt = self.input_file.is_some() 
            && !self.password.is_empty() 
            && !self.progress.is_running();
            
        ui.horizontal(|ui| {
            if ui.add_enabled(can_decrypt, egui::Button::new("🔓 Decrypt File").min_size(egui::vec2(120.0, 30.0))).clicked() {
                self.start_decrypt_operation();
            }
            
            if !can_decrypt && !self.progress.is_running() {
                let reason = if self.input_file.is_none() {
                    "Select an encrypted file"
                } else if self.password.is_empty() {
                    "Enter the password"
                } else {
                    "Check all fields"
                };
                ui.label(egui::RichText::new(reason).color(egui::Color32::GRAY));
            }
        });
    }
    
    fn draw_hash_ui(&mut self, ui: &mut egui::Ui) {
        // File selection
        ui.horizontal(|ui| {
            ui.label("Input file:");
            file_picker_button(ui, "Select file to hash", &mut self.input_file);
        });
        
        if let Some(ref path) = self.input_file {
            ui.label(format!("📁 {}", path.display()));
        }
        
        ui.add_space(10.0);
        
        // Hash algorithm selection
        ui.horizontal(|ui| {
            ui.label("Hash algorithm:");
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", self.hash_algorithm))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.hash_algorithm, HashAlg::Blake3, "BLAKE3 (Recommended)");
                    ui.selectable_value(&mut self.hash_algorithm, HashAlg::Sha256, "SHA-256");
                    ui.selectable_value(&mut self.hash_algorithm, HashAlg::Sha512, "SHA-512");
                    ui.selectable_value(&mut self.hash_algorithm, HashAlg::Sha3_256, "SHA3-256");
                    ui.selectable_value(&mut self.hash_algorithm, HashAlg::Blake2b, "BLAKE2b");
                });
        });
        
        ui.add_space(15.0);
        
        // Action button
        let can_hash = self.input_file.is_some() && !self.progress.is_running();
            
        ui.horizontal(|ui| {
            if ui.add_enabled(can_hash, egui::Button::new("🔍 Calculate Hash").min_size(egui::vec2(120.0, 30.0))).clicked() {
                self.start_hash_operation();
            }
            
            if !can_hash && !self.progress.is_running() {
                ui.label(egui::RichText::new("Select a file to hash").color(egui::Color32::GRAY));
            }
        });
    }
    
    fn draw_advanced_encrypt_options(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Advanced Options").strong());
            
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.use_streaming, "Use streaming mode");
                ui.label(egui::RichText::new("(for large files)").color(egui::Color32::GRAY));
            });
            
            if self.use_streaming {
                ui.horizontal(|ui| {
                    ui.label("Chunk size (bytes):");
                    ui.add(egui::TextEdit::singleline(&mut self.chunk_size)
                        .desired_width(100.0));
                    ui.label(egui::RichText::new("(0 = auto)").color(egui::Color32::GRAY));
                });
            }
            
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.armor, "ASCII armor output");
                ui.label(egui::RichText::new("(Base64 encoding)").color(egui::Color32::GRAY));
            });
            
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.force_overwrite, "Force overwrite existing files");
            });
            
            ui.separator();
            
            ui.label(egui::RichText::new("Key Derivation (KDF) Parameters").strong());
            
            ui.horizontal(|ui| {
                ui.label("Memory cost (KiB):");
                ui.add(egui::DragValue::new(&mut self.kdf_params.mem_kib)
                    .range(1024..=1_048_576)
                    .speed(1024));
            });
            
            ui.horizontal(|ui| {
                ui.label("Time cost (iterations):");
                ui.add(egui::DragValue::new(&mut self.kdf_params.t_cost)
                    .range(1..=10)
                    .speed(1));
            });
            
            ui.horizontal(|ui| {
                ui.label("Parallelism:");
                ui.add(egui::DragValue::new(&mut self.kdf_params.parallelism)
                    .range(1..=16)
                    .speed(1));
            });
        });
    }
    
    fn draw_progress_ui(&mut self, ui: &mut egui::Ui) {
        if self.progress.is_running() {
            ui.separator();
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("🔄 ");
                ui.label(&self.progress.message);
            });
            
            if let Some(progress) = self.progress.progress {
                ui.add(egui::ProgressBar::new(progress).text(format!("{}%", (progress * 100.0) as u32)));
            } else {
                ui.add(egui::ProgressBar::new(0.0).animate(true));
            }
            
            ui.add_space(5.0);
        }
    }
    
    pub fn extract_hash_from_result(&self, result: &str) -> Option<String> {
        // Hash results have format: "Hash calculated successfully!\n\nAlgorithm: ...\nFile: ...\nHash: <hash_value>"
        if let Some(hash_line) = result.lines().find(|line| line.starts_with("Hash: ")) {
            return hash_line.strip_prefix("Hash: ").map(|s| s.to_string());
        }
        None
    }
    
    fn draw_results_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(ref result) = self.operation_result.clone() {
            ui.separator();
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("✅ ");
                ui.label("Operation completed successfully!");
            });
            
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .max_height(100.0)
                    .show(ui, |ui| {
                        ui.add(egui::TextEdit::multiline(&mut result.clone())
                            .desired_width(f32::INFINITY)
                            .code_editor());
                    });
            });
            
            ui.horizontal(|ui| {
                // Handle hash operations differently
                if let Some(AppMode::Hash) = self.last_completed_operation {
                    if ui.button("📋 Copy hash to clipboard").clicked() {
                        if let Some(hash_value) = self.extract_hash_from_result(result) {
                            ui.output_mut(|o| o.copied_text = hash_value);
                        } else {
                            // Fallback to copying entire result if hash extraction fails
                            ui.output_mut(|o| o.copied_text = result.clone());
                        }
                    }
                } else {
                    if ui.button("📋 Copy to Clipboard").clicked() {
                        ui.output_mut(|o| o.copied_text = result.clone());
                    }
                }
                
                if ui.button("🗑 Clear").clicked() {
                    self.operation_result = None;
                    self.last_completed_operation = None;
                }
            });
        }
        
        if let Some(ref error) = self.error_message {
            ui.separator();
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("❌ ");
                ui.colored_label(egui::Color32::RED, "Error occurred:");
            });
            
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.colored_label(egui::Color32::RED, error);
            });
            
            ui.horizontal(|ui| {
                if ui.button("🗑 Clear").clicked() {
                    self.error_message = None;
                }
            });
        }
    }
    
    fn get_password_strength(&self) -> u32 {
        let password = &self.password;
        let mut score = 0u32;
        
        if password.len() >= 8 { score += 20; }
        if password.len() >= 12 { score += 10; }
        if password.len() >= 16 { score += 10; }
        
        if password.chars().any(|c| c.is_ascii_lowercase()) { score += 10; }
        if password.chars().any(|c| c.is_ascii_uppercase()) { score += 10; }
        if password.chars().any(|c| c.is_ascii_digit()) { score += 10; }
        if password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) { score += 20; }
        
        score.min(100)
    }
    
    fn handle_operation_messages(&mut self) {
        let mut messages_to_process = Vec::new();
        
        if let Some(ref mut receiver) = self.result_receiver {
            while let Ok(message) = receiver.try_recv() {
                messages_to_process.push(message);
            }
        }
        
        for message in messages_to_process {
            match message {
                OperationMessage::Progress { message, progress } => {
                    self.progress.message = message;
                    self.progress.progress = progress;
                }
                OperationMessage::Success(result) => {
                    self.progress.reset();
                    self.operation_result = Some(result);
                    self.error_message = None;
                    self.last_completed_operation = Some(self.mode);
                    self.result_receiver = None;
                }
                OperationMessage::Error(error) => {
                    self.progress.reset();
                    self.error_message = Some(error);
                    self.operation_result = None;
                    self.last_completed_operation = None;
                    self.result_receiver = None;
                }
            }
        }
    }
    
    fn start_encrypt_operation(&mut self) {
        let input = self.input_file.clone().unwrap();
        let output = self.output_file.clone();
        let password = SecretString::new(self.password.clone().into());
        
        let chunk_size = if self.use_streaming {
            self.chunk_size.parse().unwrap_or(0)
        } else {
            0
        };
        
        let options = EncryptOptions {
            alg: self.algorithm,
            kdf: KdfAlg::Argon2id,
            kdf_params: self.kdf_params.clone(),
            armor: self.armor,
            force: self.force_overwrite,
            stream: self.use_streaming,
            chunk_size,
        };
        
        let (sender, receiver) = mpsc::unbounded_channel();
        self.result_receiver = Some(receiver);
        self.progress.start("Starting encryption...");
        
        let rt = self.runtime.as_ref().unwrap().clone();
        self.operation_handle = Some(rt.spawn(async move {
            Operation::encrypt(input, output, password, options, sender).await;
        }));
    }
    
    fn start_decrypt_operation(&mut self) {
        let input = self.input_file.clone().unwrap();
        let output = self.output_file.clone();
        let password = SecretString::new(self.password.clone().into());
        let force_overwrite = self.force_overwrite;
        
        let (sender, receiver) = mpsc::unbounded_channel();
        self.result_receiver = Some(receiver);
        self.progress.start("Starting decryption...");
        
        let rt = self.runtime.as_ref().unwrap().clone();
        self.operation_handle = Some(rt.spawn(async move {
            Operation::decrypt(input, output, password, force_overwrite, sender).await;
        }));
    }
    
    fn start_hash_operation(&mut self) {
        let input = self.input_file.clone().unwrap();
        let algorithm = self.hash_algorithm;
        
        let (sender, receiver) = mpsc::unbounded_channel();
        self.result_receiver = Some(receiver);
        self.progress.start("Calculating hash...");
        
        let rt = self.runtime.as_ref().unwrap().clone();
        self.operation_handle = Some(rt.spawn(async move {
            Operation::hash(input, algorithm, sender).await;
        }));
    }
}