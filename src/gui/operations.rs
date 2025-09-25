use std::path::PathBuf;
use tokio::sync::mpsc;
use enc_file::{EncryptOptions, HashAlg, decrypt_file, encrypt_file, encrypt_file_streaming, hash_file, to_hex_lower};
use secrecy::SecretString;

#[derive(Debug)]
pub enum OperationMessage {
    Progress { message: String, progress: Option<f32> },
    Success(String),
    Error(String),
}

pub struct Operation;

impl Operation {
    pub async fn encrypt(
        input: PathBuf,
        output: Option<PathBuf>,
        password: SecretString,
        options: EncryptOptions,
        sender: mpsc::UnboundedSender<OperationMessage>,
    ) {
        let _ = sender.send(OperationMessage::Progress {
            message: "Reading input file...".to_string(),
            progress: Some(0.1),
        });
        
        let result = if options.stream {
            // Use streaming encryption
            let _ = sender.send(OperationMessage::Progress {
                message: "Encrypting with streaming mode...".to_string(),
                progress: Some(0.5),
            });
            
            encrypt_file_streaming(&input, output.as_deref(), password, options)
        } else {
            // Use regular encryption
            let _ = sender.send(OperationMessage::Progress {
                message: "Encrypting file...".to_string(),
                progress: Some(0.5),
            });
            
            encrypt_file(&input, output.as_deref(), password, options)
        };
        
        match result {
            Ok(output_path) => {
                let _ = sender.send(OperationMessage::Success(
                    format!("File encrypted successfully!\nOutput: {}", output_path.display())
                ));
            }
            Err(e) => {
                let _ = sender.send(OperationMessage::Error(
                    format!("Encryption failed: {}", e)
                ));
            }
        }
    }
    
    pub async fn decrypt(
        input: PathBuf,
        output: Option<PathBuf>,
        password: SecretString,
        force_overwrite: bool,
        sender: mpsc::UnboundedSender<OperationMessage>,
    ) {
        let _ = sender.send(OperationMessage::Progress {
            message: "Reading encrypted file...".to_string(),
            progress: Some(0.1),
        });
        
        // Handle force overwrite by removing the file if it exists
        if force_overwrite {
            if let Some(ref output_path) = output {
                if output_path.exists() {
                    let _ = std::fs::remove_file(output_path);
                }
            }
        }
        
        let _ = sender.send(OperationMessage::Progress {
            message: "Decrypting file...".to_string(),
            progress: Some(0.5),
        });
        
        match decrypt_file(&input, output.as_deref(), password) {
            Ok(output_path) => {
                let _ = sender.send(OperationMessage::Success(
                    format!("File decrypted successfully!\nOutput: {}", output_path.display())
                ));
            }
            Err(e) => {
                let _ = sender.send(OperationMessage::Error(
                    format!("Decryption failed: {}", e)
                ));
            }
        }
    }
    
    pub async fn hash(
        input: PathBuf,
        algorithm: HashAlg,
        sender: mpsc::UnboundedSender<OperationMessage>,
    ) {
        let _ = sender.send(OperationMessage::Progress {
            message: "Reading file...".to_string(),
            progress: Some(0.1),
        });
        
        let _ = sender.send(OperationMessage::Progress {
            message: format!("Computing {} hash...", format!("{:?}", algorithm)),
            progress: Some(0.5),
        });
        
        match hash_file(&input, algorithm) {
            Ok(digest) => {
                let hex_hash = to_hex_lower(&digest);
                let _ = sender.send(OperationMessage::Success(
                    format!("Hash calculated successfully!\n\nAlgorithm: {:?}\nFile: {}\nHash: {}", 
                           algorithm, input.display(), hex_hash)
                ));
            }
            Err(e) => {
                let _ = sender.send(OperationMessage::Error(
                    format!("Hash calculation failed: {}", e)
                ));
            }
        }
    }
}