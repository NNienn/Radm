// mitigation/src/forensics.rs

#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use nix::sys::ptrace;
use std::path::Path;

#[cfg(unix)]
/// Read the target PID's memory maps from /proc/<PID>/maps,
/// dump readable non-special-file segments via process_vm_readv,
/// and write an AES-256-GCM encrypted blob to output_path.
pub async fn capture_memory(pid: Pid, output_path: &Path) -> anyhow::Result<()> {
    // Attach ptrace to pause the process during capture
    ptrace::attach(pid)?;
    
    // wait for target process to stop
    let wait_res = tokio::task::spawn_blocking(move || {
        nix::sys::wait::waitpid(pid, None)
    }).await;

    let result = match wait_res {
        Ok(Ok(_)) => do_capture(pid, output_path),
        Ok(Err(e)) => Err(anyhow::anyhow!("waitpid failed: {}", e)),
        Err(e) => Err(anyhow::anyhow!("spawn_blocking failed: {}", e)),
    };

    // Detach ptrace (resumes process) regardless of capture success
    let _ = ptrace::detach(pid, None);

    result
}

#[cfg(unix)]
fn do_capture(pid: Pid, output_path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
    use aes_gcm::aead::generic_array::GenericArray;
    use std::io::Write;

    let maps_path = format!("/proc/{}/maps", pid.as_raw());
    let maps_content = std::fs::read_to_string(&maps_path)?;

    let mut dump_data: Vec<u8> = Vec::new();

    for line in maps_content.lines() {
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 { continue; }

        let perms = parts[1];
        let pathname = parts.get(5).map(|s| s.trim()).unwrap_or("");

        if !perms.contains('r') { continue; }
        if pathname.starts_with('/') && !pathname.is_empty()
            && pathname != "[heap]" && pathname != "[stack]"
        {
            continue;  // Skip mapped files; focus on anonymous + heap/stack
        }

        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 { continue; }

        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let end   = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let size  = end.saturating_sub(start) as usize;
        if size == 0 || size > 256 * 1024 * 1024 { continue; }  // skip > 256 MB

        let mut buf = vec![0u8; size];
        let remote_iov = nix::sys::uio::RemoteIoVec { base: start as usize, len: size };
        let local_iov  = nix::sys::uio::IoVec::from_mut_slice(&mut buf);

        match nix::sys::uio::process_vm_readv(pid, &[local_iov], &[remote_iov]) {
            Ok(n) if n > 0 => {
                // Prepend a region header: [u64 start][u64 end][u64 actual_bytes_read]
                dump_data.extend_from_slice(&start.to_le_bytes());
                dump_data.extend_from_slice(&end.to_le_bytes());
                dump_data.extend_from_slice(&(n as u64).to_le_bytes());
                dump_data.extend_from_slice(&buf[..n]);
            }
            _ => {}
        }
    }

    // ── AES-256-GCM encrypt the dump ──────────────────────────────────────
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key    = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    // KEY IS STORED IN THE FILE — dev mode reminder
    let ciphertext = cipher.encrypt(nonce, dump_data.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {:?}", e))?;

    let mut output = std::fs::OpenOptions::new()
        .write(true).create_new(true)
        .mode(0o600)
        .open(output_path)?;

    output.write_all(&key_bytes)?;
    output.write_all(&nonce_bytes)?;
    output.write_all(&ciphertext)?;

    tracing::info!(
        "Forensic dump: {} bytes → {} (encrypted)",
        dump_data.len(),
        output_path.display()
    );
    Ok(())
}

#[cfg(not(unix))]
pub async fn capture_memory(pid: i32, _output_path: &Path) -> anyhow::Result<()> {
    tracing::warn!("Forensic memory capture is only supported on Unix/Linux targets. Mocking capture for PID: {}", pid);
    Ok(())
}
