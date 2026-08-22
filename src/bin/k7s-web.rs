//! k7s-web — the browser-facing shell's entry point.
//!
//! Boots a tokio runtime, builds a [`k7s_server::web::WebState`] (kube client +
//! watchers + SSE plumbing all wired up to a fresh `WebEventSink`), and
//! serves an axum router.
//!
//! Features:
//! - **Auto port selection**: tries the preferred port, then increments until
//!   an available port is found.
//! - **Auto browser open**: opens the default browser to the serving URL.
//! - **Embedded assets**: serves the built React app from compile-time
//!   embedded files when no `--static` dir is given.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};

use k7s_server::web::{serve, WebState};

#[k7s_deps::tokio::main]
async fn main() -> std::io::Result<()> {
    // Install the rustls crypto provider before any TLS connections are made.
    let _ = k7s_deps::rustls::crypto::ring::default_provider().install_default();

    // Match the Tauri shell's default level so logs feel familiar.
    k7s_deps::tracing_subscriber::fmt()
        .with_env_filter(
            k7s_deps::tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| k7s_deps::tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = parse_args();

    // ── Address selection ─────────────────────────────────────────────
    let addr = if let Some(a) = args.addr {
        a
    } else {
        pick_port(args.bind, args.preferred_port).await
    };

    // Where prefs and any future state lives.
    let data_dir = k7s_server::default_data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        k7s_deps::tracing::warn!("could not create {}: {e}", data_dir.display());
    }

    // Validate --static if given.
    if let Some(dir) = &args.static_dir {
        if !dir.join("index.html").exists() {
            k7s_deps::tracing::error!(
                "{} does not contain index.html — did you `npm run build`?",
                dir.display()
            );
            std::process::exit(1);
        }
    }

    // Determine whether to use embedded assets.
    let use_embedded = args.static_dir.is_none();

    let state = WebState::new(data_dir, addr);

    // ── Startup banner ──────────────────────────────────────────────
    let version = env!("CARGO_PKG_VERSION");
    let url = format!("http://{addr}");

    // Collect non-loopback IPv4 addresses for LAN access hints.
    let lan_ips: Vec<String> = local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, addr)| match addr {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_link_local() => {
                Some(v4.to_string())
            }
            _ => None,
        })
        .collect();

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());
    // Truncate hostname if too long for the banner box.
    let hostname = if hostname.len() > 24 {
        format!("{}…", &hostname[..23])
    } else {
        hostname
    };
    let os_info = format!(
        "{} {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        hostname
    );

    // Build the LAN lines first to measure the box width.
    let mut lan_lines: Vec<String> = Vec::new();
    if addr.ip().is_unspecified() {
        for ip in &lan_ips {
            lan_lines.push(format!("http://{}:{}", ip, addr.port()));
        }
    }
    // Box width: enough for the longest content line, minimum 48.
    let content_width = lan_lines
        .iter()
        .map(|s| s.len() + 12) // "  LAN      : " prefix
        .chain(std::iter::once(os_info.len() + 12))
        .chain(std::iter::once(url.len() + 12))
        .chain(std::iter::once(format!("v{}", version).len() + 16))
        .max()
        .unwrap_or(48)
        .max(48);
    let w = content_width; // inner width

    println!();
    println!("  ╔{}╗", "═".repeat(w));
    println!(
        "  ║{:^width$}║",
        format!("k7s-web  v{}", version),
        width = w
    );
    println!("  ╠{}╣", "═".repeat(w));
    println!("  ║  Platform : {:<width$}║", os_info, width = w - 13);
    println!("  ║  Local    : {:<width$}║", url, width = w - 13);
    if addr.ip().is_unspecified() {
        if lan_lines.is_empty() {
            println!(
                "  ║  LAN      : {:<width$}║",
                "(no non-loopback IPv4 found)",
                width = w - 13
            );
        } else {
            for lan in &lan_lines {
                println!("  ║  LAN      : {:<width$}║", lan, width = w - 13);
            }
        }
    } else if !addr.ip().is_loopback() {
        println!("  ║  Bind     : {:<width$}║", url, width = w - 13);
    }
    println!("  ╚{}╝", "═".repeat(w));
    println!();

    k7s_deps::tracing::info!("k7s-web v{version} listening on {url}");

    // ── Auto-open browser ────────────────────────────────────────────
    // Only try when a browser is actually present — the static build often
    // runs on headless servers where a failed xdg-open is just noise.
    if !args.no_open {
        if browser_available() {
            if let Err(e) = open::that(&url) {
                k7s_deps::tracing::warn!("failed to open browser: {e}");
            }
        } else {
            k7s_deps::tracing::info!(
                "no browser detected on this host (server/headless?) — skipping auto-open"
            );
        }
    }

    // ── Start server ─────────────────────────────────────────────────
    k7s_deps::tokio::select! {
        result = serve(addr, state, args.static_dir, use_embedded) => {
            result?;
        }
        _ = k7s_deps::tokio::signal::ctrl_c() => {
            k7s_deps::tracing::info!("Ctrl+C received, shutting down");
        }
    }

    Ok(())
}

/// Try to bind to `preferred` port on `bind_ip`; if busy, try the next 100 ports.
async fn pick_port(bind_ip: IpAddr, preferred: u16) -> SocketAddr {
    let addr = SocketAddr::new(bind_ip, preferred);
    if StdTcpListener::bind(addr).is_ok() {
        return addr;
    }
    for port in (preferred + 1)..=(preferred + 100) {
        let addr = SocketAddr::new(bind_ip, port);
        if StdTcpListener::bind(addr).is_ok() {
            k7s_deps::tracing::info!("port {preferred} busy, using {port}");
            return addr;
        }
    }
    let listener = StdTcpListener::bind(SocketAddr::new(bind_ip, 0)).expect("bind to port 0");
    let addr = listener.local_addr().expect("get local addr");
    k7s_deps::tracing::info!("port {preferred}+ busy, OS assigned {addr}");
    addr
}

// ── CLI argument parsing ─────────────────────────────────────────────

fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!();
    eprintln!("  k7s-web v{version} — Kubernetes 可视化监控 Web 服务");
    eprintln!();
    eprintln!("  用法:");
    eprintln!("    k7s-web [选项]");
    eprintln!();
    eprintln!("  网络选项:");
    eprintln!("    --bind <IP>           绑定监听地址 (默认: 127.0.0.1)");
    eprintln!("                          0.0.0.0  = 监听所有网卡 (局域网可访问)");
    eprintln!("                          127.0.0.1 = 仅本机访问");
    eprintln!("                          192.168.x.x = 绑定指定网卡");
    eprintln!("    --port <PORT>         监听端口 (默认: 7180)");
    eprintln!("                          端口占用时自动递增尝试下一个");
    eprintln!("    --addr <IP:PORT>      完整监听地址 (覆盖 --bind 和 --port)");
    eprintln!();
    eprintln!("  资源选项:");
    eprintln!("    --static <DIR>        从指定目录加载前端资源");
    eprintln!("                          (默认使用编译时内嵌的前端包)");
    eprintln!("    --no-open             启动后不自动打开浏览器");
    eprintln!();
    eprintln!("  其他:");
    eprintln!("    -V, --version         显示版本号");
    eprintln!("    -h, --help            显示本帮助信息");
    eprintln!();
    eprintln!("  环境变量:");
    eprintln!("    K7S_WEB_TOKEN         API 访问令牌 (loopback 自动生成，非 loopback 需设置)");
    eprintln!("    K7S_HOOK_TOKEN        Webhook 访问令牌 (不设置则 webhook 禁用)");
    eprintln!("    K7S_ALLOWED_ORIGINS   允许的 CORS 源 (逗号分隔)");
    eprintln!("    RUST_LOG              日志级别 (默认: info，可选: debug, warn, error)");
    eprintln!();
    eprintln!("  使用示例:");
    eprintln!();
    eprintln!("    # 本地开发 (仅本机访问，自动打开浏览器)");
    eprintln!("    k7s-web");
    eprintln!();
    eprintln!("    # 指定端口");
    eprintln!("    k7s-web --port 8080");
    eprintln!();
    eprintln!("    # 局域网可访问 (所有网卡)");
    eprintln!("    k7s-web --bind 0.0.0.0");
    eprintln!();
    eprintln!("    # 局域网可访问 + 指定端口");
    eprintln!("    k7s-web --bind 0.0.0.0 --port 80");
    eprintln!();
    eprintln!("    # 绑定指定网卡");
    eprintln!("    k7s-web --bind 192.168.1.100 --port 3000");
    eprintln!();
    eprintln!("    # 指定完整地址");
    eprintln!("    k7s-web --addr 10.10.30.79:7180");
    eprintln!();
    eprintln!("    # 使用外部前端资源 (开发模式，支持热更新)");
    eprintln!("    k7s-web --static ./k7s-frontend/dist --port 5173");
    eprintln!();
    eprintln!("    # 生产部署 (后台运行，不打开浏览器)");
    eprintln!("    nohup k7s-web --bind 0.0.0.0 --port 80 --no-open &");
    eprintln!();
    eprintln!("    # 启用调试日志");
    eprintln!("    RUST_LOG=debug k7s-web");
    eprintln!();
    eprintln!("    # 带 webhook 令牌启动");
    eprintln!("    K7S_HOOK_TOKEN=my-secret k7s-web --bind 0.0.0.0");
    eprintln!();
    eprintln!("  Docker:");
    eprintln!("    docker run -p 7180:7180 k7s-web --bind 0.0.0.0 --no-open");
    eprintln!();
    eprintln!("  访问方式:");
    eprintln!("    启动后终端会显示访问地址，格式如:");
    eprintln!("      Local : http://127.0.0.1:7180");
    eprintln!("      LAN   : http://192.168.x.x:7180   (仅 --bind 0.0.0.0 时显示)");
    eprintln!();
    eprintln!("    浏览器打开上述地址即可使用 Kubernetes 可视化监控。");
    eprintln!("    局域网内其他设备使用 LAN 地址访问。");
    eprintln!();
}

struct Args {
    addr: Option<SocketAddr>,
    bind: IpAddr,
    preferred_port: u16,
    static_dir: Option<std::path::PathBuf>,
    no_open: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: None,
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        preferred_port: 7180,
        static_dir: None,
        no_open: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" => {
                args.addr = iter.next().and_then(|s| s.parse().ok());
            }
            "--bind" => {
                if let Some(s) = iter.next() {
                    match s.parse::<IpAddr>() {
                        Ok(ip) => args.bind = ip,
                        Err(e) => {
                            eprintln!("invalid --bind address '{s}': {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
            "--port" => {
                args.preferred_port = iter.next().and_then(|s| s.parse().ok()).unwrap_or(7180);
            }
            "--static" | "--static-dir" => {
                args.static_dir = iter.next().map(std::path::PathBuf::from);
            }
            "--no-open" => {
                args.no_open = true;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                eprintln!("k7s-web v{}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                k7s_deps::tracing::warn!("ignoring unknown arg: {other}");
            }
        }
    }
    args
}

// ---------------------------------------------------------------------------
// Browser detection — decide whether auto-open is worth attempting.
// ---------------------------------------------------------------------------

/// Is `bin` an executable file on PATH?
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

/// Best-effort "does this host have a browser to open?" check.
///
/// The static binary often runs on servers: no GUI session, no browser
/// installed. Trying to open there only produces a confusing failure —
/// detect and skip instead. `--no-open` stays the explicit override.
fn browser_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // No graphical session → nowhere for a browser window to land.
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        const CANDIDATES: &[&str] = &[
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "firefox",
            "firefox-esr",
            "microsoft-edge",
            "brave-browser",
            // Not a browser, but if xdg-open exists it knows the default.
            "xdg-open",
        ];
        CANDIDATES.iter().any(|c| which(c))
    }
    #[cfg(target_os = "macos")]
    {
        const APPS: &[&str] = &[
            "/Applications/Google Chrome.app",
            "/Applications/Chromium.app",
            "/Applications/Firefox.app",
            "/Applications/Microsoft Edge.app",
            "/Applications/Brave Browser.app",
            "/Applications/Safari.app",
        ];
        APPS.iter().any(|p| std::path::Path::new(p).exists())
    }
    #[cfg(target_os = "windows")]
    {
        const CANDIDATES: &[&str] = &["chrome.exe", "msedge.exe"];
        const PATHS: &[&str] = &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ];
        CANDIDATES.iter().any(|c| which(c))
            || PATHS.iter().any(|p| std::path::Path::new(p).is_file())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn which_finds_a_known_binary() {
        // `cargo`/`rustc` are on PATH whenever tests run.
        assert!(which("cargo") || which("rustc"));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn which_rejects_missing_binary() {
        assert!(!which("definitely-not-a-real-binary-k7s"));
    }

    #[test]
    fn browser_available_never_panics() {
        // Environment-dependent by nature; the contract is only "no panic".
        let _ = browser_available();
    }
}
