fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();

        // Embed the .ico so Explorer / taskbar / Alt+Tab shows the icon
        res.set_icon("assets/icon.ico");

        // Publisher / version strings shown in Add/Remove Programs and UAC prompts
        res.set("ProductName", "rfshare");
        res.set("FileDescription", "Fast, encrypted file transfers");
        res.set("CompanyName", "Imrany");
        res.set("LegalCopyright", "Copyright © 2026 Imrany");
        res.set("ProductVersion", "0.17.1");
        res.set("FileVersion", "0.17.1");

        // Request the lowest privilege level — prevents UAC elevation prompts.
        // The app only uses local network sockets; it needs no admin rights.
        res.set_manifest(
            r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="0.5.0.0" processorArchitecture="*"
                    name="dev.rfshare.app" type="win32"/>
  <description>rfshare — fast encrypted LAN file transfers</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <!-- asInvoker = run as the launching user, no elevation, no UAC prompt -->
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 / 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <!-- Windows 8.1 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
</assembly>
"#,
        );

        if let Err(e) = res.compile() {
            eprintln!("winresource error (non-fatal): {}", e);
        }
    }
}
