using System;
using System.Data.SQLite;
using System.Windows;
using System.Windows.Threading;
using EnterpriseFileSecurity.Common;
using EnterpriseFileSecurity.Core.Crypto;
using EnterpriseFileSecurity.Core.Services;
using EnterpriseFileSecurity.Data;
using EnterpriseFileSecurity.USB.Services;

namespace EnterpriseFileSecurity.UI;

public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }

    // ── 全局服务引用（供 MainWindow 访问）──
    public static IAuthenticationService AuthService { get; private set; } = null!;
    public static IAccessControlEngine AclEngine { get; private set; } = null!;
    public static IAuditLogger AuditLogger { get; private set; } = null!;
    public static IKeyRotationService KeyRotationService { get; private set; } = null!;
    public static IFileEncryptorService FileEncryptor { get; private set; } = null!;
    public static UsbDeviceMonitor UsbMonitor { get; private set; } = null!;
    public static UsbWhitelistManager UsbWhitelist { get; private set; } = null!;
    public static UsbBlockEngine UsbBlocker { get; private set; } = null!;
    public static MaliciousUsbScanner UsbScanner { get; private set; } = null!;
    public static UsbAlertLogger UsbAlertLogger { get; private set; } = null!;
    public static HotPlugStateManager HotPlugManager { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ── 第一步：确保数据库和文件夹存在 ─────────────────────────────
        DatabaseInitializer.EnsureAllDatabasesCreated();

        // ── 第二步：打开数据库连接 ──────────────────────────────────────
        var keyStoreConn = new SQLiteConnection($"Data Source={DatabaseInitializer.KeyStoreDbPath};Version=3;");
        keyStoreConn.Open();

        // ── 第三步：创建种子管理员账户 ──────────────────────────────────
        DatabaseInitializer.SeedDefaultAdmin(keyStoreConn);

        // ── 第四步：手动构造所有服务 ────────────────────────────────────
        AuthService = new AuthenticationService(keyStoreConn);
        AclEngine = new AccessControlEngine();
        AuditLogger = new AuditLogger(DatabaseInitializer.AuditDbPath);
        KeyRotationService = new KeyRotationService(keyStoreConn, AuthService);
        FileEncryptor = new FileEncryptorService(AuthService, DatabaseInitializer.EncryptedStoragePath);

        // ── USB 服务 ──────────────────────────────────────────────────
        UsbWhitelist = new UsbWhitelistManager();
        UsbBlocker = new UsbBlockEngine();
        UsbScanner = new MaliciousUsbScanner();
        UsbAlertLogger = new UsbAlertLogger(DatabaseInitializer.UsbAlertDbPath);
        HotPlugManager = new HotPlugStateManager();
        UsbMonitor = new UsbDeviceMonitor();

        // ── USB 事件订阅 ──────────────────────────────────────────────
        UsbMonitor.OnDeviceInserted += (deviceInfo) =>
        {
            // 去抖动处理
            if (!HotPlugManager.HandleDeviceInsert(deviceInfo)) return;

            // 恶意设备检测
            if (UsbScanner.ScanDevice(deviceInfo))
            {
                UsbBlocker.BlockDevice(deviceInfo, BlockReason.MaliciousDevice);
                HotPlugManager.MarkBlocked(deviceInfo.PnpDeviceID);
                UsbAlertLogger.LogAlert(deviceInfo, UsbAlertType.MaliciousDeviceBlocked,
                    $"恶意USB设备被拦截: {deviceInfo.Model} ({deviceInfo.VID}:{deviceInfo.PID})");
                return;
            }

            // 白名单检查
            if (!UsbWhitelist.IsDeviceAuthorized(deviceInfo))
            {
                UsbBlocker.BlockDevice(deviceInfo, BlockReason.NotInWhitelist);
                HotPlugManager.MarkBlocked(deviceInfo.PnpDeviceID);
                UsbAlertLogger.LogAlert(deviceInfo, UsbAlertType.UnauthorizedDeviceBlocked,
                    $"未授权USB设备被拦截: {deviceInfo.Model} ({deviceInfo.VID}:{deviceInfo.PID})");
                return;
            }

            // 授权通过
            UsbAlertLogger.LogAlert(deviceInfo, UsbAlertType.AuthorizedDeviceAllowed,
                $"授权USB设备接入: {deviceInfo.Model}");

            // 记录审计日志
            AuditLogger.LogAsync(new AuditEntry
            {
                UserID = SessionContext.CurrentUserID ?? "SYSTEM",
                UserName = Environment.UserName,
                FilePath = deviceInfo.PnpDeviceID ?? "",
                OperationType = FileOperationType.Read,
                Result = AuditResult.Allow,
                Detail = $"USB设备接入: {deviceInfo.Model} (SN:{deviceInfo.SerialNumber})"
            });
        };

        UsbMonitor.OnDeviceRemoved += (deviceInfo) =>
        {
            HotPlugManager.HandleDeviceRemove(deviceInfo);
            UsbAlertLogger.LogAlert(deviceInfo, UsbAlertType.DeviceEjected,
                $"USB设备移除: {deviceInfo.Model}");
        };

        // ── 第五步：将服务注入到 MainWindow ────────────────────────────
        var mainWindow = new MainWindow(
            AuthService, AclEngine, AuditLogger, KeyRotationService, FileEncryptor,
            UsbMonitor, UsbWhitelist, UsbBlocker, UsbScanner, UsbAlertLogger, HotPlugManager);

        // ── 第六步：全局异常处理 ──────────────────────────────────────
        MainWindow = mainWindow;
        DispatcherUnhandledException += (s, args) =>
        {
            MessageBox.Show($"发生未处理的异常：\n{args.Exception.Message}",
                "SecFS 错误", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            string msg = args.ExceptionObject is Exception ex ? ex.Message : "未知错误";
            System.Diagnostics.Debug.WriteLine($"[SecFS] 致命异常: {msg}");
        };

        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        UsbMonitor?.Stop();
        (AuditLogger as IDisposable)?.Dispose();
        base.OnExit(e);
    }
}