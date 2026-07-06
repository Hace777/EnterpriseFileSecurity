using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using EnterpriseFileSecurity.Common;
using EnterpriseFileSecurity.Core.Services;
using EnterpriseFileSecurity.USB.Services;

namespace EnterpriseFileSecurity.UI;

public partial class MainWindow : Window
{
    private readonly IAuthenticationService _auth;
    private readonly IAccessControlEngine _acl;
    private readonly IAuditLogger _audit;
    private readonly IKeyRotationService _keyRot;
    private readonly IFileEncryptorService _fileEnc;
    private readonly UsbDeviceMonitor _usbMon;
    private readonly UsbWhitelistManager _usbWl;
    private readonly UsbBlockEngine _usbBlk;
    private readonly MaliciousUsbScanner _usbScan;
    private readonly UsbAlertLogger _usbAlert;
    private readonly HotPlugStateManager _usbHot;

    private AuthResult? _currentAuth;
    private bool _usbMonitoringActive;

    public MainWindow(
        IAuthenticationService auth, IAccessControlEngine acl, IAuditLogger audit,
        IKeyRotationService keyRot, IFileEncryptorService fileEnc,
        UsbDeviceMonitor usbMon, UsbWhitelistManager usbWl, UsbBlockEngine usbBlk,
        MaliciousUsbScanner usbScan, UsbAlertLogger usbAlert, HotPlugStateManager usbHot)
    {
        InitializeComponent();
        _auth = auth;
        _acl = acl;
        _audit = audit;
        _keyRot = keyRot;
        _fileEnc = fileEnc;
        _usbMon = usbMon;
        _usbWl = usbWl;
        _usbBlk = usbBlk;
        _usbScan = usbScan;
        _usbAlert = usbAlert;
        _usbHot = usbHot;

        TxtStatus.Text = "状态：就绪（未登录）";
        TxtFooter.Text = $"KeyStore: {DatabaseInitializer.KeyStoreDbPath}  |  Vault: {DatabaseInitializer.EncryptedStoragePath}";
    }

    #region ── 登录面板 ──

    private void BtnLogin_Click(object sender, RoutedEventArgs e)
    {
        ClearContent();
        AddTitle("用户登录");

        AddLabel("用户名:");
        var txtUser = AddTextBox("", 250);
        AddLabel("密码:");
        var txtPwd = new PasswordBox { Width = 250, Margin = new Thickness(0, 0, 0, 8) };
        ContentPanel.Children.Add(txtPwd);

        var btnLogin = new Button { Content = "登录", Width = 100, Height = 32, Margin = new Thickness(0, 5, 0, 5) };
        var lblResult = AddLabel("", 12, Brushes.Gray);

        btnLogin.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(txtUser.Text) || string.IsNullOrWhiteSpace(txtPwd.Password))
            { lblResult.Text = "用户名和密码不能为空"; return; }

            try
            {
                var result = _auth.Login(txtUser.Text.Trim(), txtPwd.Password);
                if (result.Success)
                {
                    _currentAuth = result;
                    SessionContext.SetSession(result.UserID, (UserRole)result.RoleID, result.PrivateKey);
                    TxtStatus.Text = $"状态：已登录 — {result.UserName} ({RoleName((UserRole)result.RoleID)})";
                    lblResult.Foreground = Brushes.Green;
                    lblResult.Text = $"登录成功！欢迎 {result.UserName}。";

                    // 显示/隐藏管理员按钮
                    BtnAdmin.Visibility = (UserRole)result.RoleID == UserRole.GeneralManager
                        ? Visibility.Visible : Visibility.Collapsed;

                    _audit.LogAsync(new AuditEntry
                    {
                        UserID = result.UserID, UserName = result.UserName,
                        FilePath = "SYSTEM", OperationType = FileOperationType.Read,
                        Result = AuditResult.Allow, Detail = "用户登录系统"
                    });
                }
                else if (result.IsLocked)
                { lblResult.Foreground = Brushes.OrangeRed; lblResult.Text = $"[锁定] {result.ErrorMessage}"; }
                else
                { lblResult.Foreground = Brushes.Red; lblResult.Text = $"[失败] {result.ErrorMessage}"; }
            }
            catch (Exception ex) { lblResult.Foreground = Brushes.Red; lblResult.Text = $"异常: {ex.Message}"; }
        };

        ContentPanel.Children.Add(btnLogin);

        // 注册按钮
        var btnReg = new Button { Content = "注册新用户（管理员功能）", Width = 180, Height = 28, Margin = new Thickness(0, 15, 0, 0) };
        btnReg.Click += (_, _) => ShowRegisterPanel();
        ContentPanel.Children.Add(btnReg);

        // 快速提示
        AddLabel("", 5);
        AddLabel("默认管理员: admin / Admin@123", 11, Brushes.DarkGray);
        TxtStatus.Text = "状态：登录界面";
    }

    private void ShowRegisterPanel()
    {
        ClearContent();
        AddTitle("注册新用户");

        AddLabel("用户名:");
        var txtUser = AddTextBox("", 250);
        AddLabel("密码:");
        var txtPwd = new PasswordBox { Width = 250, Margin = new Thickness(0, 0, 0, 5) };
        ContentPanel.Children.Add(txtPwd);
        AddLabel("显示名称:");
        var txtDisp = AddTextBox("", 250);
        AddLabel("角色 (0=总经理, 1=经理, 2=员工, 3=实习生):");
        var txtRole = AddTextBox("2", 80);

        var lblResult = AddLabel("", 12, Brushes.Gray);
        var btnReg = new Button { Content = "提交注册", Width = 120, Height = 32, Margin = new Thickness(0, 10, 0, 0) };
        btnReg.Click += (_, _) =>
        {
            try
            {
                if (!int.TryParse(txtRole.Text, out int roleId) || roleId < 0 || roleId > 3)
                { lblResult.Text = "角色ID无效 (0-3)"; return; }
                var (ok, uid, err) = _auth.RegisterUser(txtUser.Text.Trim(), txtPwd.Password, txtDisp.Text.Trim(), roleId);
                lblResult.Foreground = ok ? Brushes.Green : Brushes.Red;
                lblResult.Text = ok ? $"注册成功！UserID: {uid}" : $"失败: {err}";
            }
            catch (Exception ex) { lblResult.Text = $"异常: {ex.Message}"; }
        };
        ContentPanel.Children.Add(btnReg);
    }

    #endregion

    #region ── 管理员用户管理面板 ──

    private void ShowAdminUserPanel()
    {
        ClearContent();
        AddTitle("管理员 — 用户管理");

        if (_currentAuth == null || (UserRole)_currentAuth.RoleID != UserRole.GeneralManager)
        {
            AddLabel("仅总经理角色可访问此功能", 14, Brushes.OrangeRed);
            return;
        }

        var listBox = new ListBox
        {
            Width = 700, Height = 250, Margin = new Thickness(0, 10, 0, 10),
            FontFamily = new FontFamily("Consolas"), FontSize = 11
        };
        ContentPanel.Children.Add(listBox);

        var btnRefresh = new Button { Content = "刷新用户列表", Width = 120, Height = 28, Margin = new Thickness(0, 0, 0, 5) };
        btnRefresh.Click += (_, _) =>
        {
            listBox.Items.Clear();
            var users = _auth.ListAllUsers();
            foreach (var u in users)
                listBox.Items.Add($"{u.UserID[..8]}... | {u.UserName,-15} | {u.DisplayName,-10} | {RoleName((UserRole)u.RoleID),-8} | {(u.IsLocked ? "锁定" : "正常")} | 失败:{u.FailedAttempts}");
        };
        ContentPanel.Children.Add(btnRefresh);

        // 操作区域
        var opPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 10, 0, 0) };
        var txtTarget = AddTextBox("", 150);
        opPanel.Children.Add(new TextBlock { Text = "目标用户名:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0) });
        opPanel.Children.Add(txtTarget);
        ContentPanel.Children.Add(opPanel);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        var lblOp = AddLabel("", 12, Brushes.Gray);

        void AddOpBtn(string text, Action<string> action)
        {
            var btn = new Button { Content = text, Width = 100, Height = 28, Margin = new Thickness(0, 0, 8, 0) };
            btn.Click += (_, _) =>
            {
                if (string.IsNullOrWhiteSpace(txtTarget.Text)) { lblOp.Text = "请输入目标用户名"; return; }
                try { action(txtTarget.Text.Trim()); }
                catch (Exception ex) { lblOp.Text = $"异常: {ex.Message}"; }
            };
            btnPanel.Children.Add(btn);
        }

        AddOpBtn("删除用户", uname =>
        {
            var users = _auth.ListAllUsers();
            var u = users.FirstOrDefault(x => x.UserName == uname);
            if (u == null) { lblOp.Text = "用户不存在"; return; }
            bool ok = _auth.DeleteUser(u.UserID);
            lblOp.Foreground = ok ? Brushes.Green : Brushes.Red;
            lblOp.Text = ok ? $"已删除用户 {uname}" : "删除失败";
        });

        AddOpBtn("解锁用户", uname =>
        {
            var users = _auth.ListAllUsers();
            var u = users.FirstOrDefault(x => x.UserName == uname);
            if (u == null) { lblOp.Text = "用户不存在"; return; }
            _auth.UnlockUser(u.UserID);
            lblOp.Foreground = Brushes.Green;
            lblOp.Text = $"已解锁用户 {uname}";
        });

        AddOpBtn("设为员工(2)", uname =>
        {
            var users = _auth.ListAllUsers();
            var u = users.FirstOrDefault(x => x.UserName == uname);
            if (u == null) { lblOp.Text = "用户不存在"; return; }
            _auth.UpdateUserRole(u.UserID, 2);
            lblOp.Foreground = Brushes.Green;
            lblOp.Text = $"已更新角色";
        });

        AddOpBtn("设为经理(1)", uname =>
        {
            var users = _auth.ListAllUsers();
            var u = users.FirstOrDefault(x => x.UserName == uname);
            if (u == null) { lblOp.Text = "用户不存在"; return; }
            _auth.UpdateUserRole(u.UserID, 1);
            lblOp.Foreground = Brushes.Green;
            lblOp.Text = $"已更新角色";
        });

        ContentPanel.Children.Add(btnPanel);
        TxtStatus.Text = "状态：管理员 — 用户管理";
    }

    #endregion

    #region ── 文件加解密管理面板 ──

    private void BtnFiles_Click(object sender, RoutedEventArgs e)
    {
        ClearContent();
        AddTitle("文件透明加解密管理");

        if (_currentAuth == null) { AddLabel("请先登录", 14, Brushes.OrangeRed); return; }

        var lblInfo = AddLabel($"Vault路径: {_fileEnc.VaultPath}\n已登录: {_currentAuth.UserName} ({RoleName((UserRole)_currentAuth.RoleID)})", 11, Brushes.DarkGray);

        // ── 加密区域 ──
        AddLabel("", 10);
        var encPanel = new Border
        {
            BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1),
            Padding = new Thickness(10), Margin = new Thickness(0, 5, 0, 5), CornerRadius = new CornerRadius(4)
        };
        var encStack = new StackPanel();
        encStack.Children.Add(new TextBlock { Text = "加密文件", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 8) });

        var encPathPanel = new StackPanel { Orientation = Orientation.Horizontal };
        var txtEncPath = new TextBox { Width = 400, Margin = new Thickness(0, 0, 5, 0), IsReadOnly = true };
        encPathPanel.Children.Add(txtEncPath);
        var btnBrowse = new Button { Content = "浏览...", Width = 70, Height = 24 };
        btnBrowse.Click += (_, _) =>
        {
            var dlg = new OpenFileDialog { Title = "选择要加密的文件", Filter = "所有文件|*.*" };
            if (dlg.ShowDialog() == true) txtEncPath.Text = dlg.FileName;
        };
        encPathPanel.Children.Add(btnBrowse);
        encStack.Children.Add(encPathPanel);

        AddLabel("安全等级 (S=0, A=1, B=2, C=3, D=4):", 11);
        var txtLevel = new TextBox { Text = "2", Width = 40, Margin = new Thickness(0, 0, 0, 5) };
        encStack.Children.Add(txtLevel);

        var lblEncResult = CreateLabel("", 12, Brushes.Gray);
        var btnEncrypt = new Button { Content = "执行加密", Width = 120, Height = 32, Margin = new Thickness(0, 5, 0, 0) };
        btnEncrypt.Click += (_, _) =>
        {
            try
            {
                if (string.IsNullOrEmpty(txtEncPath.Text) || !File.Exists(txtEncPath.Text))
                { lblEncResult.Text = "请选择有效文件"; return; }
                if (!int.TryParse(txtLevel.Text, out int level) || level < 0 || level > 4)
                { lblEncResult.Text = "安全等级无效 (0-4)"; return; }

                string levelCode = level switch { 0 => "S", 1 => "A", 2 => "B", 3 => "C", _ => "D" };
                var authUsers = new List<string> { _currentAuth.UserID };
                string encPath = _fileEnc.EncryptFile(txtEncPath.Text, levelCode, authUsers);

                lblEncResult.Foreground = Brushes.Green;
                lblEncResult.Text = $"加密成功！\n加密文件: {encPath}\n安全等级: {levelCode}";

                _audit.LogAsync(new AuditEntry
                {
                    UserID = _currentAuth.UserID, UserName = _currentAuth.UserName,
                    FilePath = txtEncPath.Text, OperationType = FileOperationType.Write,
                    Result = AuditResult.Allow, Detail = $"文件加密: {levelCode}级",
                    FileSecurityLevel = levelCode, FileSize = new FileInfo(txtEncPath.Text).Length
                });
            }
            catch (Exception ex) { lblEncResult.Foreground = Brushes.Red; lblEncResult.Text = $"加密失败: {ex.Message}"; }
        };
        encStack.Children.Add(btnEncrypt);
        encStack.Children.Add(lblEncResult);
        encPanel.Child = encStack;
        ContentPanel.Children.Add(encPanel);

        // ── 解密区域 ──
        var decPanel = new Border
        {
            BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1),
            Padding = new Thickness(10), Margin = new Thickness(0, 5, 0, 5), CornerRadius = new CornerRadius(4)
        };
        var decStack = new StackPanel();
        decStack.Children.Add(new TextBlock { Text = "解密文件", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 8) });

        var decPathPanel = new StackPanel { Orientation = Orientation.Horizontal };
        var txtDecPath = new TextBox { Width = 400, Margin = new Thickness(0, 0, 5, 0), IsReadOnly = true };
        decPathPanel.Children.Add(txtDecPath);
        var btnDecBrowse = new Button { Content = "选择.secfs", Width = 80, Height = 24 };
        btnDecBrowse.Click += (_, _) =>
        {
            var dlg = new OpenFileDialog { Title = "选择加密文件", Filter = "加密文件|*.secfs|所有文件|*.*", InitialDirectory = _fileEnc.VaultPath };
            if (dlg.ShowDialog() == true) txtDecPath.Text = dlg.FileName;
        };
        decPathPanel.Children.Add(btnDecBrowse);
        decStack.Children.Add(decPathPanel);

        var lblDecResult = CreateLabel("", 12, Brushes.Gray);
        var btnDecrypt = new Button { Content = "执行解密", Width = 120, Height = 32, Margin = new Thickness(0, 5, 0, 0) };
        btnDecrypt.Click += (_, _) =>
        {
            try
            {
                if (string.IsNullOrEmpty(txtDecPath.Text) || !File.Exists(txtDecPath.Text))
                { lblDecResult.Text = "请选择有效加密文件"; return; }
                string tempPath = _fileEnc.DecryptFile(txtDecPath.Text);
                lblDecResult.Foreground = Brushes.Green;
                lblDecResult.Text = $"解密成功！临时明文: {tempPath}";

                _audit.LogAsync(new AuditEntry
                {
                    UserID = _currentAuth.UserID, UserName = _currentAuth.UserName,
                    FilePath = txtDecPath.Text, OperationType = FileOperationType.Read,
                    Result = AuditResult.Allow, Detail = "文件解密"
                });
            }
            catch (Exception ex) { lblDecResult.Foreground = Brushes.Red; lblDecResult.Text = $"解密失败: {ex.Message}"; }
        };
        decStack.Children.Add(btnDecrypt);
        decStack.Children.Add(lblDecResult);
        decPanel.Child = decStack;
        ContentPanel.Children.Add(decPanel);

        // ── 加密文件列表 ──
        AddLabel("", 5);
        var btnList = new Button { Content = "刷新加密文件列表", Width = 150, Height = 28, Margin = new Thickness(0, 5, 0, 5) };
        var listBox = new ListBox { Width = 700, Height = 120, FontFamily = new FontFamily("Consolas"), FontSize = 10 };
        btnList.Click += (_, _) =>
        {
            listBox.Items.Clear();
            var files = _fileEnc.ListEncryptedFiles();
            foreach (var f in files)
            {
                try
                {
                    var meta = _fileEnc.ReadMetadata(f);
                    string size = meta.OriginalFileSize > 1024 * 1024
                        ? $"{meta.OriginalFileSize / (1024 * 1024)}MB"
                        : $"{meta.OriginalFileSize / 1024}KB";
                    listBox.Items.Add($"{Path.GetFileName(f)} | 原文件:{meta.OriginalFileName} | 等级:{meta.SecurityLevel} | 大小:{size} | 用户数:{meta.AuthorizedUserIds.Count}");
                }
                catch { listBox.Items.Add($"{Path.GetFileName(f)} | [读取元数据失败]"); }
            }
            if (files.Count == 0) listBox.Items.Add("(暂无加密文件)");
        };
        ContentPanel.Children.Add(btnList);
        ContentPanel.Children.Add(listBox);

        TxtStatus.Text = "状态：文件加解密管理";
    }

    #endregion

    #region ── 密钥管理面板 ──

    private void BtnKeys_Click(object sender, RoutedEventArgs e)
    {
        ClearContent();
        AddTitle("密钥管理");

        if (_currentAuth == null) { AddLabel("请先登录", 14, Brushes.OrangeRed); return; }

        AddLabel("密钥体系：RSA-2048（非对称） + AES-256-GCM（对称加密私钥）", 12, Brushes.DarkGray);
        AddLabel("密钥轮换周期：90天自动轮换 | 私钥以KEK(AES-256-GCM)加密存储", 12, Brushes.DarkGray);

        var lblExpiry = AddLabel("", 12, Brushes.Gray);
        var btnCheck = new Button { Content = "检查过期密钥（7天内）", Width = 180, Height = 30, Margin = new Thickness(0, 10, 0, 5) };
        btnCheck.Click += (_, _) =>
        {
            try
            {
                var expiring = _keyRot.CheckExpiringKeys();
                lblExpiry.Text = expiring.Count > 0
                    ? $"即将过期密钥数: {expiring.Count}（用户: {string.Join(", ", expiring)}）"
                    : "所有密钥均在有效期内";
            }
            catch (Exception ex) { lblExpiry.Text = $"错误: {ex.Message}"; }
        };
        ContentPanel.Children.Add(btnCheck);

        // 手动轮换
        AddLabel("", 5);
        var rotPanel = new Border
        {
            BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1),
            Padding = new Thickness(10), Margin = new Thickness(0, 10, 0, 0), CornerRadius = new CornerRadius(4)
        };
        var rotStack = new StackPanel();
        rotStack.Children.Add(new TextBlock
        {
            Text = "手动密钥轮换", FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 8)
        });
        rotStack.Children.Add(new TextBlock
        {
            Text = "输入密码确认身份后执行轮换（生成新密钥对，旧密钥吊销）",
            FontSize = 11, Foreground = Brushes.DarkGray, Margin = new Thickness(0, 0, 0, 5)
        });
        var txtRotPwd = new PasswordBox { Width = 250, Margin = new Thickness(0, 0, 0, 5) };
        rotStack.Children.Add(txtRotPwd);
        var lblRotResult = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Margin = new Thickness(0, 5, 0, 0) };
        var btnRotate = new Button { Content = "执行密钥轮换", Width = 140, Height = 30 };
        btnRotate.Click += (_, _) =>
        {
            try
            {
                var (ok, rot) = _keyRot.RotateKeys(_currentAuth.UserID, txtRotPwd.Password, "MANUAL");
                lblRotResult.Foreground = ok ? Brushes.Green : Brushes.Red;
                lblRotResult.Text = ok
                    ? $"轮换成功！新密钥ID: {rot.NewKeyID[..12]}..."
                    : $"轮换失败";
            }
            catch (Exception ex) { lblRotResult.Foreground = Brushes.Red; lblRotResult.Text = $"异常: {ex.Message}"; }
        };
        rotStack.Children.Add(btnRotate);
        rotStack.Children.Add(lblRotResult);
        rotPanel.Child = rotStack;
        ContentPanel.Children.Add(rotPanel);

        TxtStatus.Text = "状态：密钥管理";
    }

    #endregion

    #region ── USB管控面板 ──

    private void BtnUSB_Click(object sender, RoutedEventArgs e)
    {
        ClearContent();
        AddTitle("USB端口管控");

        var lblUsbStatus = AddLabel($"监控状态: {(_usbMonitoringActive ? "运行中" : "已停止")}", 13,
            _usbMonitoringActive ? Brushes.Green : Brushes.Gray);

        var ctrlPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 8) };
        var btnStart = new Button { Content = "启动USB监控", Width = 120, Height = 30, Margin = new Thickness(0, 0, 8, 0) };
        var btnStop = new Button { Content = "停止USB监控", Width = 120, Height = 30 };

        btnStart.Click += (_, _) =>
        {
            try { _usbMon.Start(); _usbMonitoringActive = true; lblUsbStatus.Text = "监控状态: 运行中"; lblUsbStatus.Foreground = Brushes.Green; }
            catch (Exception ex) { MessageBox.Show($"启动USB监控失败: {ex.Message}\n请确认以管理员权限运行。"); }
        };
        btnStop.Click += (_, _) =>
        {
            _usbMon.Stop(); _usbMonitoringActive = false;
            lblUsbStatus.Text = "监控状态: 已停止"; lblUsbStatus.Foreground = Brushes.Gray;
        };
        ctrlPanel.Children.Add(btnStart);
        ctrlPanel.Children.Add(btnStop);
        ContentPanel.Children.Add(ctrlPanel);

        AddLabel("USB监控需要管理员权限运行。系统通过WMI实时监控USB设备插拔，", 11, Brushes.DarkGray);
        AddLabel("经去抖动→恶意检测→白名单匹配→拦截/放行流程处理。", 11, Brushes.DarkGray);

        // 白名单管理
        AddLabel("", 8);
        var wlPanel = new Border
        {
            BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1),
            Padding = new Thickness(10), Margin = new Thickness(0, 5, 0, 5), CornerRadius = new CornerRadius(4)
        };
        var wlStack = new StackPanel();
        wlStack.Children.Add(new TextBlock { Text = "白名单管理", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 5) });

        var wlListBox = new ListBox { Width = 680, Height = 100, FontFamily = new FontFamily("Consolas"), FontSize = 10 };
        var btnWlRefresh = new Button { Content = "刷新白名单", Width = 100, Height = 24, Margin = new Thickness(0, 5, 0, 5) };
        btnWlRefresh.Click += (_, _) =>
        {
            wlListBox.Items.Clear();
            foreach (var e in _usbWl.GetAllEntries())
                wlListBox.Items.Add($"{e.Model,-20} | SN:{e.SerialNumber,-15} | VID:{e.VID} PID:{e.PID} | 所有者:{e.OwnerName}");
            if (_usbWl.GetAllEntries().Count == 0) wlListBox.Items.Add("(白名单为空)");
        };
        wlStack.Children.Add(btnWlRefresh);
        wlStack.Children.Add(wlListBox);
        wlPanel.Child = wlStack;
        ContentPanel.Children.Add(wlPanel);

        TxtStatus.Text = "状态：USB端口管控";
    }

    #endregion

    #region ── 审计日志面板 ──

    private void BtnAudit_Click(object sender, RoutedEventArgs e)
    {
        ClearContent();
        AddTitle("审计日志查询");

        var queryPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 8) };
        queryPanel.Children.Add(new TextBlock
        {
            Text = "从:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0)
        });
        var dpFrom = new DatePicker { Width = 140, SelectedDate = DateTime.Now.AddDays(-7), Margin = new Thickness(0, 0, 8, 0) };
        queryPanel.Children.Add(dpFrom);
        queryPanel.Children.Add(new TextBlock
        {
            Text = "到:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 5, 0)
        });
        var dpTo = new DatePicker { Width = 140, SelectedDate = DateTime.Now, Margin = new Thickness(0, 0, 8, 0) };
        queryPanel.Children.Add(dpTo);
        ContentPanel.Children.Add(queryPanel);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 5, 0, 10) };
        var btnQuery = new Button { Content = "查询全部日志", Width = 120, Height = 28, Margin = new Thickness(0, 0, 8, 0) };
        var btnExport = new Button { Content = "导出CSV", Width = 100, Height = 28 };
        btnPanel.Children.Add(btnQuery);
        btnPanel.Children.Add(btnExport);
        ContentPanel.Children.Add(btnPanel);

        var logListBox = new ListBox
        {
            Width = 700, Height = 280,
            FontFamily = new FontFamily("Consolas"), FontSize = 10,
            HorizontalContentAlignment = HorizontalAlignment.Stretch
        };
        ContentPanel.Children.Add(logListBox);

        var lblLogCount = AddLabel("", 11, Brushes.Gray);

        List<AuditEntry> _lastQuery = new();

        btnQuery.Click += (_, _) =>
        {
            try
            {
                var from = dpFrom.SelectedDate ?? DateTime.Now.AddDays(-7);
                var to = (dpTo.SelectedDate ?? DateTime.Now).AddDays(1);
                _lastQuery = _audit.QueryAll(from, to, 200);
                logListBox.Items.Clear();
                foreach (var entry in _lastQuery)
                    logListBox.Items.Add($"{entry.Timestamp:yyyy-MM-dd HH:mm:ss} | {entry.UserName,-10} | {entry.OperationType,-8} | {entry.Result,-6} | {entry.FileName,-20} | {entry.Detail}");
                lblLogCount.Text = $"共 {_lastQuery.Count} 条记录";
            }
            catch (Exception ex) { lblLogCount.Text = $"查询失败: {ex.Message}"; }
        };

        btnExport.Click += (_, _) =>
        {
            if (_lastQuery.Count == 0) { lblLogCount.Text = "请先查询日志"; return; }
            try
            {
                string csv = _audit.ExportToCsv(_lastQuery);
                string exportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    $"SecFS_Audit_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                File.WriteAllText(exportPath, csv, System.Text.Encoding.UTF8);
                lblLogCount.Foreground = Brushes.Green;
                lblLogCount.Text = $"已导出 {_lastQuery.Count} 条记录到: {exportPath}";
            }
            catch (Exception ex) { lblLogCount.Text = $"导出失败: {ex.Message}"; }
        };

        TxtStatus.Text = "状态：审计日志查询";
    }

    private void BtnAdmin_Click(object sender, RoutedEventArgs e)
    {
        ShowAdminUserPanel();
    }

    #endregion

    #region ── UI辅助方法 ──

    private void ClearContent() => ContentPanel.Children.Clear();

    private void AddTitle(string text)
    {
        ContentPanel.Children.Add(new TextBlock
        {
            Text = text, FontSize = 18, FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 5, 0, 12)
        });
    }

    private TextBlock AddLabel(string text, int fontSize = 13, Brush? foreground = null)
    {
        var lbl = CreateLabel(text, fontSize, foreground);
        ContentPanel.Children.Add(lbl);
        return lbl;
    }

    /// <summary>创建 TextBlock 但不自动添加到任何面板（由调用方自行决定放置位置）</summary>
    private static TextBlock CreateLabel(string text, int fontSize = 13, Brush? foreground = null)
    {
        return new TextBlock
        {
            Text = text, FontSize = fontSize,
            Foreground = foreground ?? Brushes.Black,
            Margin = new Thickness(0, 3, 0, 3),
            TextWrapping = TextWrapping.Wrap
        };
    }

    private TextBox AddTextBox(string text, int width)
    {
        var tb = new TextBox { Text = text, Width = width, Margin = new Thickness(0, 0, 0, 5) };
        ContentPanel.Children.Add(tb);
        return tb;
    }

    private static string RoleName(UserRole role) => role switch
    {
        UserRole.GeneralManager => "总经理",
        UserRole.Manager => "经理",
        UserRole.Employee => "员工",
        UserRole.Intern => "实习生",
        _ => "未知"
    };

    #endregion
}