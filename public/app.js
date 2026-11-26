// MailSleuth frontend — part 1: i18n, helpers, authentication, profile, tabs.
const $ = id => document.getElementById(id);
let csrf = '', last = null, lastResults = [], lastErrors = [], user = '', role = '', uid = '';
let lastDns = null, lastIp = null;
let histLoaded = false, histLoading = false, histCases = [];
let sessionTimerId = null, sessionExpires = 0, lastLoginMs = 0;
let logsLoaded = false, logsLoading = false, logsData = [], sessionsData = [];
let profileData = null, adminUsers = [], adminLoaded = false;
let lang = (() => { try { return localStorage.getItem('lang') === 'vi' ? 'vi' : 'en'; } catch { return 'en'; } })();

const store = {
  get: k => { try { return sessionStorage.getItem(k) || ''; } catch { return ''; } },
  set: (k, v) => { try { sessionStorage.setItem(k, v); } catch {} },
  del: k => { try { sessionStorage.removeItem(k); } catch {} }
};

const I18N = {
en: {
  title: 'MailSleuth — Email Forensics & Attacker Tracing Lab',
  subtitle: 'Email Forensics & Attacker Tracing Lab',
  loginH: 'Login', loginIdent: 'username, phone or user ID', username: 'username', password: 'password', login: 'Login',
  forgot: 'Forgot password?', createAccount: 'Create account', haveAccount: 'Back to login',
  regH: 'Create account', confirmPass: 'confirm password', phonePh: 'phone (optional, for login)',
  userRule: 'Username: 3–32 characters (letters, digits, . _ -). Password: 10–72 characters, max 72 UTF-8 bytes.',
  register: 'Register', recH: 'Reset password', reset: 'Reset', recoveryKey: 'Key ID XXXX-XXXX-...',
  keyTitle: 'Save your recovery key', keyHint: 'This key is shown once and is the only way to reset a forgotten password. Store it somewhere safe; the server keeps only a hash.',
  copy: 'Copy', saved: 'I saved it', copied: 'Copied.', copyFailed: 'Copy failed — select the key manually.',
  loggingIn: 'Logging in',
  errRate: 'Too many requests — wait a minute and try again.', errLogin: 'Wrong username or password.',
  errNetwork: 'Cannot reach server: ', errExists: 'That username is already taken.',
  errBadUser: 'Username must be 3–32 characters: letters, digits, dot, underscore or dash, with at least one letter or digit.',
  errWeak: 'New password must be 10–72 characters and at most 72 UTF-8 bytes.',
  errDisabled: 'Registration is disabled on this server.', errRegister: 'Registration failed — try again.',
  errMatch: 'The two passwords do not match.', errRecover: 'Wrong Key ID or account.',
  recOk: 'Password reset. Save the new Key ID shown below.', errPhoneExists: 'That phone number is already registered.',
  errBadPhone: 'Phone number must have 9–15 digits.', errServer: 'Server error — try again.',
  logout: 'Logout', profileTitle: 'Profile', uploadAvatar: 'Upload avatar', avatarHint: 'PNG or JPEG only, max 2 MB.',
  avatarBadType: 'Only PNG or JPEG images are allowed.', avatarBad: 'Invalid image file.', avatarTooLarge: 'Avatar is too large (max 2 MB).',
  avatarOk: 'Avatar updated.', avatarFailed: 'Avatar upload failed — try again.',
  profileRole: 'Role', profileCreated: 'Created', loginTime: 'Login time', sessionTime: 'Session left',
  sessionExpired: 'Session expired — please log in again.', accountTitle: 'Account — change password',
  currentPass: 'current password', newPass: 'new password (10–72 chars)', change: 'Change',
  passOk: 'Password changed. Please log in again.', passBad: 'Current password is wrong.',
  renameTitle: 'Rename (one-time ID from admin)', renameHint: 'Only an administrator can issue a one-time rename ID. It expires in 15 minutes and works once.',
  renameToken: 'one-time rename ID', newUsername: 'new username', renameGo: 'Rename account',
  renameOk: 'Account renamed — log in again.', renameFailed: 'Rename failed.', renameExpired: 'Rename ID expired or already used.',
  signedIn: 'Signed in: ',
  appH: 'Email dataset',
  dashCases: 'Cases', dashMessages: 'Messages', dashBad: 'Malicious', dashWarn: 'Suspicious', dashOk: 'Clean',
 dashFindings: 'Findings', dashRelations: 'Relations', tabCase: 'Case file', caseH: 'Case file & chain of custody',
 caseHint: 'Objective, scope, evidence inventory, custody, timeline, assessment, response and team. All re-signed.',
  tabAnalysis: 'Analysis', tabResults: 'Results', tabGuide: 'Guide', tabHistory: 'History', tabDns: 'DNS',
  tabIp: 'IP / Geo', tabTrust: 'Local AI', tabAdmin: 'Administration', tabLogs: 'Logs',
  platformLabel: 'Platform', platformAuto: 'Auto-detect',
  dropHint: 'Drag & drop email files or whole folders here, or use the buttons below.',
  pickFilesBtn: 'Choose files', pickFolderBtn: 'Choose folder', clearList: 'Clear list',
  analyze: 'Analyze', pause: 'Pause', resume: 'Resume', stop: 'Stop', cancel: 'Cancel',
  runRunning: 'Analyzing…', runPaused: 'Paused — waiting to resume.', runPausing: 'Pausing after the current file…',
  runResuming: 'Resuming…', runStopping: 'Stopping after the current file…', runStopped: 'Stopped — finished results were kept.',
  runCancelled: 'Cancelled — this run was discarded.', runStoppedNoResults: 'Stopped before any result was produced.',
  batchTimeout: 'The request timed out.', stepValidate: 'Validating files', stepUpload: 'Uploading', stepProcess: 'Analyzing',
  stepScore: 'Score', pickFiles: 'files', pickNone: 'No files selected.', pickSkipped: 'skipped', pickDup: 'duplicates',
  pickLimit: 'Too many files (max 2000).', pickRemove: 'Remove', pfReady: 'ready', pfRejected: 'rejected by preflight',
  pfBadExt: 'unsupported extension', pfEmpty: 'empty file', pfTooLarge: 'file too large', pfDupe: 'duplicate',
  noFile: 'Choose at least one file.', uploadErrors: 'Some files could not be analyzed',
  analysisControls: 'Analysis controls', liveTitle: 'Analysis', liveFile: 'File', liveStage: 'Stage', liveDetail: 'Detail',
  resultsH: 'Analysis results', resOverview: 'Overview', resMessages: 'Headers & body', resUrls: 'URLs by target',
  resGraph: 'Entity graph', repHtml: 'Report HTML', repPdf: 'Report PDF', repCsv: 'Report CSV',
  repBundle: 'Export bundle…', repVerify: 'Verify signature', urlCsv: 'Export URL CSV',
  urlImport: 'Import URL CSV/JSON/XML/TXT', urlImportDir: 'Import folder', graphBtn: 'Entity graph',
  noResult: 'No result yet — run an analysis first.', caseLabel: 'Case', score: 'Score', verdict: 'Verdict',
  messagesLabel: 'Messages', attachments: 'Attachments', findings: 'Findings', noFindings: 'No findings.',
  shown: 'Showing the first 300 findings.', urlsByTarget: 'URL statistics by target', urlLabel: 'URL', hostLabel: 'Host',
  riskLabel: 'Risk', reasonsLabel: 'Reasons', targetLabel: 'Target', groupTotal: 'URLs',
  importOk: 'URL import complete.', importMerged: 'merged', importFail: 'URL import failed.',
  exportOk: 'Export saved.', exportFail: 'Export failed: ', verifyOk: 'Signature valid — the report has not changed.',
  verifyBad: 'SIGNATURE MISMATCH — the case data changed after signing.', signatureLabel: 'SHA-256 signature',
  clientLabel: 'Detected platform', formatLabel: 'Format', shaLabel: 'SHA-256', custodyLabel: 'Chain of custody',
  receivedCount: 'Received hops', totalTransit: 'Total transit', hopFrom: 'From', gatewayLabel: 'Gateway',
  hopDelay: 'Delay', hopTime: 'Time', authEnvelope: 'Envelope', headerChecks: 'Header checks', forensics: 'Authentication & routing',
  threats: 'URLs and attachments', iocCount: 'IOC', senderDns: 'Sender domain DNS', dnsExplain: 'SPF, DMARC and MX of the sender domain.',
  ipIntelligence: 'Origin IP intelligence', ipExplain: 'Local GeoLite2 and PTR; the map is an internal schematic.',
  mapTitle: 'Server locations found in the mail', locatedSummary: 'Located', coordinatesLabel: 'Coordinates',
  countryLabel: 'Country', cityLabel: 'City', asnLabel: 'ASN', organizationLabel: 'Organization', ptrLabel: 'PTR',
  serverTypeLabel: 'Server type', assessLabel: 'Assessment', confidenceLabel: 'Confidence', approxLabel: 'Location is approximate and may be affected by VPN/proxy.',
  missing: 'No Authentication-Results header was found.', statusLabel: 'Status', selectorLabel: 'Selector', policy: 'Policy',
  alignmentLabel: 'alignment', upstreamLabel: 'Upstream result', upstreamSpf: 'Upstream SPF', upstreamDkim: 'Upstream DKIM',
  upstreamDmarc: 'Upstream DMARC', dkimSignaturesLabel: 'DKIM signatures', yesLabel: 'yes', noLabel: 'no', unknownLabel: 'unknown',
  htmlBlocked: 'Remote content is blocked in this view.', bodyText: 'Text body', bodyHtml: 'HTML body', bodyEmpty: 'No body stored.',
  bodyTruncated: 'The body was truncated.', bodyOmitted: 'The body was omitted (too large).',
  contentLoadFailed: 'Could not load message content.', showFirstMessages: 'Showing the first 200 messages.',
  originIps: 'Origin IPs', fromLabel: 'From', toLabel: 'To', replyToLabel: 'Reply-To', returnPathLabel: 'Return-Path',
  dateLabel: 'Date', messageIdLabel: 'Message-ID', authLabel: 'Authentication',
  reportFailed: 'Report failed: ', graphFailed: 'Graph failed: ', fileLevel: 'File level', importedTarget: 'Imported',
  historyH: 'Investigation history', historySearchPh: 'file, analyst or case ID', historySearch: 'Search', refresh: 'Refresh',
  historyHint: 'Latest 100 cases. Open a case to restore its result.', historyEmpty: 'No cases yet.', historyOpen: 'Open',
  historyWhen: 'Date', historyFile: 'File', historyAnalyst: 'Analyst', historyMessages: 'Messages', historyVerdict: 'Verdict', historyScore: 'Score',
  guideH: 'Guide — how to use MailSleuth',
  guide1: 'Choose Windows or Linux in the dashboard to set the platform for the next run; Auto-detect keeps the value found in the file.',
  guide2: 'Add .eml, .msg, .mbox, .emlx, .mht, .mhtml or .txt files (single, multiple, or a whole folder). PST/OST must be exported to EML first with readpst or Outlook.',
  guide3: 'Press Analyze. Three live lines show the file, the stage and the detail; the amplitude bar and the percentage show real progress. Pause stops after the current file, Stop keeps finished results, Cancel discards the run.',
  guide4: 'Results opens automatically. The first strip identifies the email platform (Outlook, Exchange, Thunderbird, Apple Mail, Gmail, Maildir, mbox).',
  guide5: 'Every message can be expanded to read the preserved headers and the text/HTML body. Remote content is blocked.',
  guide6: 'The report carries a SHA-256 digital seal in the bottom-right corner. Verify it any time with “Verify signature”.',
  guide7: 'URL statistics are grouped by target (sender, body, attachment, imported). Export them to CSV or import CSV/JSON/XML/TXT for one-pass local re-analysis.',
  guide8: 'The entity graph at the end is built only from evidence (headers, IPs, URLs, hashes); it does not guess identities.',
  guide9: '100% offline forensic: no external API, no reputation feed, no AI/ML verdict; evidence-backed local rules only.',
  guideNotes: 'Notes and cautions',
  guideN1: 'No live DNS: SPF/DKIM/DMARC come from Authentication-Results or a local DNS snapshot. GeoIP is local MaxMind.',
  guideN2: 'Duplicate Message-ID values are normal in exported mailboxes; the tool keeps every record and its filename/folder provenance.',
  guideN3: 'A missing display name is not proof of spoofing; findings show the evidence and the weight used.',
  guideN4: 'Administrators must enroll with the offline keygen (password + CCCD salt). The CCCD is never stored.',
  guideN5: 'The map is an internal schematic, not an online tile service; it marks the server location found in the mail.',
  dnsH: 'DNS lookup', dnsDomain: 'example.com or IP', dnsTypeAll: 'All records / DNS health', dnsTypeAria: 'DNS record type',
  dnsSelector: 'DKIM selector (e.g. default)', dnsHint: 'DNS only reads the local snapshot (tools/dns_snapshot.py). No network resolver.',
  lookup: 'Lookup', noRecords: 'no records', notFoundLabel: 'not found',
  ipH: 'IP geolocation and network', ipAddr: '8.8.8.8', ipHint: 'MaxMind GeoLite2 is used locally. PTR is queried through this server. The map is an internal schematic; location is approximate and may be affected by VPN/proxy.',
  trustH: 'Local AI endpoint', trustHint: 'Only a local OpenAI-compatible endpoint is supported (Ollama, LM Studio, llama.cpp, vLLM). Cloud providers are refused. The key is stored server-side per account and is never echoed back.',
  llmBase: 'Endpoint', llmModel: 'Model', llmKey: 'API key (local, optional)', llmKeyPh: 'optional local token',
  llmEnabled: 'Enable local AI assessment during analysis', trustSave: 'Save settings', trustTest: 'Test endpoint',
  trustClear: 'Remove key', trustState: 'Server status: checking…', trustStateOn: 'Local AI', trustEnabled: 'enabled',
  trustDisabled: 'disabled', saving: 'Saving…', trustSaved: 'Settings saved.', trustTestOk: 'Endpoint reachable.',
  trustTestFail: 'Endpoint not reachable.', trustRemoved: 'Key removed.', trustLoadFailed: 'Could not load settings.',
  adminH: 'Administration', adminHint: 'Administrators only. Accounts are created with a one-time key; the server stores only a hash. Self-demotion, self-disable and removing the last administrator are refused.',
  adminStats: 'System statistics', adminCreate: 'Create account', adminCreateGo: 'Create account',
  adminUsers: 'Accounts', roleAnalyst: 'Analyst', roleAdmin: 'Administrator',
  cccdPh: 'CCCD (administrators only, used as salt)', adminMsg: 'Loading…',
  adminCreated: 'Account created. Copy the key now — it is shown once.', adminKeyOnce: 'One-time key',
  adminReset: 'Reset password', adminDisable: 'Disable', adminEnable: 'Enable', adminRole: 'Toggle role',
  adminRename: 'Rename ID', adminSelf: 'This is your own account.', adminLast: 'This is the last active administrator.',
  adminUsersEmpty: 'No accounts.', adminResetPrompt: 'New password (10–72 chars):',
  adminResetOk: 'Password reset.', adminDisabledOk: 'Account disabled.', adminEnabledOk: 'Account enabled.',
  adminRoleOk: 'Role updated.', adminRenameOk: 'One-time rename ID (valid 15 minutes):', adminLoadFailed: 'Could not load accounts.',
  adminNoCccd: 'CCCD is required for an administrator account.', adminUid: 'User ID', adminPhone: 'Phone',
  adminLastLogin: 'Last login', adminCreatedAt: 'Created', adminStatus: 'Status', adminActions: 'Actions',
  logsH: 'Audit and session log', logsHint: 'Admin only. Login duration is measured server-side; ended sessions are signed with SHA-256 and chained to the previous signature.',
  auditLog: 'Audit log', sessionLog: 'Signed session endings', logsEmpty: 'No audit entries.', sessionsEmpty: 'No signed sessions yet.',
  logsLoadFailed: 'Could not load logs.', durationMs: 'Duration (ms)', sessionUser: 'User', sessionRole: 'Role',
  reasonLabel: 'Reason', previousLabel: 'Previous signature',
  themeDark: 'Switch to dark mode', themeLight: 'Switch to light mode',
  v_clean: 'Clean', v_suspicious: 'Suspicious', v_malicious_or_phishing: 'Malicious / phishing',
  a_clean: 'clean', a_suspicious: 'suspicious', a_malicious: 'malicious', a_unverified: 'unverified',
  a_authentic: 'authentic', a_spoofed: 'spoofed',
  st_mail: 'mail server', st_mx: 'MX', st_web: 'web host', st_relay: 'relay', st_unknown: 'unknown',
  e_auth: 'Session expired — log in again.', e_csrf: 'Security token expired — reload the page.',
  e_forbidden: 'Not allowed.', e_not_found: 'Not found.', e_rate: 'Too many requests — wait a minute.',
  e_weak: 'Password too weak.', e_exists: 'Already exists.', e_phone_exists: 'Phone already registered.',
  e_bad_phone: 'Invalid phone number.', e_bad_user: 'Invalid username.', e_bad_role: 'Invalid role.',
  e_login: 'Wrong credentials.', e_recover: 'Wrong Key ID.', e_pass_bad: 'Wrong password.',
  e_rename_token: 'Invalid rename ID.', e_rename_expired: 'Rename ID expired.', e_file: 'Unsupported file.',
  e_parse: 'Could not parse the file.', e_empty: 'The file contains no message.', e_too_large: 'File too large.',
  e_upload: 'Upload failed.', e_file_too_large: 'File too large.', e_disk_full: 'Disk full.',
  e_pdf_failed: 'PDF generation failed.', e_body_unavailable: 'Body unavailable.', e_bad_ip: 'Invalid IP address.',
  e_bad_domain: 'Invalid domain.', e_bad_type: 'Invalid record type.', e_selector: 'DKIM selector required.',
  e_local_only: 'Only local/private AI endpoints are allowed.', e_bad_url: 'Invalid URL.',
  e_self_forbidden: 'You cannot do that to your own account.', e_last_admin: 'The last administrator cannot be removed.',
  e_no_location: 'No location available.', e_ips: 'No IPs given.', e_disabled: 'Registration is disabled.',
  e_unknown: 'Error: '
},
vi: {
  title: 'MailSleuth — Pháp chứng Email & Truy vết kẻ tấn công',
  subtitle: 'Pháp chứng Email & Truy vết kẻ tấn công',
  loginH: 'Đăng nhập', loginIdent: 'tên đăng nhập, số điện thoại hoặc ID', username: 'tên đăng nhập', password: 'mật khẩu', login: 'Đăng nhập',
  forgot: 'Quên mật khẩu?', createAccount: 'Tạo tài khoản', haveAccount: 'Về trang đăng nhập',
  regH: 'Tạo tài khoản', confirmPass: 'nhập lại mật khẩu', phonePh: 'số điện thoại (không bắt buộc, dùng để đăng nhập)',
  userRule: 'Tên đăng nhập: 3–32 ký tự (chữ, số, . _ -). Mật khẩu: 10–72 ký tự, tối đa 72 byte UTF-8.',
  register: 'Đăng ký', recH: 'Đặt lại mật khẩu', reset: 'Đặt lại', recoveryKey: 'Key ID XXXX-XXXX-...',
  keyTitle: 'Lưu Key ID khôi phục', keyHint: 'Key chỉ hiện một lần và là cách duy nhất để đặt lại mật khẩu khi quên. Hãy lưu an toàn; máy chủ chỉ giữ bản băm.',
  copy: 'Sao chép', saved: 'Tôi đã lưu', copied: 'Đã sao chép.', copyFailed: 'Sao chép thất bại — hãy chọn key thủ công.',
  loggingIn: 'Đang đăng nhập',
  errRate: 'Quá nhiều yêu cầu — chờ một phút rồi thử lại.', errLogin: 'Sai tên đăng nhập hoặc mật khẩu.',
  errNetwork: 'Không kết nối được máy chủ: ', errExists: 'Tên đăng nhập đã tồn tại.',
  errBadUser: 'Tên đăng nhập phải 3–32 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch ngang, có ít nhất một chữ hoặc số.',
  errWeak: 'Mật khẩu mới phải 10–72 ký tự và tối đa 72 byte UTF-8.',
  errDisabled: 'Máy chủ đã tắt đăng ký.', errRegister: 'Đăng ký thất bại — thử lại.',
  errMatch: 'Hai mật khẩu không khớp.', errRecover: 'Sai Key ID hoặc tài khoản.',
  recOk: 'Đã đặt lại mật khẩu. Hãy lưu Key ID mới bên dưới.', errPhoneExists: 'Số điện thoại đã được đăng ký.',
  errBadPhone: 'Số điện thoại phải có 9–15 chữ số.', errServer: 'Lỗi máy chủ — thử lại.',
  logout: 'Đăng xuất', profileTitle: 'Hồ sơ cá nhân', uploadAvatar: 'Tải ảnh đại diện', avatarHint: 'Chỉ nhận PNG hoặc JPEG, tối đa 2 MB.',
  avatarBadType: 'Chỉ cho phép ảnh PNG hoặc JPEG.', avatarBad: 'Tệp ảnh không hợp lệ.', avatarTooLarge: 'Ảnh đại diện quá lớn (tối đa 2 MB).',
  avatarOk: 'Đã cập nhật ảnh đại diện.', avatarFailed: 'Tải ảnh đại diện thất bại — hãy thử lại.',
  profileRole: 'Vai trò', profileCreated: 'Ngày tạo', loginTime: 'Thời gian đăng nhập', sessionTime: 'Phiên còn lại',
  sessionExpired: 'Phiên đã hết hạn — vui lòng đăng nhập lại.', accountTitle: 'Tài khoản — đổi mật khẩu',
  currentPass: 'mật khẩu hiện tại', newPass: 'mật khẩu mới (10–72 ký tự)', change: 'Đổi',
  passOk: 'Đã đổi mật khẩu. Vui lòng đăng nhập lại.', passBad: 'Mật khẩu hiện tại không đúng.',
  renameTitle: 'Đổi tên (ID cấp một lần từ admin)', renameHint: 'Chỉ quản trị viên mới cấp được ID đổi tên một lần. ID hết hạn sau 15 phút và chỉ dùng được một lần.',
  renameToken: 'ID đổi tên một lần', newUsername: 'tên đăng nhập mới', renameGo: 'Đổi tên tài khoản',
  renameOk: 'Đã đổi tên — hãy đăng nhập lại.', renameFailed: 'Đổi tên thất bại.', renameExpired: 'ID đổi tên đã hết hạn hoặc đã dùng.',
  signedIn: 'Đang đăng nhập: ',
  appH: 'Bộ dữ liệu email',
  dashCases: 'Vụ việc', dashMessages: 'Số thư', dashBad: 'Độc hại', dashWarn: 'Đáng ngờ', dashOk: 'Sạch',
  tabAnalysis: 'Phân tích', tabResults: 'Kết quả', tabGuide: 'Hướng dẫn', tabHistory: 'Lịch sử', tabDns: 'DNS',
  tabIp: 'IP / Bản đồ', tabTrust: 'AI nội bộ', tabAdmin: 'Quản trị', tabLogs: 'Nhật ký',
  platformLabel: 'Nền tảng', platformAuto: 'Tự nhận diện',
  dropHint: 'Kéo & thả tệp email hoặc cả thư mục vào đây, hoặc dùng nút bên dưới.',
  pickFilesBtn: 'Chọn tệp', pickFolderBtn: 'Chọn thư mục', clearList: 'Xóa danh sách',
  analyze: 'Phân tích', pause: 'Tạm dừng', resume: 'Tiếp tục', stop: 'Dừng', cancel: 'Hủy',
  runRunning: 'Đang phân tích…', runPaused: 'Đã tạm dừng — chờ tiếp tục.', runPausing: 'Tạm dừng sau tệp hiện tại…',
  runResuming: 'Đang tiếp tục…', runStopping: 'Dừng sau tệp hiện tại…', runStopped: 'Đã dừng — giữ lại kết quả đã xong.',
  runCancelled: 'Đã hủy — toàn bộ kết quả lần này bị bỏ.', runStoppedNoResults: 'Đã dừng trước khi có kết quả.',
  batchTimeout: 'Yêu cầu quá thời gian.', stepValidate: 'Kiểm tra tệp', stepUpload: 'Tải lên', stepProcess: 'Phân tích',
  stepScore: 'Điểm', pickFiles: 'tệp', pickNone: 'Chưa chọn tệp.', pickSkipped: 'bị bỏ', pickDup: 'trùng',
  pickLimit: 'Quá nhiều tệp (tối đa 2000).', pickRemove: 'Xóa', pfReady: 'sẵn sàng', pfRejected: 'bị loại từ đầu',
  pfBadExt: 'phần mở rộng không hỗ trợ', pfEmpty: 'tệp rỗng', pfTooLarge: 'tệp quá lớn', pfDupe: 'trùng',
  noFile: 'Hãy chọn ít nhất một tệp.', uploadErrors: 'Một số tệp không phân tích được',
  analysisControls: 'Điều khiển phân tích', liveTitle: 'Phân tích', liveFile: 'Tệp', liveStage: 'Bước', liveDetail: 'Chi tiết',
  resultsH: 'Kết quả phân tích', resOverview: 'Tổng quan', resMessages: 'Header & nội dung', resUrls: 'URL theo target',
  resGraph: 'Sơ đồ liên kết', repHtml: 'Báo cáo HTML', repPdf: 'Báo cáo PDF', repCsv: 'Báo cáo CSV',
  repBundle: 'Xuất trọn gói…', repVerify: 'Kiểm tra chữ ký', urlCsv: 'Xuất CSV URL',
  urlImport: 'Nhập URL CSV/JSON/XML/TXT', urlImportDir: 'Nhập thư mục', graphBtn: 'Sơ đồ liên kết',
  noResult: 'Chưa có kết quả — hãy phân tích trước.', caseLabel: 'Vụ việc', score: 'Điểm', verdict: 'Kết luận',
  messagesLabel: 'Số thư', attachments: 'Tệp đính kèm', findings: 'Phát hiện', noFindings: 'Không có phát hiện.',
  shown: 'Hiển thị 300 phát hiện đầu tiên.', urlsByTarget: 'Thống kê URL theo từng target', urlLabel: 'URL', hostLabel: 'Host',
  riskLabel: 'Rủi ro', reasonsLabel: 'Lý do', targetLabel: 'Target', groupTotal: 'URL',
  importOk: 'Đã nhập URL.', importMerged: 'đã gộp', importFail: 'Nhập URL thất bại.',
  exportOk: 'Đã lưu tệp xuất.', exportFail: 'Xuất thất bại: ', verifyOk: 'Chữ ký hợp lệ — báo cáo không bị thay đổi.',
  verifyBad: 'CHỮ KÝ KHÔNG KHỚP — dữ liệu đã thay đổi sau khi ký.', signatureLabel: 'Chữ ký SHA-256',
  clientLabel: 'Nền tảng phát hiện', formatLabel: 'Định dạng', shaLabel: 'SHA-256', custodyLabel: 'Chuỗi bảo quản',
  receivedCount: 'Số chặng Received', totalTransit: 'Tổng thời gian truyền', hopFrom: 'Từ', gatewayLabel: 'Gateway',
  hopDelay: 'Độ trễ', hopTime: 'Thời gian', authEnvelope: 'Envelope', headerChecks: 'Kiểm tra header', forensics: 'Xác thực & đường truyền',
  threats: 'URL và tệp đính kèm', iocCount: 'IOC', senderDns: 'DNS miền người gửi', dnsExplain: 'SPF, DMARC và MX của miền người gửi.',
  ipIntelligence: 'Thông tin IP nguồn', ipExplain: 'GeoLite2 nội bộ và PTR; bản đồ là lược đồ nội bộ.',
  mapTitle: 'Vị trí máy chủ phát hiện trong thư', locatedSummary: 'Định vị được', coordinatesLabel: 'Tọa độ',
  countryLabel: 'Quốc gia', cityLabel: 'Thành phố', asnLabel: 'ASN', organizationLabel: 'Tổ chức', ptrLabel: 'PTR',
  serverTypeLabel: 'Loại máy chủ', assessLabel: 'Đánh giá', confidenceLabel: 'Độ tin cậy', approxLabel: 'Vị trí chỉ tương đối và có thể bị ảnh hưởng bởi VPN/proxy.',
  missing: 'Không tìm thấy header Authentication-Results.', statusLabel: 'Trạng thái', selectorLabel: 'Selector', policy: 'Chính sách',
  alignmentLabel: 'alignment', upstreamLabel: 'Kết quả thượng nguồn', upstreamSpf: 'SPF thượng nguồn', upstreamDkim: 'DKIM thượng nguồn',
  upstreamDmarc: 'DMARC thượng nguồn', dkimSignaturesLabel: 'Chữ ký DKIM', yesLabel: 'có', noLabel: 'không', unknownLabel: 'không rõ',
  htmlBlocked: 'Nội dung từ xa bị chặn trong chế độ xem này.', bodyText: 'Nội dung văn bản', bodyHtml: 'Nội dung HTML', bodyEmpty: 'Không lưu nội dung.',
  bodyTruncated: 'Nội dung đã bị cắt bớt.', bodyOmitted: 'Nội dung bị bỏ qua (quá lớn).',
  contentLoadFailed: 'Không tải được nội dung thư.', showFirstMessages: 'Hiển thị 200 thư đầu tiên.',
  originIps: 'IP nguồn', fromLabel: 'Từ', toLabel: 'Đến', replyToLabel: 'Reply-To', returnPathLabel: 'Return-Path',
  dateLabel: 'Ngày', messageIdLabel: 'Message-ID', authLabel: 'Xác thực',
  reportFailed: 'Tạo báo cáo thất bại: ', graphFailed: 'Tạo sơ đồ thất bại: ', fileLevel: 'Mức tệp', importedTarget: 'Nhập vào',
  historyH: 'Lịch sử điều tra', historySearchPh: 'tệp, chuyên viên hoặc mã vụ việc', historySearch: 'Tìm', refresh: 'Làm mới',
  historyHint: '100 vụ việc gần nhất. Mở một vụ để khôi phục kết quả.', historyEmpty: 'Chưa có vụ việc.', historyOpen: 'Mở',
  historyWhen: 'Ngày', historyFile: 'Tệp', historyAnalyst: 'Chuyên viên', historyMessages: 'Số thư', historyVerdict: 'Kết luận', historyScore: 'Điểm',
  guideH: 'Hướng dẫn sử dụng MailSleuth',
  guide1: 'Chọn Windows hoặc Linux ở dashboard để đặt nền tảng cho lần chạy tới; Tự nhận diện sẽ giữ giá trị tìm thấy trong tệp.',
  guide2: 'Thêm tệp .eml, .msg, .mbox, .emlx, .mht, .mhtml hoặc .txt (một tệp, nhiều tệp hoặc cả thư mục). PST/OST phải được xuất sang EML trước bằng readpst hoặc Outlook.',
  guide3: 'Bấm Phân tích. Ba dòng trực tiếp hiển thị tệp, bước và chi tiết; thanh biên độ và % cho biết tiến độ thật. Tạm dừng sẽ dừng sau tệp hiện tại, Dừng giữ kết quả đã xong, Hủy bỏ toàn bộ lần chạy.',
  guide4: 'Tab Kết quả tự mở. Dòng tab đầu nhận diện nền tảng email (Outlook, Exchange, Thunderbird, Apple Mail, Gmail, Maildir, mbox).',
  guide5: 'Mỗi thư có thể mở để xem header và nội dung text/HTML đã lưu. Nội dung từ xa bị chặn.',
  guide6: 'Báo cáo có mộc số SHA-256 ở góc dưới bên phải. Kiểm tra lại bất cứ lúc nào bằng “Kiểm tra chữ ký”.',
  guide7: 'Thống kê URL được nhóm theo target (người gửi, nội dung, tệp đính kèm, nhập vào). Xuất CSV hoặc nhập CSV/JSON/XML/TXT để phân tích lại một lần bằng luật nội bộ.',
  guide8: 'Sơ đồ liên kết ở cuối chỉ dựng từ chứng cứ (header, IP, URL, hash); không suy đoán danh tính.',
  guide9: 'AI nội bộ là tùy chọn và chỉ được trỏ tới localhost/địa chỉ riêng. Không hỗ trợ nhà cung cấp AI đám mây.',
  guideNotes: 'Ghi chú và lưu ý',
  guideN1: 'Mặc định offline: DNS trực tiếp bị tắt trừ khi máy chủ đặt LIVE_DNS=1. GeoIP dùng cơ sở dữ liệu MaxMind nội bộ.',
  guideN2: 'Message-ID trùng là bình thường trong hộp thư xuất ra; công cụ giữ mọi bản ghi và nguồn gốc tên tệp/thư mục.',
  guideN3: 'Thiếu tên hiển thị không phải bằng chứng giả mạo; phát hiện luôn nêu chứng cứ và trọng số.',
  guideN4: 'Quản trị viên phải đăng ký bằng script keygen offline (mật khẩu + muối CCCD). CCCD không bao giờ được lưu.',
  guideN5: 'Bản đồ là lược đồ nội bộ, không phải dịch vụ tile trực tuyến; nó đánh dấu vị trí máy chủ tìm thấy trong thư.',
  dnsH: 'Tra cứu DNS', dnsDomain: 'example.com hoặc IP', dnsTypeAll: 'Tất cả bản ghi / kiểm tra DNS', dnsTypeAria: 'Loại bản ghi DNS',
  dnsSelector: 'DKIM selector (ví dụ default)', dnsHint: 'DNS gốc do máy chủ này truy vấn. Truy vấn trực tiếp cần LIVE_DNS=1; nếu không, bộ phân giải sẽ báo trạng thái offline.',
  lookup: 'Tra cứu', noRecords: 'không có bản ghi', notFoundLabel: 'không tìm thấy',
  ipH: 'Định vị IP và mạng', ipAddr: '8.8.8.8', ipHint: 'MaxMind GeoLite2 dùng nội bộ. PTR được truy vấn qua máy chủ này. Bản đồ là lược đồ nội bộ; vị trí tương đối và có thể bị ảnh hưởng bởi VPN/proxy.',
  trustH: 'Endpoint AI nội bộ', trustHint: 'Chỉ hỗ trợ endpoint tương thích OpenAI chạy nội bộ (Ollama, LM Studio, llama.cpp, vLLM). Nhà cung cấp đám mây bị từ chối. Key lưu phía máy chủ theo tài khoản và không bao giờ trả lại.',
  llmBase: 'Endpoint', llmModel: 'Model', llmKey: 'API key (nội bộ, tùy chọn)', llmKeyPh: 'token nội bộ (tùy chọn)',
  llmEnabled: 'Bật đánh giá bằng AI nội bộ khi phân tích', trustSave: 'Lưu cài đặt', trustTest: 'Kiểm tra endpoint',
  trustClear: 'Xóa key', trustState: 'Trạng thái máy chủ: đang kiểm tra…', trustStateOn: 'AI nội bộ', trustEnabled: 'đang bật',
  trustDisabled: 'đang tắt', saving: 'Đang lưu…', trustSaved: 'Đã lưu cài đặt.', trustTestOk: 'Endpoint phản hồi.',
  trustTestFail: 'Không kết nối được endpoint.', trustRemoved: 'Đã xóa key.', trustLoadFailed: 'Không tải được cài đặt.',
  adminH: 'Quản trị hệ thống', adminHint: 'Chỉ quản trị viên. Tài khoản được tạo kèm key dùng một lần; máy chủ chỉ lưu bản băm. Tự hạ quyền, tự khóa và xóa quản trị viên cuối cùng đều bị từ chối.',
  adminStats: 'Thống kê hệ thống', adminCreate: 'Tạo tài khoản', adminCreateGo: 'Tạo tài khoản',
  adminUsers: 'Danh sách tài khoản', roleAnalyst: 'Chuyên viên', roleAdmin: 'Quản trị viên',
  cccdPh: 'CCCD (chỉ quản trị viên, dùng làm muối)', adminMsg: 'Đang tải…',
  adminCreated: 'Đã tạo tài khoản. Sao chép key ngay — chỉ hiện một lần.', adminKeyOnce: 'Key dùng một lần',
  adminReset: 'Đặt lại mật khẩu', adminDisable: 'Khóa', adminEnable: 'Mở khóa', adminRole: 'Đổi vai trò',
  adminRename: 'Cấp ID đổi tên', adminSelf: 'Đây là tài khoản của bạn.', adminLast: 'Đây là quản trị viên hoạt động cuối cùng.',
  adminUsersEmpty: 'Chưa có tài khoản.', adminResetPrompt: 'Mật khẩu mới (10–72 ký tự):',
  adminResetOk: 'Đã đặt lại mật khẩu.', adminDisabledOk: 'Đã khóa tài khoản.', adminEnabledOk: 'Đã mở khóa tài khoản.',
  adminRoleOk: 'Đã đổi vai trò.', adminRenameOk: 'ID đổi tên một lần (hiệu lực 15 phút):', adminLoadFailed: 'Không tải được danh sách tài khoản.',
  adminNoCccd: 'Tài khoản quản trị viên bắt buộc nhập CCCD.', adminUid: 'ID người dùng', adminPhone: 'Điện thoại',
  adminLastLogin: 'Đăng nhập cuối', adminCreatedAt: 'Ngày tạo', adminStatus: 'Trạng thái', adminActions: 'Thao tác',
  logsH: 'Nhật ký hoạt động và phiên', logsHint: 'Chỉ admin. Thời gian đăng nhập được đo phía máy chủ; phiên kết thúc được ký SHA-256 và nối với chữ ký trước.',
  auditLog: 'Nhật ký hoạt động', sessionLog: 'Phiên đã ký khi kết thúc', logsEmpty: 'Không có bản ghi.', sessionsEmpty: 'Chưa có phiên nào được ký.',
  logsLoadFailed: 'Không tải được nhật ký.', durationMs: 'Thời lượng (ms)', sessionUser: 'Người dùng', sessionRole: 'Vai trò',
  reasonLabel: 'Lý do', previousLabel: 'Chữ ký trước',
  themeDark: 'Chuyển sang chế độ tối', themeLight: 'Chuyển sang chế độ sáng',
  v_clean: 'Sạch', v_suspicious: 'Đáng ngờ', v_malicious_or_phishing: 'Độc hại / lừa đảo',
  a_clean: 'sạch', a_suspicious: 'đáng ngờ', a_malicious: 'độc hại', a_unverified: 'chưa xác minh',
  a_authentic: 'chính danh', a_spoofed: 'giả mạo',
  st_mail: 'máy chủ thư', st_mx: 'MX', st_web: 'máy chủ web', st_relay: 'relay', st_unknown: 'không rõ',
  e_auth: 'Phiên đã hết hạn — đăng nhập lại.', e_csrf: 'Mã bảo mật đã hết hạn — tải lại trang.',
  e_forbidden: 'Không có quyền.', e_not_found: 'Không tìm thấy.', e_rate: 'Quá nhiều yêu cầu — chờ một phút.',
  e_weak: 'Mật khẩu quá yếu.', e_exists: 'Đã tồn tại.', e_phone_exists: 'Số điện thoại đã đăng ký.',
  e_bad_phone: 'Số điện thoại không hợp lệ.', e_bad_user: 'Tên đăng nhập không hợp lệ.', e_bad_role: 'Vai trò không hợp lệ.',
  e_login: 'Sai thông tin đăng nhập.', e_recover: 'Sai Key ID.', e_pass_bad: 'Sai mật khẩu.',
  e_rename_token: 'ID đổi tên không hợp lệ.', e_rename_expired: 'ID đổi tên đã hết hạn.', e_file: 'Tệp không hỗ trợ.',
  e_parse: 'Không phân tích được tệp.', e_empty: 'Tệp không có thư nào.', e_too_large: 'Tệp quá lớn.',
  e_upload: 'Tải lên thất bại.', e_file_too_large: 'Tệp quá lớn.', e_disk_full: 'Ổ đĩa đầy.',
  e_pdf_failed: 'Tạo PDF thất bại.', e_body_unavailable: 'Không có nội dung.', e_bad_ip: 'Địa chỉ IP không hợp lệ.',
  e_bad_domain: 'Tên miền không hợp lệ.', e_bad_type: 'Loại bản ghi không hợp lệ.', e_selector: 'Cần DKIM selector.',
  e_local_only: 'Chỉ cho phép endpoint AI nội bộ/riêng.', e_bad_url: 'URL không hợp lệ.',
  e_self_forbidden: 'Không thể thao tác trên chính tài khoản của bạn.', e_last_admin: 'Không thể xóa quản trị viên cuối cùng.',
  e_no_location: 'Không có vị trí.', e_ips: 'Chưa nhập IP.', e_disabled: 'Đã tắt đăng ký.',
  e_unknown: 'Lỗi: '
}
};

const t = k => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;
const verdictText = v => t('v_' + v);
const assessText = v => { const k = 'a_' + v, s = t(k); return s === k ? v : s; };
const serverText = k => { const key = 'st_' + k, s = t(key); return s === key ? k : s; };
const errText = code => (code && (I18N[lang]['e_' + code] || I18N.en['e_' + code])) || (t('e_unknown') + (code || 'unknown'));
const apiCode = j => {
  if (!j) return '';
  if (typeof j.error === 'string') return j.error;
  if (j.error && typeof j.error === 'object') return j.error.code || j.error.error || '';
  const d = j.detail;
  if (typeof d === 'string') return d;
  if (d && typeof d === 'object') return d.error || d.code || '';
  return '';
};
const fmtDate = d => {
  if (!d) return '—';
  const x = new Date(d);
  return Number.isNaN(x.getTime()) ? String(d) : x.toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-GB', { hour12: false });
};
const fSize = n => n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB'
  : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB'
    : n >= 1024 ? Math.round(n / 1024) + ' KB' : n + ' B';
const api = (p, o = {}) => fetch(p, { ...o, headers: { ...(o.headers || {}), 'x-csrf': csrf } });
const el = (tag, cls = '', text = null) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== null) e.textContent = text;
  return e;
};
const badge = (text, kind = '') => el('span', 'badge ' + kind, text);
const addKV = (dl, label, value) => {
  const empty = value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length) || value === '—';
  if (empty) return;
  dl.append(el('dt', '', label), el('dd', '', String(value)));
};
const setRunState = (msg, kind = '') => {
  const x = $('runState');
  if (!x) return;
  x.textContent = msg || '';
  x.className = 'summary runstate' + (kind ? ' ' + kind : '');
  x.hidden = !msg;
};
const showKey = key => {
  if (!key) return;
  $('keyval').textContent = key;
  $('keymsg').textContent = '';
  $('keybox').hidden = false;
};
const showAuth = view => {
  $('loginForm').hidden = view !== 'login';
  $('reg').hidden = view !== 'reg';
  $('rec').hidden = view !== 'rec';
  $('err').textContent = '';
  $('nmsg').textContent = '';
  $('rmsg').textContent = '';
  $('rmsg').className = '';
};

// ---------------------------------------------------------------------------
// download helpers — ask for a location when the browser supports it
// ---------------------------------------------------------------------------
function pickerType(name, mime) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return ext ? [{ description: mime || ext.toUpperCase(), accept: { [mime || 'application/octet-stream']: ['.' + ext] } }] : [];
}
async function saveBlob(blob, filename, mime = '') {
  try {
    if (window.showSaveFilePicker) {
      const h = await window.showSaveFilePicker({ suggestedName: filename, types: pickerType(filename, mime) });
      const w = await h.createWritable();
      await w.write(blob);
      await w.close();
      return true;
    }
  } catch (e) {
    if (e && e.name === 'AbortError') return false;
  }
  const u = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = u; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1500);
  return true;
}
async function saveMany(files) {
  try {
    if (window.showDirectoryPicker) {
      const dir = await window.showDirectoryPicker({ mode: 'readwrite' });
      for (const f of files) {
        const h = await dir.getFileHandle(f.name, { create: true });
        const w = await h.createWritable();
        await w.write(f.blob);
        await w.close();
      }
      return true;
    }
  } catch (e) {
    if (e && e.name === 'AbortError') return false;
  }
  for (const f of files) await saveBlob(f.blob, f.name, f.mime || '');
  return true;
}
const blobFrom = async (url, fallback) => {
  const r = await api(url);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(apiCode(j) || String(r.status));
  }
  return r.blob();
};

// ---------------------------------------------------------------------------
// theme
// ---------------------------------------------------------------------------
function applyTheme(dark) {
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  try { localStorage.setItem('theme', dark ? 'dark' : 'light'); } catch {}
  const b = $('themeBtn');
  if (b) {
    b.textContent = dark ? '☀️' : '🌙';
    b.title = dark ? t('themeLight') : t('themeDark');
    b.setAttribute('aria-label', b.title);
  }
}
function initTheme() {
  let dark = false;
  try { dark = localStorage.getItem('theme') === 'dark'; } catch {}
  applyTheme(dark);
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------
async function login() {
  $('err').textContent = '';
  const btn = $('go');
  btn.disabled = true;
  const started = Date.now();
  const timer = setInterval(() => { btn.textContent = `${t('loggingIn')} ${((Date.now() - started) / 1000).toFixed(1)}s`; }, 100);
  try {
    const r = await fetch('/api/login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: $('u').value.trim(), pass: $('p').value })
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 429) { $('err').textContent = t('errRate'); return; }
    if (!r.ok) { $('err').textContent = t('errLogin'); return; }
    enterApp(j);
  } catch (e) {
    $('err').textContent = t('errNetwork') + e.message;
  } finally {
    clearInterval(timer);
    btn.textContent = t('login');
    btn.disabled = false;
  }
}

async function register() {
  $('nmsg').textContent = '';
  const p1 = $('np').value, p2 = $('np2').value;
  if (p1 !== p2) { $('nmsg').textContent = t('errMatch'); return; }
  const btn = $('ngo');
  btn.disabled = true;
  try {
    const r = await fetch('/api/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: $('nu').value.trim(), pass: p1, phone: $('nphone').value.trim() })
    });
    const j = await r.json().catch(() => ({}));
    const code = apiCode(j);
    if (r.status === 429) $('nmsg').textContent = t('errRate');
    else if (code === 'exists') $('nmsg').textContent = t('errExists');
    else if (code === 'phone_exists') $('nmsg').textContent = t('errPhoneExists');
    else if (code === 'bad_phone') $('nmsg').textContent = t('errBadPhone');
    else if (code === 'bad_user') $('nmsg').textContent = t('errBadUser');
    else if (code === 'weak') $('nmsg').textContent = t('errWeak');
    else if (code === 'disabled') $('nmsg').textContent = t('errDisabled');
    else if (!r.ok) $('nmsg').textContent = t('errRegister');
    else {
      const creds = { user: $('nu').value.trim(), pass: p1 };
      $('nu').value = ''; $('np').value = ''; $('np2').value = ''; $('nphone').value = '';
      showAuth('login');
      $('u').value = creds.user; $('p').value = creds.pass;
      await login();
      showKey(j.recovery);
    }
  } catch (e) {
    $('nmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

async function recover() {
  $('rmsg').textContent = '';
  $('rmsg').className = '';
  const btn = $('rgo');
  btn.disabled = true;
  try {
    const r = await fetch('/api/recover', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: $('ru').value.trim(), key: $('rk').value, new: $('rp').value })
    });
    const j = await r.json().catch(() => ({}));
    const code = apiCode(j);
    if (r.status === 429) $('rmsg').textContent = t('errRate');
    else if (code === 'weak') $('rmsg').textContent = t('errWeak');
    else if (!r.ok) $('rmsg').textContent = t('errRecover');
    else {
      $('rk').value = ''; $('rp').value = '';
      showKey(j.recovery);
      showAuth('login');
      $('u').value = j.user || '';
      $('rmsg').textContent = t('recOk');
      $('rmsg').className = 'ok';
    }
  } catch (e) {
    $('rmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

function enterApp(j) {
  csrf = j.csrf || '';
  user = j.user || '';
  role = j.role || 'analyst';
  uid = j.uid || '';
  $('login').hidden = true;
  $('app').hidden = false;
  $('accountBar').hidden = false;
  $('p').value = '';
  lastLoginMs = Number(j.loginMs) || 0;
  profileData = null;
  histLoaded = false; histCases = [];
  logsLoaded = false; logsData = []; sessionsData = [];
  adminLoaded = false; adminUsers = [];
  $('histOut').textContent = ''; $('histMsg').textContent = '';
  $('logsOut').textContent = ''; $('sessionsOut').textContent = ''; $('logsMsg').textContent = '';
  const admin = role === 'admin';
  $('tabAdmin').hidden = !admin;
  $('tabLogs').hidden = !admin;
  if (!admin && !$('paneAdmin').hidden) switchTab('tabAnalysis');
  if (!admin && !$('paneLogs').hidden) switchTab('tabAnalysis');
  const plat = (() => { try { return localStorage.getItem('platform') || 'auto'; } catch { return 'auto'; } })();
  if ($('platform')) $('platform').value = plat;
  renderWho();
  startSessionTimer(j.expiresAt);
  loadProfile();
  loadDashboard();
  }

function leaveApp() {
  csrf = ''; user = ''; role = ''; uid = '';
  if (job) { job.cancelled = true; try { job.ac?.abort(); } catch {} job = null; }
  last = null; lastResults = []; lastErrors = [];
  clearInterval(sessionTimerId); sessionTimerId = null; sessionExpires = 0; lastLoginMs = 0;
  profileData = null; adminUsers = []; adminLoaded = false;
  histLoaded = false; histCases = [];
  logsLoaded = false; logsData = []; sessionsData = [];
  $('app').hidden = true;
  $('login').hidden = false;
  $('accountBar').hidden = true;
  $('accountMenu').open = false;
  $('keybox').hidden = true;
  $('f').value = ''; $('fdir').value = '';
  picked = []; pfRejected = []; setRunState(''); renderPick();
  $('out').textContent = '';
  $('resultsOut').textContent = '';
  $('live').hidden = true;
  $('po').value = ''; $('pn').value = ''; $('pmsg').textContent = '';
  $('rnToken').value = ''; $('rnNew').value = ''; $('rnPass').value = ''; $('rnMsg').textContent = '';
  lastDns = null; lastIp = null;
  $('dnsDomain').value = ''; $('dnsOut').textContent = ''; $('dnsMsg').textContent = '';
  $('ipAddr').value = ''; $('ipOut').textContent = ''; $('ipMsg').textContent = '';
  $('histQ').value = ''; $('histOut').textContent = ''; $('histMsg').textContent = '';
  $('logsOut').textContent = ''; $('sessionsOut').textContent = ''; $('logsMsg').textContent = '';
  $('tabAdmin').hidden = true; $('tabLogs').hidden = true;
  $('adminUsers').textContent = ''; $('adminStats').textContent = ''; $('adminMsg').textContent = '';
  $('avatarMsg').textContent = ''; $('avatarFile').value = '';
  for (const id of ['avatarSm', 'avatarBig']) { const x = $(id); if (x) { x.hidden = true; x.removeAttribute('src'); } }
  for (const id of ['avatarSmMono', 'avatarBigMono']) { const x = $(id); if (x) { x.hidden = true; x.textContent = ''; } }
  showAuth('login');
}

function renderWho() {
  if ($('who')) $('who').textContent = user ? t('signedIn') + user : '';
  if ($('accountName')) $('accountName').textContent = user || '';
}

// ---------------------------------------------------------------------------
// profile / password / rename / avatar
// ---------------------------------------------------------------------------
function renderProfile() {
  if (!profileData) return;
  const p = profileData;
  $('profileMeta').textContent = `${p.user} · ${t('profileRole')}: ${p.role} · ${t('profileCreated')}: ${fmtDate(p.created)}`;
  $('loginMs').textContent = lastLoginMs ? `${t('loginTime')}: ${lastLoginMs} ms` : '';
  const src = p.hasAvatar ? `/api/profile/avatar?v=${encodeURIComponent(p.avatarUpdated || '')}` : '';
  for (const id of ['avatarSm', 'avatarBig']) {
    const img = $(id);
    if (!img) continue;
    if (src) { img.src = src; img.hidden = false; } else { img.removeAttribute('src'); img.hidden = true; }
  }
  const initial = (String(p.user || '?').trim().charAt(0) || '?').toUpperCase();
  for (const id of ['avatarSmMono', 'avatarBigMono']) {
    const x = $(id);
    if (!x) continue;
    if (src) { x.hidden = true; x.textContent = ''; } else { x.textContent = initial; x.hidden = false; }
  }
}

function renderSessionTimer() {
  if (!sessionExpires) { $('sessionTimer').textContent = ''; return; }
  const left = Math.max(0, sessionExpires - Date.now());
  const total = Math.floor(left / 1000);
  const hh = String(Math.floor(total / 3600)).padStart(2, '0');
  const mm = String(Math.floor((total % 3600) / 60)).padStart(2, '0');
  const ss = String(total % 60).padStart(2, '0');
  $('sessionTimer').textContent = `${t('sessionTime')}: ${hh}:${mm}:${ss}`;
  if (left <= 0) {
    clearInterval(sessionTimerId); sessionTimerId = null;
    leaveApp();
    $('err').textContent = t('sessionExpired');
  }
}
function startSessionTimer(expiresAt) {
  clearInterval(sessionTimerId);
  sessionTimerId = null;
  sessionExpires = Number(expiresAt) || 0;
  renderSessionTimer();
  if (sessionExpires) sessionTimerId = setInterval(renderSessionTimer, 1000);
}

async function loadProfile() {
  try {
    const r = await api('/api/profile');
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (r.ok) { profileData = j; renderProfile(); }
  } catch {}
}

async function uploadAvatar() {
  $('avatarMsg').textContent = '';
  const file = $('avatarFile').files?.[0];
  if (!file) return;
  const typeOk = ['image/png', 'image/jpeg'].includes(file.type) || /\.(png|jpe?g)$/i.test(file.name);
  if (!typeOk) { $('avatarMsg').textContent = t('avatarBadType'); return; }
  if (file.size > 2 * 1024 * 1024) { $('avatarMsg').textContent = t('avatarTooLarge'); return; }
  const fd = new FormData();
  fd.append('avatar', file);
  const btn = $('avatarUpload');
  btn.disabled = true;
  try {
    const r = await api('/api/profile/avatar', { method: 'POST', body: fd });
    const j = await r.json().catch(() => ({}));
    const code = apiCode(j);
    if (r.status === 401 || code === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!r.ok) {
      $('avatarMsg').textContent = code === 'avatar_too_large' ? t('avatarTooLarge')
        : code === 'bad_avatar' ? t('avatarBad') : code === 'rate' ? t('errRate') : t('avatarFailed');
      return;
    }
    $('avatarFile').value = '';
    $('avatarMsg').textContent = t('avatarOk');
    await loadProfile();
  } catch (e) {
    $('avatarMsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

async function changePassword() {
  $('pmsg').textContent = '';
  const btn = $('pgo');
  btn.disabled = true;
  try {
    const r = await api('/api/password', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ current: $('po').value, new: $('pn').value })
    });
    const j = await r.json().catch(() => ({}));
    const code = apiCode(j);
    if (r.status === 401 || code === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    $('pmsg').textContent = r.ok ? t('passOk')
      : code === 'weak' ? t('errWeak') : r.status === 429 ? t('errRate') : t('passBad');
    if (r.ok) { $('po').value = ''; $('pn').value = ''; setTimeout(leaveApp, 1200); }
  } catch (e) {
    $('pmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

async function renameAccount() {
  $('rnMsg').textContent = '';
  const btn = $('rnGo');
  btn.disabled = true;
  try {
    const r = await api('/api/profile/rename', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: $('rnToken').value.trim(), new: $('rnNew').value.trim(), pass: $('rnPass').value })
    });
    const j = await r.json().catch(() => ({}));
    const code = apiCode(j);
    $('rnMsg').textContent = r.ok ? t('renameOk')
      : code === 'rename_expired' ? t('renameExpired')
        : code === 'exists' ? t('errExists')
          : code === 'bad_user' ? t('errBadUser')
            : code === 'pass_bad' ? t('passBad') : t('renameFailed');
    if (r.ok) { $('rnToken').value = ''; $('rnNew').value = ''; $('rnPass').value = ''; setTimeout(leaveApp, 1200); }
  } catch (e) {
    $('rnMsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

// ---------------------------------------------------------------------------
// tabs
// ---------------------------------------------------------------------------
function switchTab(id) {
  for (const tab of document.querySelectorAll('.tab')) {
    const active = tab.id === id;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
    const pane = $(tab.dataset.pane);
    if (pane) pane.hidden = !active;
  }
}
document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    switchTab(tab.id);
    if (tab.id === 'tabHistory') loadHistory();
    if (tab.id === 'tabLogs') loadLogs();
    if (tab.id === 'tabCase') renderCasePane();
    if (tab.id === 'tabAdmin') loadAdmin();
    if (tab.id === 'tabResults') renderCurrentResult();
  };
});
// MailSleuth frontend — part 2: analysis streaming, results, message viewer, URL intel, graph.
let picked = []; // {f, path}
let pfRejected = []; // {path, size, reason}
let job = null; // {paused, stopped, cancelled, ac, done, failed}
let resTab = 'overview';
let currentIdx = 0;

const OK_EXT = /\.(eml|emlx|mht|mhtml|msg|mbox|mbx|txt)$/i;
const PICK_FILE_MAX = 80 * 1024 * 1024;
const PICK_TOTAL_MAX = 2000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function addFiles(fileList, prefix = '') {
  const items = Array.from(fileList || []).map(f => ({
    f,
    path: prefix ? prefix.replace(/\/+$/, '') + '/' + f.name
      : (typeof f.__path === 'string' && f.__path ? f.__path : (f.webkitRelativePath || f.name))
  }));
  addItems(items);
}

function addItems(items) {
  const rejected = [];
  const seen = new Set(picked.map(x => x.path + '|' + x.f.size + '|' + x.f.lastModified));
  for (const { f, path } of items) {
    const reason = !OK_EXT.test(f.name) ? 'pfBadExt'
      : f.size === 0 ? 'pfEmpty'
        : f.size > PICK_FILE_MAX ? 'pfTooLarge' : null;
    if (reason) { rejected.push({ path, size: f.size, reason }); continue; }
    const key = path + '|' + f.size + '|' + f.lastModified;
    if (seen.has(key)) { rejected.push({ path, size: f.size, reason: 'pfDupe' }); continue; }
    seen.add(key);
    picked.push({ f, path });
  }
  pfRejected = rejected;
  renderPick();
}

function renderPick() {
  const list = $('flist');
  if (!list) return;
  list.textContent = '';
  const total = picked.reduce((s, x) => s + x.f.size, 0);
  const skipped = pfRejected.filter(x => x.reason !== 'pfDupe').length;
  const dupes = pfRejected.length - skipped;
  let msg = picked.length ? `${picked.length} ${t('pickFiles')} · ${fSize(total)}` : t('pickNone');
  if (skipped) msg += ` · ${skipped} ${t('pickSkipped')}`;
  if (dupes) msg += ` · ${dupes} ${t('pickDup')}`;
  if (picked.length > PICK_TOTAL_MAX) msg += ` · ${t('pickLimit')}`;
  if (picked.length && !pfRejected.length) msg += ` · ✓ ${t('pfReady')}`;
  $('pickMsg').textContent = msg;
  picked.forEach((x, i) => {
    const li = el('li', 'filerow');
    li.append(el('span', 'fname', x.path), el('span', 'fsize', fSize(x.f.size)));
    const rm = el('button', 'ghost', '×');
    rm.type = 'button';
    rm.title = t('pickRemove');
    rm.setAttribute('aria-label', t('pickRemove') + ': ' + x.path);
    rm.onclick = () => { picked.splice(i, 1); renderPick(); };
    li.append(rm);
    list.append(li);
  });
  const pf = $('preflight');
  if (pf) {
    const pl = $('pfList');
    pl.textContent = '';
    if (pfRejected.length) {
      pf.hidden = false;
      $('pfMsg').textContent = `${pfRejected.length} ${t('pfRejected')}`;
      for (const x of pfRejected) {
        const li = el('li', 'filerow pfbad');
        li.append(el('span', 'fname', x.path), el('span', 'fsize', fSize(x.size || 0)));
        li.append(el('span', 'pfreason', t(x.reason)));
        pl.append(li);
      }
    } else pf.hidden = true;
  }
  syncRunButtons();
}

function syncRunButtons() {
  if (!$('run')) return;
  const running = !!job;
  $('run').disabled = running || !picked.length || picked.length > PICK_TOTAL_MAX;
  const p = $('btnPause'), s = $('btnStop'), c = $('btnCancel');
  if (p) { p.disabled = !running || (job && (job.stopped || job.cancelled)); p.textContent = t(job && job.paused ? 'resume' : 'pause'); }
  if (s) s.disabled = !running || !!(job && (job.stopped || job.cancelled));
  if (c) c.disabled = !running || !!(job && job.cancelled);
}

async function waitIfPaused() {
  if (!job || !job.paused) return;
  setRunState(t('runPaused'), 'warn');
  while (job && job.paused && !job.stopped && !job.cancelled) await sleep(150);
  if (job && !job.stopped && !job.cancelled) setRunState(t('runRunning'));
}

function setLive(title, l1, l2, l3, pct, running = true) {
  const box = $('live');
  if (!box) return;
  box.hidden = false;
  $('liveTitle').textContent = title || '';
  $('liveL1').textContent = l1 || '';
  $('liveL2').textContent = l2 || '';
  $('liveL3').textContent = l3 || '';
  const v = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
  $('progPct').textContent = v + '%';
  const amp = $('ampBar');
  if (amp) {
    amp.setAttribute('aria-valuenow', String(v));
    amp.classList.toggle('running', !!running);
    const bars = [...amp.children];
    bars.forEach((b, i) => {
      const phase = (v / 7) + i * 0.75;
      const h = 18 + 78 * Math.abs(Math.sin(phase));
      b.style.height = h.toFixed(0) + '%';
      b.classList.toggle('lit', (i + 1) / bars.length <= v / 100);
    });
  }
}
function hideLive() { const x = $('live'); if (x) x.hidden = true; }

class StreamError extends Error {
  constructor(code, detail = '') { super(code || 'parse'); this.code = code || 'parse'; this.detail = detail; }
}

async function streamOne(item, idx, total, basePct) {
  const fd = new FormData();
  fd.append('file', item.f, item.f.name);
  fd.append('platform', $('platform').value || 'auto');
  fd.append('lang', lang);
  const ac = new AbortController();
  job.ac = ac;
  const pctFor = p => Math.min(99.5, basePct + (p / 100) * (100 / total));
  setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
    `${t('liveFile')}: ${item.path}`,
    `${t('liveStage')}: ${t('stepUpload')}`,
    `${fSize(item.f.size)}`, pctFor(2), true);
  const r = await fetch('/api/analyze/stream', { method: 'POST', body: fd, headers: { 'x-csrf': csrf }, signal: ac.signal });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new StreamError(apiCode(j) || (r.status === 401 ? 'auth' : 'upload'));
  }
  if (!r.body) throw new StreamError('parse');
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let result = null;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      const p = pctFor(Number(ev.pct) || 0);
      if (ev.type === 'stage') {
        const stage = ev.stage === 'receive' ? t('stepUpload') : t('stepProcess');
        const detail = ev.bytes != null ? `${fSize(ev.bytes)}` : '';
        setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
          `${t('liveFile')}: ${ev.file || item.path}`,
          `${t('liveStage')}: ${stage}`, detail, p, true);
      } else if (ev.type === 'result') {
        result = ev.result;
        const rr = result || {};
        setLive(`${t('liveTitle')} ${idx + 1}/${total}`,
          `${t('liveFile')}: ${rr.custody?.original || item.path}`,
          `${t('liveStage')}: ${String(rr.format || '').toUpperCase()} × ${rr.count || 0}`,
          `${t('verdict')}: ${verdictText(rr.verdict)} · ${rr.score}/100 · ${rr.client?.label || ''}`,
          p, false);
      } else if (ev.type === 'error') {
        throw new StreamError(ev.error || 'parse', ev.detail || '');
      }
    }
  }
  if (!result) throw new StreamError('parse');
  return result;
}

async function startAnalysis() {
  if (job) return;
  const files = picked.slice();
  if (!files.length) { $('out').textContent = t('noFile'); return; }
  if (files.length > PICK_TOTAL_MAX) { $('out').textContent = t('pickLimit'); return; }
  $('out').textContent = '';
  $('resultsOut').textContent = '';
  last = null; lastResults = []; lastErrors = [];
  job = { paused: false, stopped: false, cancelled: false, ac: null, done: [], failed: null };
  syncRunButtons();
  setRunState(t('runRunning'));
  setLive(t('liveTitle'), t('stepValidate'), '', '', 0, true);
  const results = [], errors = [];
  let netErr = '';
  try {
    for (let i = 0; i < files.length; i++) {
      await waitIfPaused();
      if (!job || job.cancelled || job.stopped) break;
      const basePct = (i / files.length) * 100;
      try {
        const r = await streamOne(files[i], i, files.length, basePct);
        results.push(r);
        if (job) job.done.push(files[i]);
      } catch (e) {
        if (e && e.name === 'AbortError' && (!job || job.cancelled || job.stopped)) break;
        if (e instanceof StreamError && e.code === 'auth') {
          leaveApp(); $('err').textContent = t('e_auth'); return;
        }
        const code = (e && e.code) || 'parse';
        const detail = (e && e.detail) || (e && e.message) || '';
        errors.push({ file: files[i].path, error: code, detail });
        if (job) job.failed = { file: files[i].path, code, detail };
        break;
      }
    }
  } catch (e) {
    netErr = t('errNetwork') + (e && e.message ? e.message : String(e));
  }
  const wasCancelled = !!(job && job.cancelled);
  const wasStopped = !!(job && job.stopped);
  const done = job ? job.done.slice() : [];
  const failed = job ? job.failed : null;
  job = null;
  syncRunButtons();

  if (wasCancelled) {
    last = null; lastResults = []; lastErrors = [];
    $('resultsOut').textContent = '';
    hideLive();
    setRunState(t('runCancelled'), 'bad');
    return;
  }

  // Finished files leave the picker so a resume continues exactly at the
  // failing/remaining file instead of re-analyzing everything.
  if (done.length) {
    const doneKeys = new Set(done.map(x => x.path + '|' + x.f.size + '|' + x.f.lastModified));
    picked = picked.filter(x => !doneKeys.has(x.path + '|' + x.f.size + '|' + x.f.lastModified));
    renderPick();
  }

  if (results.length) {
    lastResults = results;
    lastErrors = errors;
    currentIdx = 0;
    resTab = 'overview';
    last = results.reduce((a, b) => (b.score > a.score || (b.score === a.score && a.verdict === 'clean' && b.verdict !== 'clean')) ? b : a);
    histLoaded = false;
    renderCurrentResult();
    switchTab('tabResults');
    loadDashboard();
  }

  if (failed) {
    const msg = `${t('uploadErrors')}: ${failed.file} — ${errText(failed.code)}${failed.detail ? ' (' + failed.detail + ')' : ''}. ${t('runStopping')}`;
    setRunState(msg, 'bad');
    if (!results.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      box.append(el('div', '', `${failed.file}: ${errText(failed.code)}${failed.detail ? ' — ' + failed.detail : ''}`));
      $('out').append(box);
    }
  } else if (netErr) {
    setRunState(netErr, 'bad');
  } else if (wasStopped) {
    setRunState(`${t('runStopped')} ${results.length}/${files.length}`, 'warn');
  } else if (errors.length) {
    setRunState(t('uploadErrors'), 'bad');
  } else {
    setRunState('');
  }
  if (!results.length && !failed) {
    if (errors.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      errors.forEach(e => box.append(el('div', '', `${e.file}: ${errText(e.error)}${e.detail ? ' — ' + e.detail : ''}`)));
      $('out').append(box);
    } else if (wasStopped) {
      $('out').textContent = t('runStoppedNoResults');
    } else if (!netErr) {
      $('out').textContent = errText('upload');
    }
  }
  hideLive();
}

// ---------------------------------------------------------------------------
// results rendering
// ---------------------------------------------------------------------------
const bodyCache = new Map();
const verdictClass = v => v === 'malicious_or_phishing' ? 'malicious' : v === 'suspicious' ? 'suspicious' : 'clean';
const verdictGlow = v => v === 'malicious_or_phishing' ? 'glow-red' : v === 'suspicious' ? 'glow-yellow' : v === 'clean' ? '' : 'glow-blue';
const platformIcon = p => p === 'linux' ? '🐧' : '🪟';
const clientIcon = key => {
  const k = String(key || '').toLowerCase();
  if (k.includes('outlook') || k.includes('exchange')) return '🪟';
  if (k.includes('thunderbird')) return '🦅';
  if (k.includes('apple')) return '🍎';
  if (k.includes('gmail')) return '✉️';
  if (k.includes('maildir') || k.includes('mbox')) return '🐧';
  return '✉️';
};
const currentCase = () => (lastResults[currentIdx]?.custody?.caseId) || '';

function renderCurrentResult() {
  const out = $('resultsOut');
  if (!out) return;
  const r = lastResults[currentIdx];
  if (!r) {
    $('resultCase').textContent = t('noResult');
    out.textContent = '';
    return;
  }
  $('resultCase').textContent = '';
  if (lastResults.length > 1) {
    const sel = el('select', 'caseSel');
    lastResults.forEach((x, i) => {
      const o = el('option', '', `${i + 1}. ${x.custody?.original || ''} — ${verdictText(x.verdict)}`);
      o.value = String(i);
      o.selected = i === currentIdx;
      sel.append(o);
    });
    sel.onchange = () => { currentIdx = Number(sel.value) || 0; resTab = 'overview'; renderCurrentResult(); };
    $('resultCase').append(sel);
  }
  $('resultCase').append(el('span', '', ` ${t('caseLabel')}: ${r.custody?.caseId || ''} · ${t('shaLabel')} ${r.custody?.sha256 || ''}`));
  out.textContent = '';

  const strip = el('div', 'clientTabs');
  const first = el('button', 'clientTab active');
  first.type = 'button';
  first.append(el('span', 'clientIco', platformIcon(r.platform)),
    el('span', '', ` ${r.client?.label || r.format || ''} `),
    badge(`${String(r.format || '').toUpperCase()} × ${r.count || 0}`, 'ok'));
  first.title = t('clientLabel');
  strip.append(first);
  strip.append(el('span', 'clientMeta', `${t('platformLabel')}: ${r.platform || 'auto'} · ${t('verdict')}: ${verdictText(r.verdict)} · ${r.score}/100`));
  out.append(strip);

  const tabs = el('div', 'subtabs');
  for (const [key, label] of [['overview', t('resOverview')], ['messages', t('resMessages')], ['urls', t('resUrls')], ['graph', t('resGraph')]]) {
    const b = el('button', 'subtab' + (resTab === key ? ' active' : ''), label);
    b.type = 'button';
    b.onclick = () => { resTab = key; renderCurrentResult(); };
    tabs.append(b);
  }
  out.append(tabs);
  const body = el('div', 'resBody');
  out.append(body);
  if (resTab === 'messages') renderMessages(body, r);
  else if (resTab === 'urls') renderUrls(body, r);
  else if (resTab === 'graph') renderGraph(body, r);
  else renderOverview(body, r);
}

function renderOverview(out, r) {
  const cls = verdictClass(r.verdict);
  const banner = el('div', `verdictBanner ${cls} ${verdictGlow(r.verdict)}`);
  banner.append(el('strong', '', `${t('verdict')}: ${verdictText(r.verdict)}`),
    el('span', '', ` · ${t('score')}: ${r.score}/100`),
    el('span', 'bannerMeta', ` · ${r.format?.toUpperCase()} × ${r.count}${r.truncated ? '+' : ''} · ${r.client?.label || ''}`));
  out.append(banner);

  const stats = el('div', 'statRow');
  for (const [n, label] of [[r.count || 0, t('messagesLabel')], [(r.attachments || []).length, t('attachments')],
    [(r.findings || []).length, t('findings')], [(r.urls || []).length, 'URL'], [(r.originIPs || []).length, 'IP']]) {
    const c = el('div', 'statCard');
    c.append(el('b', '', String(n)), el('span', '', label));
    stats.append(c);
  }
  out.append(stats);

  const meta = el('dl', 'kv');
  addKV(meta, t('custodyLabel'), `${r.custody?.caseId || ''} · ${fmtDate(r.custody?.utc)}`);
  addKV(meta, t('shaLabel'), r.custody?.sha256);
  addKV(meta, t('signatureLabel'), r.signature?.sha256);
  addKV(meta, t('formatLabel'), `${r.format} · ${r.platform}`);
  addKV(meta, t('clientLabel'), r.client?.label);
  out.append(meta);

  renderForensics(out, r);
  renderThreats(out, r);
  renderEnrichment(out, r);

  const fh = el('h4', '', `${t('findings')} (${(r.findings || []).length})`);
  out.append(fh);
  if (!r.findings?.length) {
    out.append(el('div', 'f s0', t('noFindings')));
  } else {
    for (const f of r.findings.slice(0, 300)) {
      const d = el('div', 'f s' + (f.sev ?? 0) + (f.weight === 0 ? ' info' : ''));
      d.textContent = `${r.count > 1 ? '#' + ((f.m ?? 0) + 1) + ' ' : ''}${f.type || ''}: ${f.evidence || ''}`;
      out.append(d);
    }
    if (r.findings.length > 300) out.append(el('p', 'hint', t('shown')));
  }

  if (r.attachments?.length) {
    const det = el('details');
    det.append(el('summary', '', `${t('attachments')} (${r.attachments.length})`));
    const ul = el('ul', 'att');
    for (const a of r.attachments.slice(0, 200)) {
      const li = el('li', '', `${a.m !== undefined ? '#' + (a.m + 1) + ' ' : ''}${a.name} — ${a.size} B — ${a.sha256}${a.magic && a.magic !== 'unknown' ? ' — ' + a.magic : ''}`);
      if (a.scanEngines?.length) {
        li.append(' - ', badge('scan: ' + a.scanEngines.join(', '), a.verdict === 'malicious' ? 'bad' : a.verdict === 'suspicious' ? 'warn' : ''));
      }
      if (a.verdict && a.verdict !== 'clean') {
        li.append(' - ', badge(assessText(a.verdict), a.verdict === 'malicious' ? 'bad' : 'warn'));
        const tip = [];
        if (a.reasons?.length) tip.push(a.reasons.join('; '));
        if (a.scanMatches?.length) tip.push(a.scanMatches.map(m => (m.engine || '') + ':' + (m.rule || m.description || '')).join('; '));
        if (tip.length) li.title = tip.join(' | ');
      } else if (a.scanMatches?.length) {
        li.title = a.scanMatches.map(m => (m.engine || '') + ':' + (m.rule || m.description || '')).join('; ');
      }
      ul.append(li);
    }
    det.append(ul);
    out.append(det);
  }
}

function renderAuthDetails(auth) {
  const box = el('div', 'authbox');
  if (!auth?.headerFound) {
    box.append(el('p', 'hint', t('missing')));
    return box;
  }
  const dl = el('dl', 'kv');
  addKV(dl, t('authservLabel') || 'Authentication server', auth.authservId);
  addKV(dl, t('statusLabel'), auth.overall);
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const x = auth[k] || {};
    addKV(dl, k.toUpperCase(), x.result || 'none');
    addKV(dl, `${k.toUpperCase()} domain`, x.domain);
    if (k === 'dkim') addKV(dl, t('selectorLabel'), x.selector);
    if (k === 'dmarc') addKV(dl, t('policy'), x.policy);
    if (k === 'spf' || k === 'dkim') addKV(dl, `${k.toUpperCase()} ${t('alignmentLabel')}`, auth.alignment?.[k] === true ? t('yesLabel') : auth.alignment?.[k] === false ? t('noLabel') : t('unknownLabel'));
  }
  const up = auth.upstream || {};
  if (up.raw) {
    addKV(dl, t('upstreamLabel'), up.authserv || '—');
    addKV(dl, t('upstreamSpf'), up.spf || '—');
    addKV(dl, t('upstreamDkim'), up.dkim || '—');
    addKV(dl, t('upstreamDmarc'), up.dmarc || '—');
  }
  const sigs = auth.dkimSignatures || [];
  if (sigs.length > 1) addKV(dl, t('dkimSignaturesLabel'), sigs.map(s => `${s.domain || '?'}/${s.selector || '?'}=${s.result || '?'}`).join(', '));
  box.append(dl);
  if (auth.raw) {
    const det = el('details');
    det.append(el('summary', '', t('authHeaderLabel') || 'Authentication-Results header'), el('pre', 'rawtext', auth.raw));
    box.append(det);
  }
  return box;
}

const authKind = result => {
  const r = String(result || '').toLowerCase();
  if (r === 'pass') return 'ok';
  if (['none', 'neutral', 'softfail'].includes(r)) return 'warn';
  return r ? 'bad' : 'warn';
};
const authLine = auth => {
  const wrap = el('span', 'authbadges');
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const r = auth?.[k]?.result;
    wrap.append(badge(`${k.toUpperCase()} ${r || 'none'}`, authKind(r)));
  }
  return wrap;
};

async function openMessage(caseId, index, msg, container) {
  if (container.dataset.loaded) return;
  container.dataset.loaded = '1';
  container.textContent = '…';
  try {
    const key = caseId + ':' + index;
    let data = bodyCache.get(key);
    if (!data) {
      const r = await api(`/api/case/${caseId}/message/${index}`);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(apiCode(j) || r.status);
      data = j;
      bodyCache.set(key, data);
    }
    container.textContent = '';
    const md = el('dl', 'kv');
    addKV(md, t('fromLabel'), msg.fromName ? `${msg.fromName} <${msg.from || ''}>` : msg.from);
    addKV(md, t('toLabel'), (msg.to || []).join(', '));
    addKV(md, t('replyToLabel'), msg.replyTo);
    addKV(md, t('returnPathLabel'), msg.returnPath);
    addKV(md, t('dateLabel'), fmtDate(msg.date));
    addKV(md, t('messageIdLabel'), msg.messageId);
    addKV(md, t('originIps'), (msg.originIPs || []).join(', '));
    addKV(md, t('statusLabel'), `${verdictText(msg.verdict)} · ${msg.score}/100`);
    container.append(el('h4', '', t('authLabel')), authLine(msg.auth), renderAuthDetails(msg.auth), md);
    if (data.headers) {
      const det = el('details');
      det.append(el('summary', '', 'Raw headers'), el('pre', 'rawtext', data.headers));
      container.append(det);
    }
    if (data.text) container.append(el('h4', '', t('bodyText')), el('pre', 'mailtext', data.text));
    if (data.html) {
      container.append(el('h4', '', t('bodyHtml')), el('p', 'hint', t('htmlBlocked')));
      const frame = el('iframe', 'mailhtml');
      frame.setAttribute('sandbox', '');
      frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.title = t('bodyHtml');
      frame.srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:.75rem;color:#111;word-break:break-word}pre{white-space:pre-wrap}table{border-collapse:collapse}td,th{border:1px solid #999;padding:.25rem}</style></head><body>${data.html}</body></html>`;
      container.append(frame);
    }
    if (!data.text && !data.html) container.append(el('p', 'hint', t('bodyEmpty')));
    if (data.truncated) container.append(el('p', 'hint', t('bodyTruncated')));
    if (data.omitted) container.append(el('p', 'hint', t('bodyOmitted')));
  } catch (e) {
    container.dataset.loaded = '';
    container.textContent = t('contentLoadFailed') + ' ' + e.message;
  }
}

function renderMessages(out, r) {
  if (!r?.messages?.length) return;
  out.append(el('h4', '', `${t('messagesLabel')} (${r.messages.length})`));
  const list = el('div', 'msglist');
  r.messages.slice(0, 200).forEach((m, i) => {
    const det = el('details', 'msg');
    const sum = el('summary');
    sum.append(
      el('span', 'msgnum', '#' + (i + 1)),
      el('strong', 'msgsubject', m.subject || '(no subject)'),
      el('span', 'msgfrom', m.fromName ? `${m.fromName} <${m.from || ''}>` : (m.from || '—')),
      el('span', 'msgdate', fmtDate(m.date)),
      el('span', 'msgscore', `${verdictText(m.verdict)} · ${m.score}/100`),
      authLine(m.auth)
    );
    det.append(sum);
    const box = el('div', 'msgbody', '…');
    det.append(box);
    det.addEventListener('toggle', () => { if (det.open) openMessage(r.custody.caseId, i, m, box); });
    list.append(det);
  });
  out.append(list);
  if (r.messages.length > 200) out.append(el('p', 'hint', t('showFirstMessages')));
}

function renderForensics(out, r) {
  if (!out || !r) return;
  const auth = r.auth || {};
  const hdr = r.headerAnalysis || {};
  const rt = r.routing || {};
  if (!auth.spf && !auth.dmarc && !rt.hopCount && !hdr.receivedCount) return;
  const sec = el('section', 'toolcard');
  const head = el('div', 'toolhead');
  head.append(el('h5', '', t('forensics')));
  const badges = el('span', '');
  for (const [label, a] of [['SPF', auth.spf], ['DKIM', auth.dkim], ['DMARC', auth.dmarc]]) {
    const res = a?.result || 'none';
    const kind = res === 'pass' ? 'ok' : (res === 'fail' ? 'bad' : (res === 'not_run' ? 'warn' : ''));
    badges.append(badge(`${label}: ${res}${res === 'fail' && a?.policy ? ' (p=' + a.policy + ')' : ''}`, kind), ' ');
  }
  head.append(badges);
  sec.append(head);
  const dl = el('dl', 'kv');
  if (auth.envDomain || auth.clientIp) addKV(dl, t('authEnvelope'), `${auth.envDomain || '—'} · ${auth.clientIp || '—'}`);
  if (hdr.receivedCount != null) addKV(dl, t('receivedCount'), String(hdr.receivedCount));
  if (rt.hopCount) addKV(dl, t('totalTransit'), `${rt.totalDelayMs || 0} ms`);
  if (dl.childElementCount) sec.append(dl);
  const checks = (hdr.checks || []).concat(rt.anomalies || []);
  if (checks.length) {
    const det = el('details');
    det.append(el('summary', '', `${t('headerChecks')} (${checks.length})`));
    for (const f of checks.slice(0, 60)) det.append(el('div', 'f s' + (f.sev ?? 0) + (f.weight === 0 ? ' info' : ''), `${f.id || ''} ${f.type || ''}: ${f.evidence || ''}`));
    sec.append(det);
  }
  if (rt.hops?.length) {
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('hopFrom'), 'By', 'With', t('gatewayLabel'), t('hopDelay'), t('hopTime')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const h of rt.hops.slice(0, 40)) {
      const tr = el('tr');
      tr.append(el('td', '', '#' + h.idx),
        el('td', '', `${h.from || '—'}${h.ip ? ' (' + h.ip + ')' : ''}`),
        el('td', '', h.by || '—'), el('td', '', h.with || '—'), el('td', '', h.gateway || '—'),
        el('td', '', h.delayMs != null ? h.delayMs + ' ms' : '—'), el('td', '', h.ts || '—'));
      table.append(tr);
    }
    sec.append(table);
  }
  out.append(sec);
}

function renderThreats(out, r) {
  if (!out || !r) return;
  const urls = r.urls || [], atts = r.attachments || [], ioc = r.ioc || { counts: {} };
  if (!urls.length && !atts.length) return;
  const sec = el('section', 'toolcard');
  const head = el('div', 'toolhead');
  head.append(el('h5', '', t('threats')));
  const c = ioc.counts || {};
  if (Object.keys(c).length) head.append(badge(t('iocCount') + ': ' + Object.entries(c).map(([k, v]) => k + ' ' + v).join(', '), 'warn'));
  sec.append(head);
  if (urls.length) {
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('urlLabel'), t('hostLabel'), t('riskLabel'), t('reasonsLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    urls.slice(0, 60).forEach((u, i) => {
      const tr = el('tr');
      if (u.verdict === 'malicious') tr.className = 'rowbad'; else if (u.verdict === 'suspicious') tr.className = 'rowwarn';
      tr.append(el('td', '', String(i + 1)),
        el('td', '', (u.url || '').length > 80 ? u.url.slice(0, 80) + '…' : u.url),
        el('td', '', u.host || '—'),
        el('td', '', `${u.risk ?? '—'}% — ${assessText(u.verdict)}`),
        el('td', '', (u.reasons || []).join('; ') || '—'));
      table.append(tr);
    });
    sec.append(table);
  }
  out.append(sec);
}

function renderEnrichment(out, r) {
  const dnsEntries = Object.entries(r?.dns || {});
  if (dnsEntries.length) {
    out.append(el('h4', '', t('senderDns')), el('p', 'hint', t('dnsExplain')));
    for (const [domain, d] of dnsEntries) {
      const s = el('section', 'toolcard');
      const head = el('div', 'toolhead');
      head.append(el('h5', '', domain));
      if (d.assessment) head.append(badge(assessText(d.assessment.verdict), d.assessment.verdict === 'authentic' ? 'ok' : d.assessment.verdict === 'spoofed' ? 'bad' : 'warn'));
      s.append(head);
      const dl = el('dl', 'kv');
      const spf = d.auth?.spf, dmarc = d.auth?.dmarc;
      addKV(dl, 'SPF', spf?.found ? `${spf.raw || (spf.records || []).join(' / ')}${spf.all ? ' · all=' + spf.all : ''}` : t('notFoundLabel'));
      addKV(dl, 'DMARC', dmarc?.found ? `${dmarc.raw || 'found'}${dmarc.policy ? ' · p=' + dmarc.policy : ''}` : t('notFoundLabel'));
      addKV(dl, 'MX', (d.records?.mx || []).map(x => `${x.priority} ${x.exchange}`).join(', ') || t('noRecords'));
      if (d.assessment?.reasons?.length) addKV(dl, t('assessLabel'), d.assessment.reasons.join('; '));
      if (d.errors?.length) addKV(dl, 'Warnings', d.errors.map(e => `${e.code}: ${e.message}`).join('; '));
      s.append(dl);
      out.append(s);
    }
  }
  const ipEntries = r?.ipInfo || [];
  if (ipEntries.length) {
    out.append(el('h4', '', t('ipIntelligence')), el('p', 'hint', t('ipExplain')));
    const located = ipEntries.filter(x => x.geo?.location?.latitude != null && x.geo.location.longitude != null);
    if (located.length) {
      const img = el('img', 'ipmap');
      img.src = '/api/map?ips=' + encodeURIComponent(located.map(x => x.ip).join(','));
      img.alt = t('mapTitle');
      img.loading = 'lazy';
      out.append(img);
    }
    const locatedPct = ipEntries.length ? Math.round(located.length / ipEntries.length * 100) : 0;
    out.append(el('p', 'summary', `${t('locatedSummary')}: ${located.length}/${ipEntries.length} (${locatedPct}%)`));
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', 'IP', t('coordinatesLabel'), t('countryLabel'), t('cityLabel'), t('asnLabel'), t('organizationLabel'), t('ptrLabel'), t('serverTypeLabel'), t('assessLabel'), t('confidenceLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    ipEntries.forEach((x, n) => {
      const loc = x.geo?.location;
      const tr = el('tr');
      const conf = x.confidence != null ? Math.round(Number(x.confidence)) : null;
      tr.append(
        el('td', '', String(n + 1)), el('td', '', x.ip),
        el('td', '', loc?.latitude != null ? `${loc.latitude}, ${loc.longitude}` : '—'),
        el('td', '', x.geo?.countryIso ? `${x.geo.country || ''} (${x.geo.countryIso})` : (x.geo?.country || '—')),
        el('td', '', x.geo?.city || '—'), el('td', '', x.geo?.asn ? `AS${x.geo.asn}` : '—'),
        el('td', '', x.geo?.organization || '—'), el('td', '', (x.ptr || []).join(', ') || '—'),
        el('td', '', x.server ? `${serverText(x.server.key)}${x.server.evidence ? ' — ' + x.server.evidence : ''}` : '—'),
        el('td', '', x.assessment ? `${assessText(x.assessment.verdict)}${x.assessment.reasons?.length ? ' — ' + x.assessment.reasons.join('; ') : ''}` : '—'),
        el('td', conf == null ? '' : (conf >= 70 ? 'confhi' : conf >= 40 ? 'confmed' : 'conflo'), conf == null ? '—' : conf + '%')
      );
      table.append(tr);
    });
    out.append(table, el('p', 'hint', t('approxLabel')));
  }
}

// ---------------------------------------------------------------------------
// URLs by target
// ---------------------------------------------------------------------------
function localGroups(r) {
  const msgs = r.messages || [];
  const groups = {};
  for (const u of (r.urls || [])) {
    const m = u.m;
    const key = Number.isInteger(m) ? 'm' + m : 'file';
    if (!groups[key]) {
      const msg = Number.isInteger(m) && m >= 0 && m < msgs.length ? msgs[m] : {};
      groups[key] = { key, index: Number.isInteger(m) ? m : null, subject: msg.subject || u.target || t('fileLevel'), from: msg.from || '', urls: [] };
    }
    groups[key].urls.push(u);
  }
  return Object.values(groups);
}

async function renderUrls(out, r) {
  const cid = r.custody.caseId;
  let groups = localGroups(r);
  try {
    const resp = await api(`/api/case/${cid}/urls?lang=${lang}`);
    if (resp.ok) {
      const j = await resp.json();
      if (Array.isArray(j.groups)) groups = j.groups;
    }
  } catch {}
  out.append(el('h4', '', `${t('urlsByTarget')} (${groups.reduce((n, g) => n + (g.urls?.length || 0), 0)})`));
  if (!groups.length) {
    out.append(el('p', 'hint', '—'));
  }
  for (const g of groups) {
    const sec = el('section', 'toolcard');
    const head = el('div', 'toolhead');
    head.append(el('h5', '', g.subject || t('fileLevel')));
    if (g.from) head.append(el('span', 'summary', g.from));
    head.append(badge(`${g.urls.length} ${t('groupTotal')}`, 'warn'));
    sec.append(head);
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', t('urlLabel'), t('hostLabel'), t('riskLabel'), t('reasonsLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    g.urls.forEach((u, i) => {
      const tr = el('tr');
      if (u.verdict === 'malicious') tr.className = 'rowbad'; else if (u.verdict === 'suspicious') tr.className = 'rowwarn';
      tr.append(el('td', '', String(i + 1)),
        el('td', '', (u.url || '').length > 90 ? u.url.slice(0, 90) + '…' : u.url),
        el('td', '', u.host || '—'),
        el('td', '', `${u.risk ?? '—'}% — ${assessText(u.verdict)}`),
        el('td', '', (u.reasons || []).join('; ') || '—'));
      table.append(tr);
    });
    sec.append(table);
    out.append(sec);
  }
  if (r.urlImports?.length) {
    out.append(el('h4', '', 'Imports'));
    const table = el('table', 'datatable');
    const htr = el('tr');
    ['#', 'ID', t('historyWhen'), 'Source', 'Count', t('importMerged')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    r.urlImports.forEach((x, i) => {
      const tr = el('tr');
      tr.append(el('td', '', String(i + 1)), el('td', '', x.id), el('td', '', fmtDate(x.ts)),
        el('td', '', (x.summary?.sources || x.source || '') + ''), el('td', '', String(x.count || '')), el('td', '', String(x.merged ?? '')));
      table.append(tr);
    });
    out.append(table);
  }
}

async function renderCasePane() {
  const out = $('caseOut');
  if (!out) return;
  const cid = currentCase();
  if (!cid) { out.textContent = t('noResult'); return; }
  out.textContent = '...';
  const kinds = ['meta', 'inventory', 'custody', 'timeline', 'assessments', 'responses', 'screenshots', 'team'];
  out.textContent = '';
  for (const k of kinds) {
    try {
      const r = await fetch(`/api/case/${cid}/forensic/${k}`, { credentials: 'same-origin' });
      const j = await r.json();
      const box = el('details');
      box.append(el('summary', '', k));
      const data = j.data;
      const rows = Array.isArray(data) ? data : (data && Object.keys(data).length ? [data] : []);
      if (!rows.length) { box.append(el('p', 'hint', t('noResult'))); }
      else {
        const keys = Array.from(new Set(rows.flatMap(x => Object.keys(x)))).filter(x => x !== 'uid');
        const table = el('table');
        const thead = el('thead');
        const hrow = el('tr');
        keys.forEach(key => hrow.append(el('th', '', key)));
        thead.append(hrow); table.append(thead);
        const tbody = el('tbody');
        rows.forEach(row => {
          const tr = el('tr');
          keys.forEach(key => tr.append(el('td', '', String(row[key] ?? ''))));
          tbody.append(tr);
        });
        table.append(tbody); box.append(table);
      }
      out.append(box);
    } catch (e) { out.append(el('p', 'hint', k + ': ' + e.message)); }
  }
}

async function renderGraph(out, r) {
  const cid = r.custody.caseId;
  const vi = lang === 'vi';
  out.append(el('h4', '', t('resGraph')));
  const img = el('img', 'graphimg');
  img.alt = t('resGraph');
  img.src = `/api/case/${cid}/graph.svg?lang=${lang}&t=${Date.now()}`;
  out.append(img);
  const s = r.graph || {};
  out.append(el('p', 'summary', `${s.nodes || 0} nodes / ${s.edges || 0} edges`));

  const rel = r.relations || {};
  const items = rel.relations || [];
  out.append(el('h4', '', vi
    ? `Quan hệ giữa các thư (${rel.count || items.length})`
    : `Message relations (${rel.count || items.length})`));
  const filt = el('select');
  const kinds = ['ALL', ...Array.from(new Set(items.map(x => x.kind)))];
  for (const k of kinds) filt.append(el('option', '', k === 'ALL' ? (vi ? 'Tất cả' : 'All') : k));
  const ul = el('ul', 'att');
  const draw = () => {
    ul.textContent = '';
    for (const x of items.filter(i => filt.value === 'ALL' || i.kind === filt.value)) {
      const li = el('li', '', `#${x.src_msg + 1} -> #${x.dst_msg + 1} - ${x.kind}`);
      li.title = `${x.evidence || ''} [${x.confidence || 'observed'}]`;
      ul.append(li);
    }
  };
  filt.onchange = draw;
  out.append(filt, ul);
  draw();
  const a = el('a', '', vi ? 'Tai CSV quan he' : 'Download relations CSV');
  a.href = `/api/case/${cid}/relations?csv_out=1`;
  out.append(a);
}

// ---------------------------------------------------------------------------
// report / URL import actions
// ---------------------------------------------------------------------------
async function reportHtml() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}?lang=${lang}`);
    await saveBlob(blob, `${cid}-report-${lang}.html`, 'text/html');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportPdf() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}.pdf?lang=${lang}`);
    await saveBlob(blob, `${cid}-report-${lang}.pdf`, 'application/pdf');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportCsv() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/report/${cid}.csv?lang=${lang}&kind=summary`);
    await saveBlob(blob, `${cid}-report-${lang}.csv`, 'text/csv');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function reportBundle() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const files = [];
    files.push({ name: `${cid}-report-${lang}.pdf`, mime: 'application/pdf', blob: await blobFrom(`/api/report/${cid}.pdf?lang=${lang}`) });
    files.push({ name: `${cid}-urls-${lang}.csv`, mime: 'text/csv', blob: await blobFrom(`/api/case/${cid}/urls.csv?lang=${lang}`) });
    files.push({ name: `${cid}-report-${lang}.csv`, mime: 'text/csv', blob: await blobFrom(`/api/report/${cid}.csv?lang=${lang}&kind=summary`) });
    files.push({ name: `${cid}-report-${lang}.html`, mime: 'text/html', blob: await blobFrom(`/api/report/${cid}?lang=${lang}`) });
    const svg = await blobFrom(`/api/case/${cid}/graph.svg?lang=${lang}`);
    files.push({ name: `${cid}-graph.svg`, mime: 'image/svg+xml', blob: svg });
    await saveMany(files);
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('exportFail') + e.message; }
}
async function verifySignature() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const r = await api(`/api/report/${cid}/verify`);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    $('resultMsg').textContent = j.match ? t('verifyOk') : t('verifyBad');
    $('resultMsg').className = j.match ? 'ok' : 'bad';
  } catch (e) { $('resultMsg').textContent = t('reportFailed') + e.message; }
}
async function exportUrlCsv() {
  const cid = currentCase();
  if (!cid) return;
  try {
    const blob = await blobFrom(`/api/case/${cid}/urls.csv?lang=${lang}`);
    await saveBlob(blob, `${cid}-urls-${lang}.csv`, 'text/csv');
    $('resultMsg').textContent = t('exportOk');
  } catch (e) { $('resultMsg').textContent = t('exportFail') + e.message; }
}
async function importUrls(fileList) {
  const cid = currentCase();
  const files = Array.from(fileList || []);
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append('files', f, f.name);
  if (cid) fd.append('case_id', cid);
  try {
    const r = await api('/api/urls/import', { method: 'POST', body: fd });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    $('resultMsg').textContent = `${t('importOk')} ${j.summary?.total ?? 0} URL · ${j.merged ?? 0} ${t('importMerged')}`;
    $('resultMsg').className = 'ok';
    if (cid) {
      const resp = await api(`/api/report/${cid}?format=json`);
      if (resp.ok) {
        lastResults[currentIdx] = await resp.json();
        resTab = 'urls';
        renderCurrentResult();
      }
    }
  } catch (e) {
    $('resultMsg').textContent = t('importFail') + ' ' + e.message;
    $('resultMsg').className = 'bad';
  }
}
// MailSleuth frontend — part 3: dashboard, history, DNS/IP, local AI, admin, logs, init.
Object.assign(I18N.en, {
  authservLabel: 'Authentication server', authHeaderLabel: 'Authentication-Results header',
  geoLabel: 'Geolocation', geoUnavailable: 'Geolocation unavailable.', regionLabel: 'Region', accuracyLabel: 'Accuracy',
  timezoneLabel: 'Timezone', dnsSourceNative: 'Native DNS', resolverLabel: 'Resolvers', authRecords: 'Authentication records',
  warningsLabel: 'Warnings', durationLabel: 'Duration', keyUsed: 'Key used', keyNotUsed: 'No key', informationLabel: 'Information',
  transcriptLabel: 'Transcript', rawLabel: 'Raw', reportingNameServer: 'Reporting nameserver'
});
Object.assign(I18N.vi, {
  authservLabel: 'Máy chủ xác thực', authHeaderLabel: 'Header Authentication-Results',
  geoLabel: 'Định vị', geoUnavailable: 'Không có dữ liệu định vị.', regionLabel: 'Vùng', accuracyLabel: 'Độ chính xác',
  timezoneLabel: 'Múi giờ', dnsSourceNative: 'DNS gốc', resolverLabel: 'Bộ phân giải', authRecords: 'Bản ghi xác thực',
  warningsLabel: 'Cảnh báo', durationLabel: 'Thời lượng', keyUsed: 'Có dùng key', keyNotUsed: 'Không dùng key', informationLabel: 'Thông tin',
  transcriptLabel: 'Bản ghi', rawLabel: 'Dữ liệu gốc', reportingNameServer: 'Nameserver báo cáo'
});

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------
async function loadDashboard() {
  try {
    const r = await api('/api/cases?limit=500');
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return;
    const cases = Array.isArray(j.cases) ? j.cases : [];
    let msgs = 0, bad = 0, warn = 0, ok = 0;
    for (const c of cases) {
      msgs += Number(c.count) || 0;
      if (c.verdict === 'malicious_or_phishing') bad++;
      else if (c.verdict === 'suspicious') warn++;
      else if (c.verdict === 'clean') ok++;
    }
    if ($('dashCases')) $('dashCases').textContent = String(cases.length);
    if ($('dashMessages')) $('dashMessages').textContent = String(msgs);
    if ($('dashBad')) $('dashBad').textContent = String(bad);
    if ($('dashWarn')) $('dashWarn').textContent = String(warn);
    if ($('dashOk')) $('dashOk').textContent = String(ok);
    let findings = 0, relations = 0;
    for (const r of lastResults || []) {
      findings += (r.findings || []).length;
      relations += ((r.relations || {}).count || 0);
    }
    if ($('dashFindings')) $('dashFindings').textContent = String(findings);
    if ($('dashRelations')) $('dashRelations').textContent = String(relations);
  } catch {}
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------
function renderHistory(cases) {
  const out = $('histOut');
  if (!out) return;
  out.textContent = '';
  if (!cases.length) { out.append(el('p', 'hint', t('historyEmpty'))); return; }
  const table = el('table', 'datatable historytable');
  const htr = el('tr');
  [t('historyWhen'), t('historyFile'), t('historyAnalyst'), t('historyMessages'), t('historyVerdict'), t('historyScore'), ''].forEach(x => htr.append(el('th', '', x)));
  table.append(htr);
  for (const c of cases) {
    const tr = el('tr');
    tr.append(el('td', '', fmtDate(c.ts)), el('td', '', c.file || '—'), el('td', '', c.user || '—'),
      el('td', '', String(c.count ?? '—')), el('td', '', verdictText(c.verdict) || '—'), el('td', '', String(c.score ?? '—')));
    const td = el('td');
    const b = el('button', 'ghost', t('historyOpen'));
    b.type = 'button';
    b.onclick = () => openHistoryCase(c.id);
    td.append(b);
    tr.append(td);
    table.append(tr);
  }
  out.append(table);
}

async function loadHistory(force = false) {
  if (histLoading || (histLoaded && !force)) return;
  histLoading = true;
  $('histMsg').textContent = '';
  try {
    const r = await api('/api/cases?limit=100&q=' + encodeURIComponent($('histQ').value.trim()));
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!r.ok) { $('histMsg').textContent = t('logsLoadFailed'); return; }
    histCases = Array.isArray(j.cases) ? j.cases : [];
    histLoaded = true;
    renderHistory(histCases);
  } catch (e) {
    $('histMsg').textContent = t('errNetwork') + e.message;
  } finally { histLoading = false; }
}

async function openHistoryCase(id) {
  $('histMsg').textContent = '';
  try {
    const r = await api(`/api/report/${id}?format=json`);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(apiCode(j) || r.status);
    if (!j.custody) j.custody = { caseId: id, original: j.caseMeta?.file || '', sha256: j.caseMeta?.sha256 || '', utc: j.caseMeta?.ts || '' };
    lastResults = [j];
    currentIdx = 0;
    resTab = 'overview';
    last = j;
    renderCurrentResult();
    switchTab('tabResults');
  } catch (e) {
    $('histMsg').textContent = t('reportFailed') + e.message;
  }
}

// ---------------------------------------------------------------------------
// DNS / IP
// ---------------------------------------------------------------------------
function card(title) {
  const s = el('section', 'toolcard');
  if (title) s.append(el('h4', '', title));
  return s;
}
function listCard(title, values) {
  if (!values?.length) return null;
  const s = card(title);
  const ul = el('ul');
  values.forEach(v => ul.append(el('li', '', typeof v === 'object' ? JSON.stringify(v) : v)));
  s.append(ul);
  return s;
}
function geoCard(geo, ptrNames, status, confidence) {
  const s = card(t('geoLabel'));
  if (!geo) {
    s.append(el('p', 'hint', t('geoUnavailable')));
    if (status) s.append(el('p', 'summary', `GeoLite2: City=${status.city ? 'yes' : 'no'}, ASN=${status.asn ? 'yes' : 'no'}, Country=${status.country ? 'yes' : 'no'}`));
    return s;
  }
  const dl = el('dl', 'kv');
  addKV(dl, t('countryLabel'), geo.countryIso ? `${geo.country || ''} (${geo.countryIso})` : geo.country);
  addKV(dl, t('cityLabel'), geo.city);
  addKV(dl, t('regionLabel'), (geo.subdivisions || []).join(', '));
  addKV(dl, t('asnLabel'), geo.asn);
  addKV(dl, t('organizationLabel'), geo.organization);
  if (geo.location?.latitude != null) {
    addKV(dl, t('coordinatesLabel'), `${geo.location.latitude}, ${geo.location.longitude}`);
    addKV(dl, t('accuracyLabel'), geo.location.accuracyRadiusKm != null ? `${geo.location.accuracyRadiusKm} km` : null);
    addKV(dl, t('timezoneLabel'), geo.location.timeZone);
  }
  addKV(dl, t('ptrLabel'), (ptrNames || []).join(', '));
  if (confidence != null) addKV(dl, t('confidenceLabel'), Math.round(Number(confidence)) + '%');
  s.append(dl, el('p', 'hint', t('approxLabel')));
  return s;
}
function renderNativeDNS(d) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge(t('dnsSourceNative'), 'ok'), el('strong', '', `${d.domain} · ${d.type}`));
  box.append(head);
  if (d.resolver?.length) box.append(el('p', 'summary', `${t('resolverLabel')}: ${d.resolver.join(', ')}`));
  const r = d.records || {};
  for (const key of ['a', 'aaaa', 'ns', 'cname', 'ptr']) {
    const c = listCard(key.toUpperCase(), r[key]);
    if (c) box.append(c);
  }
  if (r.mx?.length) {
    const s = card('MX');
    const table = el('table', 'datatable');
    const tr = el('tr');
    tr.append(el('th', '', '#'), el('th', '', 'MX'));
    table.append(tr);
    r.mx.forEach(x => { const row = el('tr'); row.append(el('td', '', x.priority), el('td', '', x.exchange)); table.append(row); });
    s.append(table); box.append(s);
  }
  if (r.txt?.length) {
    const s = card('TXT');
    const ul = el('ul');
    r.txt.forEach(x => ul.append(el('li', '', x)));
    s.append(ul); box.append(s);
  }
  if (r.soa) {
    const s = card('SOA');
    const dl = el('dl', 'kv');
    for (const [k, v] of Object.entries(r.soa)) addKV(dl, k, typeof v === 'object' ? JSON.stringify(v) : v);
    s.append(dl); box.append(s);
  }
  if (d.auth) {
    const s = card(t('authRecords'));
    for (const key of ['spf', 'dmarc', 'dkim']) {
      const a = d.auth[key] || {};
      const row = el('div', 'authrow');
      row.append(badge(key.toUpperCase(), a.found ? 'ok' : 'warn'));
      if (a.found) {
        if (key === 'spf') row.append(el('span', '', `${a.raw || ''}${a.all ? ' · all=' + a.all : ''}${a.includes?.length ? ' · include=' + a.includes.join(', ') : ''}`));
        else if (key === 'dmarc') row.append(el('span', '', `${a.raw || ''}${a.policy ? ' · p=' + a.policy : ''}`));
        else row.append(el('span', '', `${a.raw || ''}${a.selector ? ' · s=' + a.selector : ''}${a.hasPublicKey ? ' · p=yes' : ' · p=no'}`));
      } else row.append(el('span', 'summary', t('notFoundLabel')));
      s.append(row);
    }
    box.append(s);
  }
  if (d.geo) box.append(geoCard(d.geo, [], d.geoStatus));
  if (d.errors?.length) {
    const s = card(t('warningsLabel'));
    const ul = el('ul');
    d.errors.forEach(e => ul.append(el('li', '', `${e.type || ''} ${e.code || ''}: ${e.message || ''}`)));
    s.append(ul); box.append(s);
  }
  return box;
}
function paintDns(_source, data) {
  $('dnsOut').textContent = '';
  $('dnsOut').append(renderNativeDNS(data));
}
function paintIp(j) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge('IP', 'ok'), el('strong', '', j.ip), el('span', 'summary', fmtDate(j.at)));
  box.append(head, geoCard(j.geo, j.ptr?.names, j.geoStatus, j.confidence));
  if (j.ptr?.errors?.length) {
    const s = card(t('warningsLabel'));
    const ul = el('ul');
    j.ptr.errors.forEach(e => ul.append(el('li', '', `${e.code}: ${e.message}`)));
    s.append(ul); box.append(s);
  }
  $('ipOut').textContent = '';
  $('ipOut').append(box);
}
async function lookupDns() {
  $('dnsMsg').textContent = '';
  $('dnsOut').textContent = '';
  const domain = $('dnsDomain').value.trim();
  if (!domain) return;
  const btn = $('dnsGo');
  btn.disabled = true;
  try {
    const body = { domain, type: $('dnsType').value };
    if (body.type === 'dkim') body.selector = $('dnsSelector').value.trim();
    const r = await api('/api/dns', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('dnsMsg').textContent = errText(apiCode(j) || r.status); return; }
    lastDns = { source: 'native', data: j };
    paintDns('native', j);
  } catch (e) { $('dnsMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}
async function lookupIp() {
  $('ipMsg').textContent = '';
  $('ipOut').textContent = '';
  const ip = $('ipAddr').value.trim();
  if (!ip) return;
  const btn = $('ipGo');
  btn.disabled = true;
  try {
    const r = await api('/api/ip', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('ipMsg').textContent = errText(apiCode(j) || r.status); return; }
    lastIp = j;
    paintIp(j);
  } catch (e) { $('ipMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}

// ---------------------------------------------------------------------------
// local AI settings
// ---------------------------------------------------------------------------
async function loadTrustStatus() {
  try {
    const r = await api('/api/settings/llm');
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('trustState').textContent = t('trustLoadFailed'); return; }
    $('llmBase').value = j.base || '';
    $('llmModel').value = j.model || '';
    $('llmKey').value = j.hasKey ? '••••••••' : '';
    $('llmEnabled').checked = !!j.enabled;
    $('trustState').textContent = `${t('trustStateOn')}: ${j.enabled ? t('trustEnabled') : t('trustDisabled')} · ${j.base || ''} · ${j.local ? 'local' : 'remote'}`;
  } catch { $('trustState').textContent = t('trustLoadFailed'); }
}
async function saveTrust() {
  $('trustMsg').textContent = t('saving');
  const body = {
    base: $('llmBase').value.trim(),
    model: $('llmModel').value.trim(),
    enabled: $('llmEnabled').checked
  };
  const k = $('llmKey').value.trim();
  if (k && k !== '••••••••') body.key = k;
  try {
    const r = await api('/api/settings/llm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('trustMsg').textContent = errText(apiCode(j) || r.status); return; }
    $('trustMsg').textContent = t('trustSaved');
    await loadTrustStatus();
  } catch (e) { $('trustMsg').textContent = t('errNetwork') + e.message; }
}
async function testTrust() {
  $('trustMsg').textContent = t('saving');
  try {
    const r = await api('/api/settings/llm/test', { method: 'POST' });
    const j = await r.json().catch(() => ({}));
    $('trustMsg').textContent = j.ok ? t('trustTestOk') : t('trustTestFail') + ' ' + (j.error || '');
  } catch (e) { $('trustMsg').textContent = t('trustTestFail') + ' ' + e.message; }
}
async function clearTrustKey() {
  try {
    const r = await api('/api/settings/llm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: '' }) });
    if (r.ok) { $('llmKey').value = ''; $('trustMsg').textContent = t('trustRemoved'); }
  } catch (e) { $('trustMsg').textContent = t('errNetwork') + e.message; }
}

// ---------------------------------------------------------------------------
// administration
// ---------------------------------------------------------------------------
async function loadAdmin(force = true) {
  if (role !== 'admin') return;
  if (adminLoaded && !force) return;
  $('adminMsg').textContent = t('adminMsg');
  try {
    const [sr, ur] = await Promise.all([api('/api/admin/stats'), api('/api/admin/users')]);
    const sj = await sr.json().catch(() => ({}));
    const uj = await ur.json().catch(() => ({}));
    if (sr.status === 401 || ur.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!sr.ok || !ur.ok) { $('adminMsg').textContent = t('adminLoadFailed'); return; }
    adminUsers = Array.isArray(uj.users) ? uj.users : [];
    adminLoaded = true;
    $('adminMsg').textContent = '';
    renderAdminStats(sj);
    renderAdminUsers();
  } catch (e) { $('adminMsg').textContent = t('errNetwork') + e.message; }
}
function renderAdminStats(s) {
  const box = $('adminStats');
  if (!box) return;
  box.textContent = '';
  for (const [label, v] of [[t('adminUsers'), s.users], [t('roleAdmin'), s.admins], [t('dashCases'), s.cases],
    ['URL imports', s.urlImports], ['Evidence bytes', fSize(s.evidenceBytes || 0)], ['Map', s.map], ['Offline', s.offline ? 'yes' : 'no']]) {
    box.append(el('span', 'statLabel', label), el('b', 'statVal', String(v ?? '—')));
  }
}
function renderAdminUsers() {
  const box = $('adminUsers');
  if (!box) return;
  box.textContent = '';
  if (!adminUsers.length) { box.append(el('p', 'hint', t('adminUsersEmpty'))); return; }
  const table = el('table', 'datatable');
  const htr = el('tr');
  [t('adminUid'), t('username'), t('profileRole'), t('adminPhone'), t('adminStatus'), t('adminLastLogin'), t('adminActions')].forEach(x => htr.append(el('th', '', x)));
  table.append(htr);
  for (const u of adminUsers) {
    const self = u.uid === uid;
    const tr = el('tr');
    tr.append(el('td', 'hashcell', u.uid || ''), el('td', '', u.user || ''), el('td', '', u.role || ''),
      el('td', '', u.phone || '—'), el('td', '', u.disabled ? 'disabled' : 'active'),
      el('td', '', fmtDate(u.lastLogin)));
    const td = el('td', 'actioncell');
    const reset = el('button', 'ghost', t('adminReset'));
    reset.type = 'button';
    reset.onclick = async () => {
      const pw = prompt(t('adminResetPrompt'));
      if (!pw) return;
      const r = await api(`/api/admin/users/${u.uid}/reset`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pass: pw }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? t('adminResetOk') + (j.recovery ? ' ' + j.recovery : '') : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const dis = el('button', 'ghost', u.disabled ? t('adminEnable') : t('adminDisable'));
    dis.type = 'button';
    dis.disabled = self;
    dis.title = self ? t('adminSelf') : '';
    dis.onclick = async () => {
      const r = await api(`/api/admin/users/${u.uid}/disable`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ disabled: !u.disabled }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? (u.disabled ? t('adminEnabledOk') : t('adminDisabledOk')) : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const roleBtn = el('button', 'ghost', t('adminRole'));
    roleBtn.type = 'button';
    roleBtn.disabled = self;
    roleBtn.onclick = async () => {
      const nr = u.role === 'admin' ? 'analyst' : 'admin';
      const r = await api(`/api/admin/users/${u.uid}/role`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: nr }) });
      const j = await r.json().catch(() => ({}));
      $('adminMsg').textContent = r.ok ? t('adminRoleOk') : errText(apiCode(j) || r.status);
      $('adminMsg').className = r.ok ? 'ok' : 'bad';
      await loadAdmin(true);
    };
    const ren = el('button', 'ghost', t('adminRename'));
    ren.type = 'button';
    ren.onclick = async () => {
      const r = await api(`/api/admin/users/${u.uid}/rename-token`, { method: 'POST' });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        $('adminMsg').textContent = `${t('adminRenameOk')} ${j.token} (${fmtDate(j.expires)})`;
        $('adminMsg').className = 'ok';
        try { await navigator.clipboard.writeText(j.token); } catch {}
      } else {
        $('adminMsg').textContent = errText(apiCode(j) || r.status);
        $('adminMsg').className = 'bad';
      }
    };
    td.append(reset, dis, roleBtn, ren);
    tr.append(td);
    table.append(tr);
  }
  box.append(table);
}
async function createAccount() {
  $('acMsg').textContent = '';
  $('acKey').hidden = true;
  const body = {
    user: $('acUser').value.trim(),
    phone: $('acPhone').value.trim(),
    pass: $('acPass').value,
    role: $('acRole').value,
    cccd: $('acCccd').value.trim()
  };
  if (body.role === 'admin' && !body.cccd) { $('acMsg').textContent = t('adminNoCccd'); return; }
  const btn = $('acGo');
  btn.disabled = true;
  try {
    const r = await api('/api/admin/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { $('acMsg').textContent = errText(apiCode(j) || r.status); return; }
    const key = j.key || j.recovery || '';
    $('acMsg').textContent = t('adminCreated');
    $('acMsg').className = 'ok';
    $('acKey').textContent = `${t('adminKeyOnce')}: ${key}`;
    $('acKey').hidden = false;
    $('acUser').value = ''; $('acPhone').value = ''; $('acPass').value = ''; $('acCccd').value = '';
    await loadAdmin(true);
  } catch (e) { $('acMsg').textContent = t('errNetwork') + e.message; }
  finally { btn.disabled = false; }
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------
function renderLogs() {
  const logsOut = $('logsOut'), sessionsOut = $('sessionsOut');
  if (!logsOut || !sessionsOut) return;
  logsOut.textContent = ''; sessionsOut.textContent = '';
  if (!logsData.length) logsOut.append(el('p', 'hint', t('logsEmpty')));
  else {
    const table = el('table', 'datatable');
    const htr = el('tr');
    [t('historyWhen'), t('sessionUser'), 'Action', 'Detail', t('durationMs')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const x of logsData) {
      const tr = el('tr');
      tr.append(el('td', '', fmtDate(x.ts)), el('td', '', x.user || '—'), el('td', '', x.action || ''), el('td', '', x.detail || ''), el('td', '', x.ms ?? '—'));
      table.append(tr);
    }
    logsOut.append(table);
  }
  if (!sessionsData.length) sessionsOut.append(el('p', 'hint', t('sessionsEmpty')));
  else {
    const table = el('table', 'datatable');
    const htr = el('tr');
    [t('historyWhen'), t('sessionUser'), t('sessionRole'), t('reasonLabel'), t('durationMs'), t('signatureLabel'), t('previousLabel')].forEach(x => htr.append(el('th', '', x)));
    table.append(htr);
    for (const x of sessionsData) {
      const tr = el('tr');
      tr.append(el('td', '', fmtDate(x.ended)), el('td', '', x.user || '—'), el('td', '', x.role || '—'),
        el('td', '', x.reason || ''), el('td', '', x.started && x.ended ? x.ended - x.started : '—'),
        el('td', 'hashcell', x.sha256 || ''), el('td', 'hashcell', x.prev_hash || '—'));
      table.append(tr);
    }
    sessionsOut.append(table);
  }
}
async function loadLogs(force = false) {
  if (logsLoading || (logsLoaded && !force)) return;
  logsLoading = true;
  $('logsMsg').textContent = '';
  try {
    const [a, b] = await Promise.all([api('/api/admin/logs'), api('/api/admin/sessions')]);
    const ja = await a.json().catch(() => []), jb = await b.json().catch(() => []);
    if (a.status === 401 || b.status === 401) { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!a.ok || !b.ok) { $('logsMsg').textContent = t('logsLoadFailed'); return; }
    logsData = Array.isArray(ja) ? ja : [];
    sessionsData = Array.isArray(jb) ? jb : [];
    logsLoaded = true;
    renderLogs();
  } catch (e) {
    $('logsMsg').textContent = t('errNetwork') + e.message;
  } finally { logsLoading = false; }
}

// ---------------------------------------------------------------------------
// language
// ---------------------------------------------------------------------------
function applyLang() {
  document.documentElement.lang = lang;
  document.title = t('title');
  document.querySelectorAll('[data-i18n]').forEach(x => { x.textContent = t(x.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(x => { x.placeholder = t(x.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-aria]').forEach(x => { x.setAttribute('aria-label', t(x.dataset.i18nAria)); });
  document.querySelectorAll('[data-i18n-g]').forEach(x => { try { x.label = t(x.dataset.i18nG); } catch {} });
  if ($('lang')) $('lang').value = lang;
  const flag = $('langFlag');
  if (flag) flag.className = 'flag-icon ' + lang;
  applyTheme(document.documentElement.dataset.theme === 'dark');
  renderWho();
  if (lastDns) paintDns(lastDns.source, lastDns.data);
  if (lastIp) paintIp(lastIp);
  if (profileData) renderProfile();
  if (sessionExpires) renderSessionTimer();
  if (logsLoaded) renderLogs();
  if (histLoaded) renderHistory(histCases);
  if (adminLoaded) { renderAdminUsers(); loadAdmin(false); }
  renderPick();
  if (lastResults.length) renderCurrentResult();
}

// ---------------------------------------------------------------------------
// file picking / drag & drop
// ---------------------------------------------------------------------------
$('f').onchange = () => { addFiles($('f').files); $('f').value = ''; };
$('fdir').onchange = () => { addFiles($('fdir').files); $('fdir').value = ''; };
$('fclear').onclick = () => { picked = []; pfRejected = []; renderPick(); };
if ($('fbtn')) $('fbtn').onclick = () => $('f').click();
if ($('fdirBtn')) $('fdirBtn').onclick = () => $('fdir').click();

async function entryFiles(entry, out, depth = 0) {
  if (!entry || depth > 8 || out.length > 2000) return;
  if (entry.isFile) {
    await new Promise(r => entry.file(f => { out.push({ f, path: (entry.fullPath || '/' + f.name).replace(/^\//, '') }); r(); }, r));
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise(r => reader.readEntries(r, r));
      for (const e of batch) await entryFiles(e, out, depth + 1);
    } while (batch.length);
  }
}
{
  const dz = $('drop');
  const over = e => { e.preventDefault(); dz.classList.add('over'); };
  dz.addEventListener('dragover', over);
  dz.addEventListener('dragenter', over);
  dz.addEventListener('dragleave', e => { if (!dz.contains(e.relatedTarget)) dz.classList.remove('over'); });
  dz.addEventListener('drop', async e => {
    e.preventDefault();
    dz.classList.remove('over');
    const dt = e.dataTransfer;
    if (!dt) return;
    const entries = Array.from(dt.items || []).map(i => i.webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) {
      const out = [];
      for (const en of entries) await entryFiles(en, out);
      if (out.length) { addItems(out); return; }
    }
    addFiles(dt.files);
  });
}

// URL import drop zone on the results pane
{
  const pane = $('paneResults');
  pane.addEventListener('dragover', e => { e.preventDefault(); pane.classList.add('over'); });
  pane.addEventListener('dragleave', () => pane.classList.remove('over'));
  pane.addEventListener('drop', e => {
    e.preventDefault();
    pane.classList.remove('over');
    const files = Array.from(e.dataTransfer?.files || []).filter(f => /\.(csv|json|xml|txt)$/i.test(f.name));
    if (files.length) importUrls(files);
  });
}

// ---------------------------------------------------------------------------
// run controls
// ---------------------------------------------------------------------------
$('run').onclick = startAnalysis;
$('btnPause').onclick = () => {
  if (!job || job.stopped || job.cancelled) return;
  job.paused = !job.paused;
  setRunState(t(job.paused ? 'runPausing' : 'runResuming'), job.paused ? 'warn' : '');
  syncRunButtons();
};
$('btnStop').onclick = () => {
  if (!job || job.stopped || job.cancelled) return;
  job.stopped = true;
  job.paused = false;
  setRunState(t('runStopping'), 'warn');
  try { job.ac?.abort(); } catch {}
  syncRunButtons();
};
$('btnCancel').onclick = () => {
  if (!job || job.cancelled) return;
  job.cancelled = true;
  job.paused = false;
  setRunState(t('runCancelled'), 'bad');
  try { job.ac?.abort(); } catch {}
  syncRunButtons();
};

// ---------------------------------------------------------------------------
// report / URL buttons
// ---------------------------------------------------------------------------
$('repHtml').onclick = reportHtml;
$('repPdf').onclick = reportPdf;
$('repCsv').onclick = reportCsv;
$('repBundle').onclick = reportBundle;
$('repVerify').onclick = verifySignature;
$('urlCsv').onclick = exportUrlCsv;
$('urlImportBtn').onclick = () => $('urlImportFile').click();
$('urlImportDirBtn').onclick = () => $('urlImportDir').click();
$('urlImportFile').onchange = () => { importUrls($('urlImportFile').files); $('urlImportFile').value = ''; };
$('urlImportDir').onchange = () => { importUrls($('urlImportDir').files); $('urlImportDir').value = ''; };
$('graphBtn').onclick = () => { resTab = 'graph'; renderCurrentResult(); };

// dashboard platform cards
for (const [id, p] of [['platWin', 'windows'], ['platLin', 'linux']]) {
  const b = $(id);
  if (b) b.onclick = () => {
    $('platform').value = p;
    try { localStorage.setItem('platform', p); } catch {}
    switchTab('tabAnalysis');
    $('drop').classList.add('over');
    setTimeout(() => $('drop').classList.remove('over'), 600);
  };
}
$('platform').onchange = () => { try { localStorage.setItem('platform', $('platform').value); } catch {} };

// ---------------------------------------------------------------------------
// auth bindings
// ---------------------------------------------------------------------------
$('go').onclick = login;
$('ngo').onclick = register;
$('rgo').onclick = recover;
for (const id of ['u', 'p']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
for (const id of ['nu', 'nphone', 'np', 'np2']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') register(); });
for (const id of ['ru', 'rk', 'rp']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') recover(); });
$('showReg').onclick = e => { e.preventDefault(); showAuth('reg'); $('nu').focus(); };
$('showLogin').onclick = e => { e.preventDefault(); showAuth('login'); $('u').focus(); };
$('recBack').onclick = e => { e.preventDefault(); showAuth('login'); };
$('forgot').onclick = e => { e.preventDefault(); showAuth('rec'); $('ru').focus(); };
$('keycopy').onclick = async () => {
  try { await navigator.clipboard.writeText($('keyval').textContent); $('keymsg').textContent = t('copied'); }
  catch { $('keymsg').textContent = t('copyFailed'); }
};
$('keyok').onclick = () => { $('keybox').hidden = true; };
$('logout').onclick = async () => { try { await api('/api/logout', { method: 'POST' }); } catch {} location.reload(); };
$('pgo').onclick = changePassword;
$('rnGo').onclick = renameAccount;
$('avatarUpload').onclick = uploadAvatar;
$('avatarFile').onchange = uploadAvatar;

// ---------------------------------------------------------------------------
// other bindings
// ---------------------------------------------------------------------------
$('dnsGo').onclick = lookupDns;
$('ipGo').onclick = lookupIp;
$('dnsType').onchange = () => { $('dnsDkimRow').hidden = $('dnsType').value !== 'dkim'; };
for (const id of ['dnsDomain', 'dnsSelector']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') lookupDns(); });
$('ipAddr').addEventListener('keydown', e => { if (e.key === 'Enter') lookupIp(); });
$('histGo').onclick = () => loadHistory(true);
$('histRefresh').onclick = () => loadHistory(true);
$('histQ').addEventListener('keydown', e => { if (e.key === 'Enter') loadHistory(true); });
$('logsRefresh').onclick = () => loadLogs(true);
$('adminRefresh').onclick = () => loadAdmin(true);
$('acGo').onclick = createAccount;
$('acRole').onchange = () => { $('acCccd').hidden = $('acRole').value !== 'admin'; };
$('acRole').onchange();
$('lang').onchange = () => {
  lang = $('lang').value === 'vi' ? 'vi' : 'en';
  try { localStorage.setItem('lang', lang); } catch {}
  applyLang();
};
$('themeBtn').onclick = () => applyTheme(document.documentElement.dataset.theme !== 'dark');

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------
initTheme();
applyLang();
(async () => {
  try {
    const r = await fetch('/api/me');
    if (r.ok) enterApp(await r.json());
  } catch {}
})();
