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
  guide9: 'The local AI endpoint is optional and must stay on localhost/private addresses. No cloud AI provider is supported.',
  guideNotes: 'Notes and cautions',
  guideN1: 'Offline by default: live DNS is disabled unless the server sets LIVE_DNS=1. GeoIP uses the local MaxMind database.',
  guideN2: 'Duplicate Message-ID values are normal in exported mailboxes; the tool keeps every record and its filename/folder provenance.',
  guideN3: 'A missing display name is not proof of spoofing; findings show the evidence and the weight used.',
  guideN4: 'Administrators must enroll with the offline keygen (password + CCCD salt). The CCCD is never stored.',
  guideN5: 'The map is an internal schematic, not an online tile service; it marks the server location found in the mail.',
  dnsH: 'DNS lookup', dnsDomain: 'example.com or IP', dnsTypeAll: 'All records / DNS health', dnsTypeAria: 'DNS record type',
  dnsSelector: 'DKIM selector (e.g. default)', dnsHint: 'Native DNS queries this server. Live queries require LIVE_DNS=1; otherwise the resolver reports the offline state.',
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
  loadTrustStatus();
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
    if (tab.id === 'tabTrust') loadTrustStatus();
    if (tab.id === 'tabAdmin') loadAdmin();
    if (tab.id === 'tabResults') renderCurrentResult();
  };
});
