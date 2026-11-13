const $ = id => document.getElementById(id);
let csrf = '', last = null, lastResults = [], lastErrors = [], user = '', lastDns = null, lastIp = null;
let histLoaded = false, histLoading = false, histCases = [];
let sessionTimerId = null, sessionExpires = 0, lastLoginMs = 0;
let logsLoaded = false, logsLoading = false, logsData = [], sessionsData = [];
let profileData = null;
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
    loginH: 'Login', username: 'username', password: 'password', login: 'Login',
    forgot: 'Forgot password?', createAccount: 'Create account', haveAccount: 'Back to login',
    regH: 'Create account', confirmPass: 'confirm password', register: 'Register',
    userRule: 'Username: 3–32 characters (letters, digits, . _ -). Password: 10–72 characters, max 72 UTF-8 bytes.',
    recH: 'Reset password', recoveryKey: 'recovery key XXXX-XXXX-...',
    newPass: 'new password (10–72 chars)', reset: 'Reset',
    keyTitle: 'Save your recovery key',
    keyHint: 'This key is shown once and is the only way to reset a forgotten password. Store it somewhere safe; the server keeps only a hash.',
    copy: 'Copy', saved: 'I saved it', signedIn: 'Signed in as ',
    copied: 'Recovery key copied.',
    copyFailed: 'Could not copy — select the key and copy it manually.',
    appH: 'Upload dataset (.eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost)',
    logout: 'Logout', analyze: 'Analyze',
    accountTitle: 'Account — change password', currentPass: 'current password', change: 'Change',
    aiTitle: 'AI assist (free model, key stays in browser)',
    aiHint: 'The API key stays in this tab and is sent only to the endpoint you choose. Only the findings summary is sent — never the raw email file. HTTPS is required (plain HTTP only for localhost).',
    aiUrl: 'API endpoint', aiModel: 'model id', apiKey: 'API key', askAi: 'Ask AI', forgetKey: 'Forget key',
    keyForgotten: 'API key removed from this tab.',
    aiNeedResult: 'Analyze an email first.',
    aiBadUrl: 'Endpoint must use HTTPS (or http://localhost / 127.0.0.1).',
    aiNeedModel: 'Enter a model id.',
    aiNeedKey: 'Enter an API key.',
    aiThinking: 'Asking the model…',
    aiTimeout: 'AI request timed out after 60 seconds.',
    aiError: 'AI request failed: ', aiEmpty: 'The AI returned an empty response.',
    pickFilesBtn: 'Choose files', pickFolderBtn: 'Choose folder',
    aiModelSelect: 'AI model (OpenRouter)', aiModelsFree: 'Free models (FREE)', aiModelsPaid: 'Paid models — your OpenRouter key',
    aiModelCustom: 'Custom… (type model id manually)',
    aiCompact: 'Compact view — hide null/empty output (uncheck for full detail)',
    confidenceLabel: 'Confidence', locatedSummary: 'Located',
    analyzing: 'Analyzing…', detailLabel: 'Details',

    tabAnalysis: 'Analysis', tabDns: 'DNS', tabIp: 'IP / Geo',
    tabHistory: 'History', historyH: 'Investigation history',
    tabTrust: 'Trust & AI', trustH: 'Threat feeds & AI assessment',
    trustHint: 'Optional. Off by default: without keys the server stays fully offline. Keys are stored per account in the server database and are never echoed back or written to the audit log. Only the URL or the file hash is ever sent to a feed - never mail content.',
    repAbuseKey: 'abuse.ch Auth-Key (URLhaus)', repVtKey: 'VirusTotal API key',
    repSbKey: 'Google Safe Browsing key', llmKey: 'LLM API key (OpenRouter compatible)',
    repAbusePh: 'free key from abuse.ch', repVtPh: 'hash lookup only - files are never uploaded',
    repSbPh: 'optional', llmKeyPh: 'optional - used only for the semantic assessment',
    trustSave: 'Save keys', trustClear: 'Remove', trustState: 'Server status: checking…',
    trustStateOn: 'Server status', trustEnabled: 'reputation feeds ON', trustDisabled: 'reputation feeds OFF',
    trustSaved: 'Keys saved.', trustCleared: 'Keys removed.',
    historyHint: 'Latest 100 cases. Admins see all cases; analysts see their own. Open a case to restore its result.',
    historySearch: 'Search', historySearchPh: 'file, analyst or case ID', refresh: 'Refresh',
    historyEmpty: 'No cases yet.', historyLoadFailed: 'Could not load history: ',
    historyLoaded: 'Loaded case from history.', historyOpen: 'Open',
    historyWhen: 'Date', historyFile: 'File', historyAnalyst: 'Analyst', historyMessages: 'Messages',
    historyVerdict: 'Verdict', historyScore: 'Score',
    profileTitle: 'Profile', uploadAvatar: 'Upload avatar', avatarHint: 'PNG or JPEG only, maximum 2 MB.',
    avatarBadType: 'Only PNG or JPEG images are allowed.', avatarBad: 'Invalid image file.',
    avatarTooLarge: 'Avatar is too large (max 2 MB).', avatarOk: 'Avatar updated.',
    avatarFailed: 'Avatar upload failed — please try again.',
    profileRole: 'Role', profileCreated: 'Account created', loginTime: 'Login time',
    sessionTime: 'Session expires in', sessionExpired: 'Session expired — please log in again.',
    loggingIn: 'Logging in',
    tabLogs: 'Logs', logsH: 'Audit and session log',
    logsHint: 'Admin only. Login duration is measured server-side; ended sessions are signed with SHA-256 and chained to the previous signature.',
    auditLog: 'Audit log', sessionLog: 'Signed session endings', logsEmpty: 'No audit entries.',
    sessionsEmpty: 'No signed sessions yet.', logsLoadFailed: 'Could not load logs: ',
    signatureLabel: 'Signature SHA-256', previousLabel: 'Previous signature', reasonLabel: 'Reason',
    durationMs: 'Duration (ms)', sessionUser: 'User', sessionRole: 'Role',
    dnsH: 'DNS lookup', dnsDomain: 'example.com or IP', dnsTypeAria: 'DNS record type', dnsSourceAria: 'DNS lookup source',
    dnsSourceNative: 'Native DNS', dnsSourceMx: 'MxToolbox', dnsTypeAll: 'All records / DNS health',
    dnsSelector: 'DKIM selector (e.g. default)', mxKey: 'MxToolbox API key (optional if server key set)', forgetMxKey: 'Forget key',
    dnsHint: 'Native DNS queries this server. MxToolbox runs the lookup remotely; you can enter your own API key. Keys stay in this tab and are never written to the audit log.',
    dnsKeyForgotten: 'MxToolbox key removed from this tab.',
    ipH: 'IP geolocation and network', ipAddr: '8.8.8.8',
    ipHint: 'MaxMind GeoLite2 is used locally. PTR is queried through this server. Location is approximate and may be affected by VPN/proxy.',
    lookup: 'Lookup', dnsNeedDomain: 'Enter a domain or IP address.', ipNeed: 'Enter a valid IP address.',
    dnsFailed: 'Lookup failed: ',
    dnsErr_bad_domain: 'Invalid domain or IP address.', dnsErr_bad_type: 'Unsupported lookup type.',
    dnsErr_selector: 'DKIM lookup needs a selector.', dnsErr_bad_ip: 'Invalid IP address.',
    dnsErr_mxtoolbox_only: 'Blacklist checks need the MxToolbox source.',
    dnsErr_mxtoolbox_auth: 'MxToolbox rejected the API key — check it, or leave it empty to use the server key.',
    dnsErr_mxtoolbox_rate: 'MxToolbox rate limit or quota exceeded.',
    dnsErr_mxtoolbox_timeout: 'MxToolbox timed out.', dnsErr_mxtoolbox_network: 'Cannot reach MxToolbox.',
    dnsErr_mxtoolbox_json: 'MxToolbox returned an invalid response.', dnsErr_mxtoolbox_not_found: 'MxToolbox lookup not found.',
    dnsErr_mxtoolbox_error: 'MxToolbox lookup failed.', dnsErr_dns_error: 'DNS lookup failed.',
    dnsErr_bad_key: 'Invalid MxToolbox API key format.', dnsErr_ip_lookup_failed: 'IP lookup failed.',
    dnsErr_body_unavailable: 'Message content is not available for this case.',
    dnsErr_rate: 'Too many lookups — wait a minute.', dnsErr_auth: 'Session expired — please log in again.',
    dnsErr_csrf: 'Session expired — please log in again.',
    sourceLabel: 'Source', queryLabel: 'Query', durationLabel: 'Duration', resolverLabel: 'Resolver',
    reportingNameServer: 'Reporting name server',
    statusLabel: 'Status', recordsLabel: 'DNS records', authRecords: 'Authentication records', noRecords: 'No records',    spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', policy: 'Policy', selectorLabel: 'Selector',
    foundLabel: 'found', notFoundLabel: 'not found', mxtoolbox: 'MxToolbox', failedLabel: 'Failed',
    warningsLabel: 'Warnings', passedLabel: 'Passed', timeoutsLabel: 'Timeouts', informationLabel: 'Information',
    transcriptLabel: 'Transcript', rawLabel: 'Raw response', keyUsed: 'API key used', keyNotUsed: 'No user key sent',
    geoLabel: 'Geolocation', countryLabel: 'Country', cityLabel: 'City', regionLabel: 'Region', asnLabel: 'ASN',
    organizationLabel: 'Organization', ptrLabel: 'PTR', coordinatesLabel: 'Coordinates', accuracyLabel: 'Accuracy',
    timezoneLabel: 'Time zone', approxLabel: 'Approximate location; VPN/proxy may affect it.',
    serverTypeLabel: 'Server type', assessLabel: 'Assessment', dnsAssessment: 'Assessment', mapTitle: 'Geolocation map',
    a_authentic: 'Likely genuine', a_suspicious: 'Suspicious', a_spoofed: 'Likely spoofed', a_unverified: 'Not verifiable',
    a_consistent: 'Consistent with dataset', a_unrelated: 'Unrelated to dataset',
    st_mail: 'Mail server', st_hosting: 'Hosting / datacenter', st_isp: 'ISP', st_cdn: 'CDN', st_proxy_vpn: 'Proxy / VPN', st_unknown: 'Unknown',
    mapglotKey: 'MapGlot API key', mapglotKeyPh: 'key from mapglot.com — saved server-side', mapKeySave: 'Save', mapKeyClear: 'Remove',
    mapglotHint: 'Each account keeps its own MapGlot key (optional): it reverse-geocodes each map point so your report legend carries the full street address. Change or remove it any time. The map image itself always comes from OpenStreetMap tiles (MapGlot has no static-image API).',
    mapKeyStatusOwn: 'Your personal key is active.', mapKeyStatusServer: 'Using the server-wide key.', mapKeyStatusEnv: 'Key from server environment.', mapKeyStatusNone: 'No key — legend shows city/country only.', mapKeyErr: 'Could not save the key.',
    mapKeyErrUnverified: '⚠ Key not active yet — verify your email at mapglot.com (inbox link), then reload this tab.',
    mapKeyErrInvalid: '⚠ MapGlot rejected the key (invalid or revoked).',
    mapKeyErrQuota: '⚠ Daily MapGlot quota reached (10,000 requests).',
    mapKeyErrUnavail: '⚠ Cannot reach mapglot.com right now.',
    geoUnavailable: 'No GeoIP data for this IP (private address, unknown range or database not loaded).',
    messagesLabel: 'Messages', messageLabel: 'Message', fromLabel: 'From', toLabel: 'To', replyToLabel: 'Reply-To',
    senderDns: 'Sender DNS (live)', ipIntelligence: 'IP intelligence',
    dnsExplain: 'Header authentication results come from the receiving server. Live DNS shows published SPF/DMARC/MX records; DKIM signatures are not cryptographically verified here.',
    ipExplain: 'Public IPs found in Received headers, enriched with MaxMind GeoLite2 and PTR. These are candidates, not proof of origin.',
    returnPathLabel: 'Return-Path', messageIdLabel: 'Message-ID', dateLabel: 'Date', authLabel: 'Authentication',
    bodyText: 'Plain text', bodyHtml: 'HTML', bodyEmpty: 'No content stored for this message.',
    bodyTruncated: 'Content was truncated.', bodyOmitted: 'Content was not stored (storage limit).',
    contentLoadFailed: 'Could not load message content.', showFirstMessages: 'Showing the first 200 messages.',
    authservLabel: 'Authentication server', authHeaderLabel: 'Authentication-Results header', alignmentLabel: 'Alignment',
    upstreamLabel: 'Upstream result', upstreamSpf: 'Upstream SPF', upstreamDkim: 'Upstream DKIM',
    upstreamDmarc: 'Upstream DMARC', dkimSignaturesLabel: 'DKIM signatures',
    yesLabel: 'yes', noLabel: 'no', unknownLabel: 'unknown', htmlBlocked: 'Remote content is blocked in this view.',


    errRate: 'Too many requests — wait a minute and try again.',
    errLogin: 'Wrong username or password.',
    errNetwork: 'Cannot reach server: ',
    errExists: 'That username is already taken.',
    errBadUser: 'Username must be 3–32 characters: letters, digits, dot, underscore or dash, with at least one letter or digit.',
    errWeak: 'New password must be 10–72 characters and at most 72 UTF-8 bytes.',
    errDisabled: 'Registration is disabled on this server.',
    errRegister: 'Registration failed — try again.',
    errMatch: 'The two passwords do not match.',
    errRecover: 'Invalid username or recovery key.',
    recOk: 'Password changed. Save your NEW recovery key below — the old key no longer works.',
    passOk: 'Password changed. Other sessions were signed out.',
    passBad: 'Current password is wrong.',
    noFile: 'Choose one or more email files first.',
    uploadErrors: 'Some files could not be analyzed:',
    reportFailed: 'Report failed: ',
    dropHint: 'Drag & drop email files or whole folders here — or use the buttons below. Supported: .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost (PST/OST up to 500 MB).',
    clearList: 'Clear list', pickNone: 'No files selected.', pickFiles: 'file(s) selected',
    pickSkipped: 'unsupported file(s) skipped', pickDup: 'duplicate(s) ignored',
    pickRemove: 'Remove from list', pickLimit: 'Maximum files per analysis: ',
    pause: 'Pause', resume: 'Resume', stop: 'Stop', cancel: 'Cancel', analysisControls: 'Analysis controls',
    runRunning: 'Analyzing…', runPausing: 'Pausing after the current batch…',
    runPaused: 'Paused — click Resume to continue.', runResuming: 'Resuming…',
    runStopping: 'Stopping after the current batch…',
    runStopped: 'Stopped — partial results kept.',
    runStoppedNoResults: 'Stopped before any file finished — no results.',
    runCancelled: 'Analysis cancelled — results discarded.',
    batchTimeout: 'Batch timed out and was aborted — partial results kept.',
    pfRejected: 'file(s) rejected by the preflight check:',
    pfBadExt: 'unsupported extension (allowed: .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost)',
    pfEmpty: 'empty file (0 bytes)',
    pfTooLarge: 'larger than 25 MB',
    pfPstTooLarge: 'PST/OST larger than 500 MB',
    pfDupe: 'duplicate — already in the list',
    pfReady: 'preflight passed, ready to analyze',
    pfNoneLeft: 'no valid files left to analyze',
    stepUpload: 'Upload batch',

    stepValidate: 'Validate', stepProcess: 'Copy & hash evidence → Parse → Analyze', stepScore: 'Score',
    score: 'Risk score', authResults: 'Authentication results', present: 'present', missing: 'missing (unverified)',
    findings: 'Findings', attachments: 'Attachments', originIps: 'Possible origin IPs',
    report: 'Report', shown: 'Showing the first 300 findings.', noFindings: 'No suspicious indicators found.',
    v_clean: 'Clean', v_suspicious: 'Suspicious', v_malicious_or_phishing: 'Malicious or phishing', v_unverified: 'Unverified',

    ft_from_returnpath_mismatch: 'From / Return-Path domain mismatch',
    ft_from_replyto_mismatch: 'From / Reply-To domain mismatch',
    ft_spf_alignment_mismatch: 'SPF domain does not align with From',
    ft_dkim_alignment_mismatch: 'DKIM domain does not align with From',
    ft_spf_fail: 'SPF failed', ft_spf_softfail: 'SPF soft-fail', ft_spf_neutral: 'SPF neutral',
    ft_spf_none: 'SPF none', ft_spf_permerror: 'SPF permanent error', ft_spf_temperror: 'SPF temporary error',
    ft_dkim_fail: 'DKIM failed', ft_dkim_none: 'DKIM none', ft_dkim_policy: 'DKIM policy',
    ft_dmarc_fail: 'DMARC failed', ft_dmarc_none: 'DMARC none',
    ft_spf_missing: 'No SPF result in headers', ft_dkim_missing: 'No DKIM result in headers', ft_dmarc_missing: 'No DMARC result in headers',
    ft_origin_ip_candidates: 'Public IPs in Received headers',
    ft_link_text_mismatch: 'Link text differs from real destination',
    ft_ip_host_link: 'Link points to a raw IP address',
    ft_punycode_domain: 'Punycode (homograph) domain',
    ft_dangerous_attachment: 'Dangerous attachment',
    ft_double_extension: 'Double file extension',
    ft_phishing_url: 'Phishing URL', ft_suspicious_url: 'Suspicious URL',
    ft_url_blocklisted: 'URL listed in a threat feed',
    ft_ml_phishing: 'Classifier (ML) verdict', ft_llm_suspicious: 'LLM semantic assessment',
    ft_suspicious_attachment: 'Suspicious attachment',
    threats: 'URL & attachment threats', iocCount: 'IOC',
    urlLabel: 'URL', hostLabel: 'Host', riskLabel: 'Risk', reasonsLabel: 'Reasons',
    a_clean: 'clean', a_suspicious: 'suspicious', a_malicious: 'MALICIOUS',
    exportSiem: 'Export SIEM',
    ft_message_id_mismatch: 'Message-ID domain mismatch',
    ft_duplicate_headers: 'Duplicated header',
    ft_missing_header: 'Missing header',
    ft_date_skew: 'Date / Received skew',
    ft_display_name_spoof: 'Display-name spoofing',
    ft_x_originating_ip: 'Sender IP disclosed (X-Originating-IP)',
    ft_hop_delay: 'Unusually long hop delay',
    ft_hop_negative_delay: 'Negative hop delay',
    ft_hop_loop: 'Routing loop',
    ft_hop_missing_from: 'Hop missing from-clause',
    ft_private_ip_hop: 'Private IP in hop',
    forensics: 'Header & routing forensics',
    authEnvelope: 'Envelope / client IP', receivedCount: 'Received headers',
    totalTransit: 'Total transit', headerChecks: 'Header & routing checks',
    hopFrom: 'From', gatewayLabel: 'Gateway', hopDelay: 'Delay', hopTime: 'Timestamp',

    e_too_large: 'File too large (max 25 MB per message file, 500 MB for PST/OST).',
    e_format_mismatch: 'File content does not match its extension.',
    e_file: 'Unsupported file type. Use .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost.',
    e_parse: 'Could not parse this email file.',
    e_readpst_missing: 'PST/OST needs the readpst tool (Linux: apt install pst-utils, or use the Docker image).',
    e_pst_timeout: 'PST/OST extraction timed out.',
    e_readpst_failed: 'PST/OST could not be read (corrupt, encrypted or unsupported).',
    e_bad_msg: 'Invalid Outlook .msg file.',
    e_bad_emlx: 'Invalid Apple .emlx file.',
    e_empty: 'No email messages were found in the file.',
    e_upload: 'Upload failed — check the file and try again.',
    e_rate: 'Too many requests — wait a minute and try again.',
    e_bad_json: 'Malformed request.',
    e_server: 'Server error — check the server log.',
    e_auth: 'Session expired — please log in again.',
    e_csrf: 'Session expired — please log in again.',
    e_not_found: 'Endpoint not found (server/client version mismatch).',
    e_unknown: 'Error: '
  },
  vi: {
    title: 'MailSleuth — Phòng thí nghiệm điều tra email & truy vết kẻ tấn công',
    subtitle: 'Phòng thí nghiệm điều tra email & truy vết kẻ tấn công',
    loginH: 'Đăng nhập', username: 'tên đăng nhập', password: 'mật khẩu', login: 'Đăng nhập',
    forgot: 'Quên mật khẩu?', createAccount: 'Tạo tài khoản', haveAccount: 'Về đăng nhập',
    regH: 'Tạo tài khoản', confirmPass: 'nhập lại mật khẩu', register: 'Đăng ký',
    userRule: 'Tên đăng nhập: 3–32 ký tự (chữ, số, . _ -). Mật khẩu: 10–72 ký tự, tối đa 72 byte UTF-8.',
    recH: 'Đặt lại mật khẩu', recoveryKey: 'khóa khôi phục XXXX-XXXX-...',
    newPass: 'mật khẩu mới (10–72 ký tự)', reset: 'Đặt lại',
    keyTitle: 'Hãy lưu khóa khôi phục',
    keyHint: 'Khóa này chỉ hiện một lần và là cách duy nhất để đặt lại mật khẩu khi quên. Hãy cất giữ an toàn; máy chủ chỉ lưu bản băm.',
    copy: 'Sao chép', saved: 'Tôi đã lưu', signedIn: 'Đăng nhập với ',
    copied: 'Đã sao chép khóa khôi phục.',
    copyFailed: 'Không sao chép được — hãy chọn khóa và sao chép thủ công.',
    appH: 'Tải dữ liệu (.eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost)',
    logout: 'Đăng xuất', analyze: 'Phân tích',
    accountTitle: 'Tài khoản — đổi mật khẩu', currentPass: 'mật khẩu hiện tại', change: 'Đổi',
    aiTitle: 'Hỗ trợ AI (model miễn phí, khóa chỉ ở trình duyệt)',
    aiHint: 'Khóa API chỉ nằm trong tab này và chỉ gửi tới endpoint bạn chọn. Chỉ bản tóm tắt phát hiện được gửi — không gửi file email gốc. Bắt buộc HTTPS (HTTP chỉ cho localhost).',
    aiUrl: 'Địa chỉ API', aiModel: 'mã model', apiKey: 'Khóa API', askAi: 'Hỏi AI', forgetKey: 'Xóa khóa',
    keyForgotten: 'Đã xóa khóa API khỏi tab này.',
    aiNeedResult: 'Hãy phân tích một email trước.',
    aiBadUrl: 'Endpoint phải dùng HTTPS (hoặc http://localhost / 127.0.0.1).',
    aiNeedModel: 'Nhập mã model.',
    aiNeedKey: 'Nhập khóa API.',
    aiThinking: 'Đang hỏi model…',
    aiTimeout: 'Yêu cầu AI quá 60 giây.',
    aiError: 'Yêu cầu AI thất bại: ', aiEmpty: 'AI trả về nội dung rỗng.',
    pickFilesBtn: 'Chọn tệp', pickFolderBtn: 'Chọn thư mục',
    aiModelSelect: 'Model AI (OpenRouter)', aiModelsFree: 'Model miễn phí (FREE)', aiModelsPaid: 'Model trả phí — khóa OpenRouter của bạn',
    aiModelCustom: 'Tùy chọn… (tự gõ mã model)',
    aiCompact: 'Chế độ gọn — ẩn giá trị rỗng/null (bỏ chọn để xem chi tiết)',
    confidenceLabel: 'Độ tin cậy', locatedSummary: 'Đã xác định vị trí',
    analyzing: 'Đang phân tích…', detailLabel: 'Chi tiết',

    tabAnalysis: 'Phân tích', tabDns: 'DNS', tabIp: 'IP / Vị trí',
    tabHistory: 'Lịch sử', historyH: 'Lịch sử điều tra',
    tabTrust: 'Tin cậy & AI', trustH: 'Nguồn cảnh báo & đánh giá bằng AI',
    trustHint: 'Tuỳ chọn. Mặc định tắt: không có key thì máy chủ vẫn chạy hoàn toàn offline. Key lưu theo tài khoản trong CSDL máy chủ, không bao giờ gửi lại và không ghi vào nhật ký. Chỉ URL hoặc hash tệp được gửi đi — không có nội dung thư.',
    repAbuseKey: 'Auth-Key abuse.ch (URLhaus)', repVtKey: 'API key VirusTotal',
    repSbKey: 'API key Google Safe Browsing', llmKey: 'API key LLM (chuẩn OpenRouter)',
    repAbusePh: 'key miễn phí từ abuse.ch', repVtPh: 'chỉ tra hash — không tải tệp lên',
    repSbPh: 'tuỳ chọn', llmKeyPh: 'tuỳ chọn — chỉ dùng cho đánh giá ngữ nghĩa',
    trustSave: 'Lưu key', trustClear: 'Xoá key', trustState: 'Trạng thái máy chủ: đang kiểm tra…',
    trustStateOn: 'Trạng thái máy chủ', trustEnabled: 'nguồn cảnh báo ĐANG BẬT', trustDisabled: 'nguồn cảnh báo đang tắt',
    trustSaved: 'Đã lưu key.', trustCleared: 'Đã xoá key.',
    historyHint: '100 vụ việc gần nhất. Admin thấy tất cả; analyst chỉ thấy vụ của mình. Mở một vụ để khôi phục kết quả.',
    historySearch: 'Tìm kiếm', historySearchPh: 'tệp, analyst hoặc mã vụ việc', refresh: 'Làm mới',
    historyEmpty: 'Chưa có vụ việc nào.', historyLoadFailed: 'Không tải được lịch sử: ',
    historyLoaded: 'Đã tải vụ việc từ lịch sử.', historyOpen: 'Mở',
    historyWhen: 'Ngày', historyFile: 'Tệp', historyAnalyst: 'Analyst', historyMessages: 'Số thư',
    historyVerdict: 'Kết luận', historyScore: 'Điểm',
    profileTitle: 'Hồ sơ cá nhân', uploadAvatar: 'Tải ảnh đại diện', avatarHint: 'Chỉ nhận PNG hoặc JPEG, tối đa 2 MB.',
    avatarBadType: 'Chỉ cho phép ảnh PNG hoặc JPEG.', avatarBad: 'Tệp ảnh không hợp lệ.',
    avatarTooLarge: 'Ảnh đại diện quá lớn (tối đa 2 MB).', avatarOk: 'Đã cập nhật ảnh đại diện.',
    avatarFailed: 'Tải ảnh đại diện thất bại — hãy thử lại.',
    profileRole: 'Vai trò', profileCreated: 'Ngày tạo tài khoản', loginTime: 'Thời gian đăng nhập',
    sessionTime: 'Phiên còn lại', sessionExpired: 'Phiên đã hết hạn — vui lòng đăng nhập lại.',
    loggingIn: 'Đang đăng nhập',
    tabLogs: 'Nhật ký', logsH: 'Nhật ký hoạt động và phiên',
    logsHint: 'Chỉ admin. Thời gian đăng nhập được đo phía máy chủ; phiên kết thúc được ký SHA-256 và nối với chữ ký trước.',
    auditLog: 'Nhật ký hoạt động', sessionLog: 'Phiên đã ký khi kết thúc', logsEmpty: 'Không có bản ghi.',
    sessionsEmpty: 'Chưa có phiên nào được ký.', logsLoadFailed: 'Không tải được nhật ký: ',
    signatureLabel: 'Chữ ký SHA-256', previousLabel: 'Chữ ký trước', reasonLabel: 'Lý do',
    durationMs: 'Thời gian (ms)', sessionUser: 'Người dùng', sessionRole: 'Vai trò',
    dnsH: 'Tra cứu DNS', dnsDomain: 'example.com hoặc IP', dnsTypeAria: 'Loại bản ghi DNS', dnsSourceAria: 'Nguồn tra cứu DNS',
    dnsSourceNative: 'DNS nội bộ', dnsSourceMx: 'MxToolbox', dnsTypeAll: 'Tất cả bản ghi / kiểm tra DNS',
    dnsSelector: 'Selector DKIM (ví dụ: default)', mxKey: 'Khóa API MxToolbox (bỏ trống nếu máy chủ đã cấu hình)', forgetMxKey: 'Xóa khóa',
    dnsHint: 'DNS nội bộ truy vấn từ máy chủ này. MxToolbox tra cứu từ xa; bạn có thể nhập khóa API riêng. Khóa chỉ nằm trong tab này và không được ghi vào audit log.',
    dnsKeyForgotten: 'Đã xóa khóa MxToolbox khỏi tab này.',
    ipH: 'Vị trí IP và thông tin mạng', ipAddr: '8.8.8.8',
    ipHint: 'MaxMind GeoLite2 được dùng cục bộ. PTR được truy vấn qua máy chủ này. Vị trí chỉ là ước tính và có thể sai do VPN/proxy.',
    lookup: 'Tra cứu', dnsNeedDomain: 'Hãy nhập tên miền hoặc địa chỉ IP.', ipNeed: 'Hãy nhập địa chỉ IP hợp lệ.',
    dnsFailed: 'Tra cứu thất bại: ',
    dnsErr_bad_domain: 'Tên miền hoặc địa chỉ IP không hợp lệ.', dnsErr_bad_type: 'Loại tra cứu không hỗ trợ.',
    dnsErr_selector: 'Tra cứu DKIM cần selector.', dnsErr_bad_ip: 'Địa chỉ IP không hợp lệ.',
    dnsErr_mxtoolbox_only: 'Kiểm tra blacklist cần nguồn MxToolbox.',
    dnsErr_mxtoolbox_auth: 'MxToolbox từ chối khóa API — kiểm tra lại, hoặc bỏ trống để dùng khóa của máy chủ.',
    dnsErr_mxtoolbox_rate: 'MxToolbox đã vượt giới hạn tần suất hoặc hạn mức.',
    dnsErr_mxtoolbox_timeout: 'MxToolbox quá thời gian.', dnsErr_mxtoolbox_network: 'Không kết nối được MxToolbox.',
    dnsErr_mxtoolbox_json: 'MxToolbox trả về dữ liệu không hợp lệ.', dnsErr_mxtoolbox_not_found: 'MxToolbox không tìm thấy kết quả.',
    dnsErr_mxtoolbox_error: 'Tra cứu MxToolbox thất bại.', dnsErr_dns_error: 'Tra cứu DNS thất bại.',
    dnsErr_bad_key: 'Định dạng khóa API MxToolbox không hợp lệ.', dnsErr_ip_lookup_failed: 'Tra cứu IP thất bại.',
    dnsErr_body_unavailable: 'Không có nội dung thư cho vụ việc này.',
    dnsErr_rate: 'Quá nhiều lần tra cứu — hãy đợi một phút.', dnsErr_auth: 'Phiên đã hết hạn — vui lòng đăng nhập lại.',
    dnsErr_csrf: 'Phiên đã hết hạn — vui lòng đăng nhập lại.',
    sourceLabel: 'Nguồn', queryLabel: 'Truy vấn', durationLabel: 'Thời gian', resolverLabel: 'Resolver',
    reportingNameServer: 'Máy chủ DNS báo cáo',
    statusLabel: 'Trạng thái', recordsLabel: 'Bản ghi DNS', authRecords: 'Bản ghi xác thực', noRecords: 'Không có bản ghi',
    spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', policy: 'Chính sách', selectorLabel: 'Selector',
    foundLabel: 'có', notFoundLabel: 'không có', mxtoolbox: 'MxToolbox', failedLabel: 'Thất bại',
    warningsLabel: 'Cảnh báo', passedLabel: 'Đạt', timeoutsLabel: 'Quá thời gian', informationLabel: 'Thông tin',
    transcriptLabel: 'Nhật ký truy vấn', rawLabel: 'Dữ liệu gốc', keyUsed: 'Có dùng khóa người dùng', keyNotUsed: 'Không gửi khóa người dùng',
    geoLabel: 'Vị trí địa lý', countryLabel: 'Quốc gia', cityLabel: 'Thành phố', regionLabel: 'Vùng', asnLabel: 'ASN',
    organizationLabel: 'Tổ chức', ptrLabel: 'PTR', coordinatesLabel: 'Tọa độ', accuracyLabel: 'Độ chính xác',
    timezoneLabel: 'Múi giờ', approxLabel: 'Vị trí ước tính; VPN/proxy có thể làm sai lệch.',
    serverTypeLabel: 'Loại server', assessLabel: 'Đánh giá', dnsAssessment: 'Đánh giá', mapTitle: 'Bản đồ định vị',
    a_authentic: 'Khả năng thật', a_suspicious: 'Đáng ngờ', a_spoofed: 'Khả năng giả mạo', a_unverified: 'Không thể xác minh',
    a_consistent: 'Khớp với tập dữ liệu', a_unrelated: 'Không liên quan tập dữ liệu',
    st_mail: 'Máy chủ mail', st_hosting: 'Hosting / datacenter', st_isp: 'ISP', st_cdn: 'CDN', st_proxy_vpn: 'Proxy / VPN', st_unknown: 'Không rõ',
    mapglotKey: 'API key MapGlot', mapglotKeyPh: 'key từ mapglot.com — lưu phía server', mapKeySave: 'Lưu', mapKeyClear: 'Xóa',
    mapglotHint: 'Mỗi tài khoản tự giữ key MapGlot riêng (không bắt buộc): dùng reverse geocoding để chú giải báo cáo của bạn có địa chỉ đầy đủ. Dễ thay đổi hoặc xóa bất cứ lúc nào. Ảnh bản đồ luôn ghép từ tile OpenStreetMap (MapGlot không có API ảnh tĩnh).',
    mapKeyStatusOwn: 'Đang dùng key riêng của bạn.', mapKeyStatusServer: 'Đang dùng key chung của server.', mapKeyStatusEnv: 'Key lấy từ biến môi trường server.', mapKeyStatusNone: 'Chưa có key — chú giải chỉ có thành phố/quốc gia.', mapKeyErr: 'Không lưu được key.',
    mapKeyErrUnverified: '⚠ Key chưa kích hoạt — hãy xác minh email tại mapglot.com (link trong hộp thư), rồi tải lại tab này.',
    mapKeyErrInvalid: '⚠ MapGlot từ chối key (sai hoặc đã thu hồi).',
    mapKeyErrQuota: '⚠ Đã hết quota ngày của MapGlot (10.000 request).',
    mapKeyErrUnavail: '⚠ Không kết nối được tới mapglot.com lúc này.',
    geoUnavailable: 'Không có dữ liệu GeoIP cho IP này (địa chỉ riêng, dải chưa biết hoặc chưa nạp database).',
    messagesLabel: 'Danh sách thư', messageLabel: 'Thư', fromLabel: 'Người gửi', toLabel: 'Người nhận', replyToLabel: 'Reply-To',
    senderDns: 'DNS miền gửi (trực tiếp)', ipIntelligence: 'Thông tin IP',
    dnsExplain: 'Kết quả xác thực trong header do máy chủ nhận ghi lại. Mục DNS trực tiếp hiển thị bản ghi SPF/DMARC/MX đã công bố; công cụ chưa xác minh chữ ký DKIM bằng mật mã.',
    ipExplain: 'Các IP công khai trong header Received, được làm giàu bằng MaxMind GeoLite2 và PTR. Đây chỉ là IP ứng viên, không phải bằng chứng nguồn gửi.',
    returnPathLabel: 'Return-Path', messageIdLabel: 'Message-ID', dateLabel: 'Ngày', authLabel: 'Xác thực',
    bodyText: 'Nội dung văn bản', bodyHtml: 'HTML', bodyEmpty: 'Không có nội dung được lưu cho thư này.',
    bodyTruncated: 'Nội dung đã bị cắt bớt.', bodyOmitted: 'Nội dung không được lưu (giới hạn dung lượng).',
    contentLoadFailed: 'Không tải được nội dung thư.', showFirstMessages: 'Chỉ hiển thị 200 thư đầu tiên.',
    authservLabel: 'Máy chủ xác thực', authHeaderLabel: 'Header Authentication-Results', alignmentLabel: 'Alignment',
    upstreamLabel: 'Kết quả máy nhận', upstreamSpf: 'SPF của máy nhận', upstreamDkim: 'DKIM của máy nhận',
    upstreamDmarc: 'DMARC của máy nhận', dkimSignaturesLabel: 'Chữ ký DKIM',
    yesLabel: 'có', noLabel: 'không', unknownLabel: 'không rõ', htmlBlocked: 'Nội dung từ xa bị chặn trong chế độ xem này.',


    errRate: 'Quá nhiều yêu cầu — hãy đợi một phút rồi thử lại.',
    errLogin: 'Sai tên đăng nhập hoặc mật khẩu.',
    errNetwork: 'Không kết nối được máy chủ: ',
    errExists: 'Tên đăng nhập này đã được sử dụng.',
    errBadUser: 'Tên đăng nhập phải 3–32 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch ngang, có ít nhất một chữ hoặc số.',
    errWeak: 'Mật khẩu mới phải 10–72 ký tự và tối đa 72 byte UTF-8.',
    errDisabled: 'Máy chủ này đã tắt đăng ký.',
    errRegister: 'Đăng ký thất bại — hãy thử lại.',
    errMatch: 'Hai mật khẩu không khớp.',
    errRecover: 'Sai tên đăng nhập hoặc khóa khôi phục.',
    recOk: 'Đã đổi mật khẩu. Hãy lưu khóa khôi phục MỚI bên dưới — khóa cũ không còn hiệu lực.',
    passOk: 'Đã đổi mật khẩu. Các phiên đăng nhập khác đã bị đăng xuất.',
    passBad: 'Mật khẩu hiện tại không đúng.',
    noFile: 'Hãy chọn một hoặc nhiều tệp email trước.',
    uploadErrors: 'Một số tệp không thể phân tích:',
    reportFailed: 'Xuất báo cáo thất bại: ',
    dropHint: 'Kéo thả tệp email hoặc cả thư mục vào đây — hoặc dùng các nút bên dưới. Hỗ trợ: .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost (PST/OST tối đa 500 MB).',
    clearList: 'Xóa danh sách', pickNone: 'Chưa chọn tệp nào.', pickFiles: 'tệp đã chọn',
    pickSkipped: 'tệp không được hỗ trợ đã bị bỏ qua', pickDup: 'tệp trùng bị bỏ qua',
    pickRemove: 'Gỡ khỏi danh sách', pickLimit: 'Số tệp tối đa mỗi lần phân tích: ',
    pause: 'Tạm dừng', resume: 'Tiếp tục', stop: 'Dừng', cancel: 'Hủy', analysisControls: 'Điều khiển phân tích',
    runRunning: 'Đang phân tích…', runPausing: 'Sẽ tạm dừng sau lô hiện tại…',
    runPaused: 'Đã tạm dừng — bấm Tiếp tục để chạy tiếp.', runResuming: 'Đang chạy tiếp…',
    runStopping: 'Sẽ dừng sau lô hiện tại…',
    runStopped: 'Đã dừng — giữ kết quả một phần.',
    runStoppedNoResults: 'Đã dừng trước khi có tệp nào xong — không có kết quả.',
    runCancelled: 'Đã hủy phân tích — kết quả bị bỏ.',
    batchTimeout: 'Lô quá thời gian nên đã bị hủy — giữ kết quả một phần.',
    pfRejected: 'tệp bị kiểm tra trước loại bỏ:',
    pfBadExt: 'phần mở rộng không hỗ trợ (cho phép: .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost)',
    pfEmpty: 'tệp rỗng (0 byte)',
    pfTooLarge: 'lớn hơn 25 MB',
    pfPstTooLarge: 'PST/OST lớn hơn 500 MB',
    pfDupe: 'trùng — đã có trong danh sách',
    pfReady: 'kiểm tra trước đạt, sẵn sàng phân tích',
    pfNoneLeft: 'không còn tệp hợp lệ để phân tích',
    stepUpload: 'Tải lên lô',

    stepValidate: 'Kiểm tra', stepProcess: 'Sao chép & băm bằng chứng → Phân tích cú pháp → Phân tích', stepScore: 'Điểm',
    score: 'Điểm rủi ro', authResults: 'Kết quả xác thực', present: 'có', missing: 'không có (chưa xác thực)',
    findings: 'Phát hiện', attachments: 'Tệp đính kèm', originIps: 'IP nguồn khả nghi',
    report: 'Báo cáo', shown: 'Chỉ hiển thị 300 phát hiện đầu tiên.', noFindings: 'Không phát hiện dấu hiệu đáng ngờ.',
    v_clean: 'Sạch', v_suspicious: 'Đáng ngờ', v_malicious_or_phishing: 'Độc hại hoặc lừa đảo', v_unverified: 'Chưa xác thực',

    ft_from_returnpath_mismatch: 'Tên miền From / Return-Path không khớp',
    ft_from_replyto_mismatch: 'Tên miền From / Reply-To không khớp',
    ft_spf_alignment_mismatch: 'Tên miền SPF không khớp với From',
    ft_dkim_alignment_mismatch: 'Tên miền DKIM không khớp với From',
    ft_spf_fail: 'SPF thất bại', ft_spf_softfail: 'SPF soft-fail', ft_spf_neutral: 'SPF trung lập',
    ft_spf_none: 'SPF không có kết quả', ft_spf_permerror: 'SPF lỗi vĩnh viễn', ft_spf_temperror: 'SPF lỗi tạm thời',
    ft_dkim_fail: 'DKIM thất bại', ft_dkim_none: 'DKIM không có kết quả', ft_dkim_policy: 'DKIM policy',
    ft_dmarc_fail: 'DMARC thất bại', ft_dmarc_none: 'DMARC không có kết quả',
    ft_spf_missing: 'Không có kết quả SPF trong header', ft_dkim_missing: 'Không có kết quả DKIM trong header', ft_dmarc_missing: 'Không có kết quả DMARC trong header',
    ft_origin_ip_candidates: 'IP công khai trong header Received',
    ft_link_text_mismatch: 'Chữ hiển thị của liên kết khác đích thật',
    ft_ip_host_link: 'Liên kết trỏ tới địa chỉ IP',
    ft_punycode_domain: 'Tên miền Punycode (giả mạo)',
    ft_dangerous_attachment: 'Tệp đính kèm nguy hiểm',
    ft_double_extension: 'Phần mở rộng kép',
    ft_phishing_url: 'URL lừa đảo', ft_suspicious_url: 'URL đáng ngờ',
    ft_url_blocklisted: 'URL có trong danh sách đe dọa',
    ft_ml_phishing: 'Phán đoán mô hình ML', ft_llm_suspicious: 'Đánh giá ngữ nghĩa bằng LLM',
    ft_suspicious_attachment: 'Tệp đính kèm đáng ngờ',
    threats: 'URL & tệp đính kèm nguy hiểm', iocCount: 'IOC',
    urlLabel: 'URL', hostLabel: 'Host', riskLabel: 'Mức rủi ro', reasonsLabel: 'Lý do',
    a_clean: 'sạch', a_suspicious: 'đáng ngờ', a_malicious: 'ĐỘC HẠI',
    exportSiem: 'Xuất SIEM',
    ft_message_id_mismatch: 'Tên miền Message-ID không khớp',
    ft_duplicate_headers: 'Header bị lặp',
    ft_missing_header: 'Thiếu header',
    ft_date_skew: 'Lệch giờ Date / Received',
    ft_display_name_spoof: 'Giả mạo tên hiển thị',
    ft_x_originating_ip: 'Tiết lộ IP người gửi (X-Originating-IP)',
    ft_hop_delay: 'Một hop trễ bất thường',
    ft_hop_negative_delay: 'Hop có mốc thời gian ngược',
    ft_hop_loop: 'Vòng lặp định tuyến',
    ft_hop_missing_from: 'Hop thiếu mệnh đề from',
    ft_private_ip_hop: 'IP riêng tư trong hop',
    forensics: 'Phân tích header & đường truyền',
    authEnvelope: 'Envelope / IP client', receivedCount: 'Số header Received',
    totalTransit: 'Tổng thời gian', headerChecks: 'Kiểm tra header & định tuyến',
    hopFrom: 'Từ', gatewayLabel: 'Gateway', hopDelay: 'Trễ', hopTime: 'Mốc thời gian',

    e_too_large: 'Tệp quá lớn (tối đa 25 MB mỗi tệp thư, 500 MB cho PST/OST).',
    e_format_mismatch: 'Nội dung tệp không khớp với phần mở rộng.',
    e_file: 'Định dạng không hỗ trợ. Dùng .eml .msg .mbox .emlx .mht .mhtml .txt .pst .ost.',
    e_parse: 'Không thể phân tích tệp email này.',
    e_readpst_missing: 'PST/OST cần công cụ readpst (Linux: apt install pst-utils, hoặc dùng Docker).',
    e_pst_timeout: 'Trích xuất PST/OST quá thời gian.',
    e_readpst_failed: 'Không đọc được PST/OST (hỏng, mã hóa hoặc không hỗ trợ).',
    e_bad_msg: 'Tệp Outlook .msg không hợp lệ.',
    e_bad_emlx: 'Tệp Apple .emlx không hợp lệ.',
    e_empty: 'Không tìm thấy email nào trong tệp.',
    e_upload: 'Tải lên thất bại — kiểm tra tệp và thử lại.',
    e_rate: 'Quá nhiều yêu cầu — hãy đợi một phút rồi thử lại.',
    e_bad_json: 'Yêu cầu không hợp lệ.',
    e_server: 'Lỗi máy chủ — xem log máy chủ.',
    e_auth: 'Phiên đã hết hạn — vui lòng đăng nhập lại.',
    e_csrf: 'Phiên đã hết hạn — vui lòng đăng nhập lại.',
    e_not_found: 'Không tìm thấy endpoint (lệch phiên bản server/client).',
    e_unknown: 'Lỗi: '
  }
};

const t = k => (I18N[lang] && I18N[lang][k]) ?? I18N.en[k] ?? k;
const verdictText = v => t('v_' + v);
const assessText = v => { const k = 'a_' + v, s = t(k); return s === k ? v : s; };
const serverText = k => { const key = 'st_' + k, s = t(key); return s === key ? k : s; };
const typeText = ty => { const k = 'ft_' + ty, s = t(k); return s === k ? ty : s; };
const errText = code => (code && (I18N[lang]['e_' + code] || I18N.en['e_' + code])) || (t('e_unknown') + (code || 'unknown'));
// Error code of an API response. The server answers flat {"error":"code"}; the
// helper also understands FastAPI's {"detail":{"error":"code"}} shape so a
// single code path works for both.
const apiCode = j => {
  if (!j) return '';
  if (typeof j.error === 'string') return j.error;
  if (j.error && typeof j.error === 'object') return j.error.code || j.error.error || '';
  const d = j.detail;
  if (typeof d === 'string') return d;
  if (d && typeof d === 'object') return d.error || d.code || '';
  return '';
};
const toolErr = code => {
  const k = 'dnsErr_' + code;
  return (I18N[lang] && I18N[lang][k]) || I18N.en[k] || t('dnsFailed') + (code || 'unknown');
};
const fmtDate = d => {
  if (!d) return '—';
  const x = new Date(d);
  return Number.isNaN(x.getTime()) ? String(d) : x.toLocaleString(lang === 'vi' ? 'vi-VN' : 'en-GB', { hour12: false });
};
const escText = s => String(s ?? '');

const api = (p, o = {}) => fetch(p, { ...o, headers: { ...(o.headers || {}), 'x-csrf': csrf } });
const step = txt => { const d = document.createElement('div'); d.textContent = '✔ ' + txt; $('prog').append(d); };
const compactMode = () => { const c = $('aicompact'); return c ? c.checked : true; };
const setProgress = (pct, running = false) => {
  const wrap = $('progBarWrap'); const bar = $('progBar'); const fill = $('progFill'); const lab = $('progPct');
  if (!wrap || !fill) return;
  const v = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
  wrap.hidden = false;
  fill.style.width = v + '%';
  if (bar) { bar.setAttribute('aria-valuenow', String(v)); bar.classList.toggle('running', !!running); }
  if (lab) lab.textContent = v + '%';
};
const hideProgress = () => { const wrap = $('progBarWrap'); if (wrap) wrap.hidden = true; };
const filterCompactText = src => {
  const s = String(src || '');
  const lines = s.split('\n').filter(ln => {
    const x = ln.trim();
    if (!x) return false;
    if (/^(null|undefined|—|-+\s*)$/i.test(x)) return false;
    if (/:\s*(null|undefined|—|~|\[\]|\{\})\s*$/i.test(x)) return false;
    if (/\bnull\b|\bundefined\b/i.test(x) && x.toLowerCase().includes('null')) return false;
    return true;
  });
  let out = lines.join('\n');
  out = out.replace(/\n{3,}/g, '\n\n').trim();
  return out || s.trim();
};
const syncModelSel = () => {
  const sel = $('aimodelSel'); const inp = $('aimodel');
  if (!sel || !inp) return;
  const custom = sel.value === '__custom';
  inp.hidden = !custom;
  if (custom) inp.focus();
};
const currentModel = () => {
  const sel = $('aimodelSel'); const inp = $('aimodel');
  if (sel && sel.value === '__custom') return (inp?.value || '').trim();
  return sel ? sel.value.trim() : (inp?.value || '').trim();
};

const el = (tag, cls = '', text = null) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== null) e.textContent = text;
  return e;
};
const badge = (text, kind = '') => el('span', 'badge ' + kind, text);
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
const addKV = (dl, label, value) => {
  const empty = value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length) || value === '—';
  if (empty && compactMode()) return;
  if (empty) { dl.append(el('dt', '', label), el('dd', '', '—')); return; }
  dl.append(el('dt', '', label), el('dd', '', String(value)));
};
const bodyCache = new Map();

function renderAuthDetails(auth) {
  const box = el('div', 'authbox');
  if (!auth?.headerFound) {
    box.append(el('p', 'hint', t('missing')));
    return box;
  }
  const dl = el('dl', 'kv');
  addKV(dl, t('authservLabel'), auth.authservId);
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
  if (sigs.length > 1) {
    addKV(dl, t('dkimSignaturesLabel'), sigs.map(s => `${s.domain || '?'}/${s.selector || '?'}=${s.result || '?'}`).join(', '));
  }
  box.append(dl);
  if (auth.raw) {
    const det = el('details');
    det.append(el('summary', '', t('authHeaderLabel')), el('pre', 'rawtext', auth.raw));
    box.append(det);
  }
  return box;
}

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

    if (msg.received?.length) {
      const det = el('details');
      det.append(el('summary', '', 'Received'), el('pre', 'rawtext', msg.received.join('\n\n')));
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


function renderEnrichment(out, r) {
  const dnsEntries = Object.entries(r?.dns || {});
  if (dnsEntries.length) {
    out.append(el('h4', '', t('senderDns')), el('p', 'hint', t('dnsExplain')));
    for (const [domain, d] of dnsEntries) {
      const s = el('section', 'toolcard');
      const head = el('div', 'toolhead');
      head.append(el('h5', '', domain));
      if (d.assessment) head.append(badge(assessText(d.assessment.verdict), d.assessment.verdict === 'authentic' ? 'ok' : d.assessment.verdict === 'spoofed' ? 'bad' : 'warn'));
      if (d.mxtoolbox) head.append(badge(t('mxtoolbox'), d.mxtoolbox.ok ? (d.mxtoolbox.status === 'ok' ? 'ok' : 'warn') : 'bad'));
      s.append(head);
      const dl = el('dl', 'kv');
      const spf = d.auth?.spf;
      const dmarc = d.auth?.dmarc;
      addKV(dl, 'SPF', spf?.found ? `${spf.raw || (spf.records || []).join(' / ')}${spf.all ? ' · all=' + spf.all : ''}` : t('notFoundLabel'));
      addKV(dl, 'DMARC', dmarc?.found ? `${dmarc.raw || 'found'}${dmarc.policy ? ' · p=' + dmarc.policy : ''}` : t('notFoundLabel'));
      addKV(dl, 'MX', (d.records?.mx || []).map(x => `${x.priority} ${x.exchange}`).join(', ') || t('noRecords'));
      if (d.mxtoolbox) {
        const mxNames = xs => (xs || []).map(x => x.name).filter(Boolean).slice(0, 3).join(', ');
        const bits = [];
        if (d.mxtoolbox.ok) {
          bits.push(d.mxtoolbox.status || 'ok');
          if (d.mxtoolbox.reportingNameServer) bits.push(`NS: ${d.mxtoolbox.reportingNameServer}`);
          if (d.mxtoolbox.summary?.failed?.length) bits.push(`${d.mxtoolbox.summary.failed.length} failed${mxNames(d.mxtoolbox.summary.failed) ? ' (' + mxNames(d.mxtoolbox.summary.failed) + ')' : ''}`);
          if (d.mxtoolbox.summary?.warnings?.length) bits.push(`${d.mxtoolbox.summary.warnings.length} warnings${mxNames(d.mxtoolbox.summary.warnings) ? ' (' + mxNames(d.mxtoolbox.summary.warnings) + ')' : ''}`);
        } else {
          bits.push(`${d.mxtoolbox.error}${d.mxtoolbox.message ? ': ' + d.mxtoolbox.message : ''}`);
        }
        addKV(dl, t('mxtoolbox'), bits.join(' · '));
      }
      if (d.assessment?.reasons?.length) addKV(dl, t('dnsAssessment'), d.assessment.reasons.join('; '));
      if (d.errors?.length) addKV(dl, t('warningsLabel'), d.errors.map(e => `${e.code}: ${e.message}`).join('; '));
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
      const confTd = el('td', conf == null ? '' : (conf >= 70 ? 'confhi' : conf >= 40 ? 'confmed' : 'conflo'), conf == null ? '—' : conf + '%');
      tr.append(
        el('td', '', String(n + 1)),
        el('td', '', x.ip),
        el('td', '', loc?.latitude != null ? `${loc.latitude}, ${loc.longitude}` : '—'),
        el('td', '', x.geo?.countryIso ? `${x.geo.country || ''} (${x.geo.countryIso})` : (x.geo?.country || '—')),
        el('td', '', x.geo?.city || '—'),
        el('td', '', x.geo?.asn ? `AS${x.geo.asn}` : '—'),
        el('td', '', x.geo?.organization || '—'),
        el('td', '', (x.ptr || []).join(', ') || '—'),
        el('td', '', x.server ? `${serverText(x.server.key)}${x.server.evidence ? ' — ' + x.server.evidence : ''}` : '—'),
        el('td', '', x.assessment ? `${assessText(x.assessment.verdict)}${x.assessment.reasons?.length ? ' — ' + x.assessment.reasons.join('; ') : ''}` : '—'),
        confTd
      );
      table.append(tr);
    });
    out.append(table, el('p', 'hint', t('approxLabel')));
  }
}

function applyLang() {
  document.documentElement.lang = lang;
  document.title = t('title');
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-aria]').forEach(el => { el.setAttribute('aria-label', t(el.dataset.i18nAria)); });
  document.querySelectorAll('[data-i18n-g]').forEach(el => { try { el.label = t(el.dataset.i18nG); } catch {} });
  syncModelSel();
  if ($('lang').value !== lang) $('lang').value = lang;
  const flag = $('langFlag');
  if (flag) flag.className = 'flag-icon ' + lang;
  renderWho();
  if (lastDns) paintDns(lastDns.source, lastDns.data);
  if (lastIp) paintIp(lastIp);
  if (profileData) renderProfile();
  if (sessionExpires) renderSessionTimer();
  if (logsLoaded) renderLogs();
  if (histLoaded) renderHistory(histCases);
  renderPick();
  if (lastResults.length) {
    $('prog').textContent = '';
    step(t('stepValidate')); step(t('stepProcess')); step(t('stepScore') + ': ' + last.score + '/100');
    renderAllResults(lastResults, lastErrors);
  }
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
    const extra = res === 'fail' && a?.policy ? ` (p=${a.policy})` : '';
    badges.append(badge(`${label}: ${res}${extra}`, kind), ' ');
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
    const det = el('details', '');
    const sum = el('summary', '', `${t('headerChecks')} (${checks.length})`);
    det.append(sum);
    for (const f of checks.slice(0, 60)) {
      det.append(el('div', 'f s' + (f.sev ?? 0) + (f.weight === 0 ? ' info' : ''), `${f.id || ''} ${typeText(f.type)}: ${f.evidence}`));
    }
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
        el('td', '', h.by || '—'),
        el('td', '', h.with || '—'),
        el('td', '', h.gateway || '—'),
        el('td', '', h.delayMs != null ? h.delayMs + ' ms' : '—'),
        el('td', '', h.ts || '—'));
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
  if (Object.keys(c).length) {
    head.append(badge(t('iocCount') + ': ' + Object.entries(c).map(([k, v]) => k + ' ' + v).join(', '), 'warn'));
  }
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
        el('td', '', u.url.length > 80 ? u.url.slice(0, 80) + '…' : u.url),
        el('td', '', u.host || '—'),
        el('td', '', u.risk + '% — ' + (t('a_' + u.verdict) || u.verdict)),
        el('td', '', (u.reasons || []).join('; ') || '—'));
      table.append(tr);
    });
    sec.append(table);
  }
  out.append(sec);
}

function renderAllResults(results, errors = []) {
  const out = $('out');
  out.textContent = '';
  if (!results.length) {
    if (errors.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      errors.forEach(e => box.append(el('div', '', `${e.file}: ${errText(e.error)}`)));
      out.append(box);
    }
    return;
  }
  if (results.length === 1) {
    renderResult(out, results[0]);
  } else {
    results.forEach((r, i) => {
      const block = el('section', 'caseblock');
      block.append(el('h3', '', `${i + 1}. ${r.custody?.original || ''}`));
      const body = el('div', 'casebody');
      block.append(body);
      out.append(block);
      renderResult(body, r);
    });
  }
  if (errors.length) {
    const box = el('div', 'f s2');
    box.append(el('strong', '', t('uploadErrors')));
    errors.forEach(e => box.append(el('div', '', `${e.file}: ${errText(e.error)}`)));
    out.append(box);
  }
}

function renderResult(out, r) {
  if (!out || !r) return;

  const h = document.createElement('h3');
  h.textContent = `${r.format.toUpperCase()} × ${r.count}${r.truncated ? '+' : ''} — ${verdictText(r.verdict)} (${t('score')}: ${r.score}/100)`;
  out.append(h);

  const meta = document.createElement('p');
  meta.className = 'summary';
  meta.textContent = `${r.custody.original} · ${t('authResults')}: ${r.authSeen ? t('present') : t('missing')} · SHA-256 ${r.custody.sha256}`;
  out.append(meta);

  if (r.originIPs?.length) {
    const p = document.createElement('p');
    p.className = 'summary';
    p.textContent = `${t('originIps')}: ${r.originIPs.join(', ')}`;
    out.append(p);
  }

  renderForensics(out, r);
  renderThreats(out, r);
  renderEnrichment(out, r);
  renderMessages(out, r);

  const fh = document.createElement('h4');
  fh.textContent = `${t('findings')} (${r.findings.length})`;
  out.append(fh);

  if (!r.findings.length) {
    const d = document.createElement('div');
    d.className = 'f s0';
    d.textContent = t('noFindings');
    out.append(d);
  }
  for (const f of r.findings.slice(0, 300)) {
    const d = document.createElement('div');
    d.className = 'f s' + f.sev + (f.weight === 0 ? ' info' : '');
    d.textContent = `${r.count > 1 ? '#' + (f.m + 1) + ' ' : ''}${typeText(f.type)}: ${f.evidence}`;
    out.append(d);
  }
  if (r.findings.length > 300) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = t('shown');
    out.append(p);
  }

  if (r.attachments?.length) {
    const det = document.createElement('details');
    const sum = document.createElement('summary');
    sum.textContent = `${t('attachments')} (${r.attachments.length})`;
    det.append(sum);
    const ul = document.createElement('ul');
    ul.className = 'att';
    for (const a of r.attachments.slice(0, 200)) {
      const li = document.createElement('li');
      li.textContent = `${a.m !== undefined ? '#' + (a.m + 1) + ' ' : ''}${a.name} — ${a.size} B — ${a.sha256}${a.magic && a.magic !== 'unknown' ? ' — ' + a.magic : ''}`;
      if (a.verdict && a.verdict !== 'clean') {
        li.append(' — ', badge(t('a_' + a.verdict) || a.verdict, a.verdict === 'malicious' ? 'bad' : 'warn'));
        if (a.reasons?.length) li.title = a.reasons.join('; ');
      }
      ul.append(li);
    }
    det.append(ul);
    out.append(det);
  }

  const bar = document.createElement('div');
  bar.className = 'reportbar';
  const siemSel = document.createElement('select');
  siemSel.className = 'siemsel';
  for (const [v, label] of [['cef', 'CEF (Wazuh)'], ['syslog', 'Syslog 5424'], ['ecs', 'ECS (Elastic)'], ['elastic', 'Elastic _bulk'], ['splunk', 'Splunk HEC'], ['stix', 'STIX 2.1']]) {
    const o = document.createElement('option'); o.value = v; o.textContent = label; siemSel.append(o);
  }
  const siemBtn = document.createElement('button');
  siemBtn.type = 'button';
  siemBtn.textContent = t('exportSiem');
  siemBtn.onclick = async () => {
    try {
      const x = await api(`/api/export/${r.custody.caseId}?format=${siemSel.value}`);
      if (!x.ok) throw new Error(String(x.status));
      const u = URL.createObjectURL(await x.blob());
      const a = document.createElement('a');
      a.href = u; a.download = `mailsleuth-${r.custody.caseId}.${siemSel.value === 'syslog' ? 'syslog' : siemSel.value}`; a.click();
      setTimeout(() => URL.revokeObjectURL(u), 1000);
    } catch (e) {
      const d = document.createElement('div');
      d.className = 'f s3';
      d.textContent = t('reportFailed') + e.message;
      out.append(d);
    }
  };
  bar.append(siemSel, siemBtn);
  for (const l of ['en', 'vi']) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = `${t('report')} ${l.toUpperCase()}`;
    b.onclick = async () => {
      try {
        const x = await api(`/api/report/${r.custody.caseId}?lang=${l}`);
        if (!x.ok) throw new Error((await x.json().catch(() => ({}))).error || x.status);
        const u = URL.createObjectURL(await x.blob());
        const a = document.createElement('a');
        a.href = u; a.download = `report-${l}.html`; a.click();
        setTimeout(() => URL.revokeObjectURL(u), 1000);
      } catch (e) {
        const d = document.createElement('div');
        d.className = 'f s3';
        d.textContent = t('reportFailed') + e.message;
        out.append(d);
      }
    };
    bar.append(b);
  }
  out.append(bar);
}

function renderProfile() {
  if (!profileData) return;
  const p = profileData;
  $('profileMeta').textContent = `${p.user} · ${t('profileRole')}: ${p.role} · ${t('profileCreated')}: ${fmtDate(p.created)}`;
  $('loginMs').textContent = lastLoginMs ? `${t('loginTime')}: ${lastLoginMs} ms` : '';
  const src = p.hasAvatar ? `/api/profile/avatar?v=${encodeURIComponent(p.avatarUpdated || '')}` : '';
  for (const id of ['avatarSm', 'avatarBig']) {
    const img = $(id);
    if (src) { img.src = src; img.hidden = false; } else { img.removeAttribute('src'); img.hidden = true; }
  }
  // No picture yet -> show the first letter of the account name instead of an
  // empty placeholder box.
  const initial = (String(p.user || '?').trim().charAt(0) || '?').toUpperCase();
  for (const id of ['avatarSmMono', 'avatarBigMono']) {
    const el = $(id);
    if (!el) continue;
    if (src) { el.hidden = true; el.textContent = ''; }
    else { el.textContent = initial; el.hidden = false; }
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
    if (r.status === 401 && apiCode(j) === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
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
    if (r.status === 403 || code === 'csrf') { leaveApp(); $('err').textContent = t('e_csrf'); return; }
    if (!r.ok) {
      $('avatarMsg').textContent = code === 'avatar_too_large' ? t('avatarTooLarge')
        : code === 'bad_avatar' ? t('avatarBad')
          : code === 'rate' ? t('errRate')
            : code === 'forbidden' ? t('e_auth')
              : t('avatarFailed');
      return;
    }
    $('avatarFile').value = '';
    $('avatarMsg').textContent = t('avatarOk');
    await loadProfile();
  } catch (e) {
    $('avatarMsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

function renderLogs() {
  const logsOut = $('logsOut'), sessionsOut = $('sessionsOut');
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
      tr.append(
        el('td', '', fmtDate(x.ended)),
        el('td', '', x.user || '—'),
        el('td', '', x.role || '—'),
        el('td', '', x.reason || ''),
        el('td', '', x.started && x.ended ? x.ended - x.started : '—'),
        el('td', 'hashcell', x.sha256 || ''),
        el('td', 'hashcell', x.prev_hash || '—')
      );
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
    if (!a.ok) { $('logsMsg').textContent = t('logsLoadFailed') + errText(ja.error || a.status); return; }
    if (!b.ok) { $('logsMsg').textContent = t('logsLoadFailed') + errText(jb.error || b.status); return; }
    logsData = Array.isArray(ja) ? ja : [];
    sessionsData = Array.isArray(jb) ? jb : [];
    logsLoaded = true;
    renderLogs();
  } catch (e) {
    $('logsMsg').textContent = t('logsLoadFailed') + e.message;
  } finally { logsLoading = false; }
}

function renderWho() {
  const line = user ? t('signedIn') + user : '';
  if ($('who')) $('who').textContent = line;
  if ($('accountName')) $('accountName').textContent = user || '';
}

function showAuth(view) {
  $('loginForm').hidden = view !== 'login';
  $('reg').hidden = view !== 'reg';
  $('rec').hidden = view !== 'rec';
  $('err').textContent = '';
  $('nmsg').textContent = '';
  $('rmsg').textContent = '';
  $('rmsg').className = '';
}

function showKey(key) {
  if (!key) return;
  $('keyval').textContent = key;
  $('keymsg').textContent = '';
  $('keybox').hidden = false;
}

// MapGlot key (IP / Geo tab, any signed-in account): the server stores it
// per user in its kv table and never sends it back — the UI only ever sees
// presence + source (own key / server-wide key / environment) and, when the
// last reverse attempt failed, an actionable error hint.
const mapKeyText = d => {
  if (!d || !d.hasKey) return t('mapKeyStatusNone');
  const base = d.source === 'user' ? t('mapKeyStatusOwn')
    : d.source === 'server' ? t('mapKeyStatusServer') : t('mapKeyStatusEnv');
  const code = { unverified: 'mapKeyErrUnverified', invalid: 'mapKeyErrInvalid', quota: 'mapKeyErrQuota', unavailable: 'mapKeyErrUnavail' }[d.error];
  return code ? base + ' ' + t(code) : base;
};

async function loadMapKeyStatus() {
  try {
    const r = await api('/api/settings/map');
    if (!r.ok) throw new Error('status');
    $('mapkeyMsg').textContent = mapKeyText(await r.json());
  } catch { $('mapkeyMsg').textContent = ''; }
}

async function saveMapKey(clear) {
  const btn = $(clear ? 'mapkeyClear' : 'mapkeySave');
  btn.disabled = true;
  try {
    const r = await api('/api/settings/map', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: clear ? '' : $('mapkey').value.trim() })
    });
    const d = await r.json().catch(() => null);
    if (!r.ok || !d) { $('mapkeyMsg').textContent = t('mapKeyErr'); return; }
    if (!clear) $('mapkey').value = '';
    $('mapkeyMsg').textContent = mapKeyText(d);
  } catch { $('mapkeyMsg').textContent = t('mapKeyErr'); }
  finally { btn.disabled = false; }
}

function enterApp(j) {
  csrf = j.csrf || '';
  user = j.user || '';
  $('login').hidden = true;
  $('app').hidden = false;
  $('accountBar').hidden = false;
  $('p').value = '';
  $('aikey').value = store.get('aikey:' + user);
  {
    const sel = $('aimodelSel'); const inp = $('aimodel');
    const saved = store.get('aimodel:' + user);
    if (sel && saved) {
      const has = [...sel.options].some(o => o.value === saved);
      if (has) { sel.value = saved; if (inp) inp.value = ''; }
      else { sel.value = '__custom'; if (inp) inp.value = saved; }
    }
    syncModelSel();
  }
  $('mxkey').value = store.get('mxkey:' + user);
  lastLoginMs = Number(j.loginMs) || 0;
  profileData = null;
  histLoaded = false; histCases = [];
  logsLoaded = false; logsData = []; sessionsData = [];
  $('histOut').textContent = ''; $('histMsg').textContent = '';
  $('logsOut').textContent = ''; $('sessionsOut').textContent = ''; $('logsMsg').textContent = '';
  const admin = j.role === 'admin';
  $('tabLogs').hidden = !admin;
  // MapGlot key row: every account manages its own key (per-user storage).
  $('mapKeyRow').hidden = false;
  $('mapKeyHint').hidden = false;
  loadMapKeyStatus();
  if (!admin && !$('paneLogs').hidden) switchTab('tabAnalysis');
  renderWho();
  startSessionTimer(j.expiresAt);
  loadProfile();
}

function leaveApp() {
  csrf = ''; user = '';
  if (job) { job.cancelled = true; try { job.ac?.abort(); } catch {} job = null; }
  last = null; lastResults = []; lastErrors = [];
  clearInterval(sessionTimerId); sessionTimerId = null; sessionExpires = 0; lastLoginMs = 0;
  profileData = null;
  histLoaded = false; histCases = [];
  logsLoaded = false; logsData = []; sessionsData = [];
  $('app').hidden = true;
  $('login').hidden = false;
  $('accountBar').hidden = true;
  $('accountMenu').open = false;
  $('keybox').hidden = true;
  $('f').value = ''; $('fdir').value = '';
  picked = []; pfRejected = []; setRunState(''); renderPick();
  $('prog').textContent = '';
  $('out').textContent = '';
  $('aiout').textContent = '';
  $('po').value = ''; $('pn').value = ''; $('pmsg').textContent = '';
  $('mxkey').value = '';
  lastDns = null; lastIp = null;
  $('dnsDomain').value = ''; $('dnsOut').textContent = ''; $('dnsMsg').textContent = '';
  $('ipAddr').value = ''; $('ipOut').textContent = ''; $('ipMsg').textContent = '';
  $('histQ').value = ''; $('histOut').textContent = ''; $('histMsg').textContent = '';
  $('logsOut').textContent = ''; $('sessionsOut').textContent = ''; $('logsMsg').textContent = '';
  $('tabLogs').hidden = true;
  $('mapKeyRow').hidden = true; $('mapKeyHint').hidden = true;
  $('mapkey').value = ''; $('mapkeyMsg').textContent = '';
  $('avatarMsg').textContent = ''; $('avatarFile').value = '';
  for (const id of ['avatarSm', 'avatarBig']) { $(id).hidden = true; $(id).removeAttribute('src'); }
  for (const id of ['avatarSmMono', 'avatarBigMono']) { const el = $(id); if (el) { el.hidden = true; el.textContent = ''; } }
  showAuth('login');
}

async function login() {
  $('err').textContent = '';
  const btn = $('go');
  btn.disabled = true;
  const started = Date.now();
  const timer = setInterval(() => {
    btn.textContent = `${t('loggingIn')} ${((Date.now() - started) / 1000).toFixed(1)}s`;
  }, 100);
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
      body: JSON.stringify({ user: $('nu').value.trim(), pass: p1 })
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 429) $('nmsg').textContent = t('errRate');
    else if (apiCode(j) === 'exists') $('nmsg').textContent = t('errExists');
    else if (apiCode(j) === 'bad_user') $('nmsg').textContent = t('errBadUser');
    else if (apiCode(j) === 'weak') $('nmsg').textContent = t('errWeak');
    else if (apiCode(j) === 'disabled') $('nmsg').textContent = t('errDisabled');
    else if (!r.ok) $('nmsg').textContent = t('errRegister');
    else {
      $('nu').value = ''; $('np').value = ''; $('np2').value = '';
      showAuth('login');
      enterApp(j);
      showKey(j.recoveryKey);
    }
  } catch (e) {
    $('nmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
}

$('go').onclick = login;
$('ngo').onclick = register;
for (const id of ['u', 'p']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
for (const id of ['nu', 'np', 'np2']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') register(); });

$('showReg').onclick = e => { e.preventDefault(); showAuth('reg'); $('nu').focus(); };
$('showLogin').onclick = e => { e.preventDefault(); showAuth('login'); $('u').focus(); };
$('recBack').onclick = e => { e.preventDefault(); showAuth('login'); };
$('forgot').onclick = e => { e.preventDefault(); showAuth('rec'); $('ru').focus(); };

$('keycopy').onclick = async () => {
  const key = $('keyval').textContent;
  try { await navigator.clipboard.writeText(key); $('keymsg').textContent = t('copied'); }
  catch { $('keymsg').textContent = t('copyFailed'); }
};
$('keyok').onclick = () => { $('keybox').hidden = true; };

$('rgo').onclick = async () => {
  $('rmsg').textContent = '';
  $('rmsg').className = '';
  const btn = $('rgo');
  btn.disabled = true;
  try {
    const r = await fetch('/api/recover', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: $('ru').value.trim(), key: $('rk').value, pass: $('rp').value })
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 429) $('rmsg').textContent = t('errRate');
    else if (apiCode(j) === 'weak') $('rmsg').textContent = t('errWeak');
    else if (!r.ok) $('rmsg').textContent = t('errRecover');
    else {
      $('rmsg').textContent = t('recOk');
      $('rmsg').className = 'ok';
      $('rk').value = ''; $('rp').value = '';
      showKey(j.newKey);
    }
  } catch (e) {
    $('rmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
};
for (const id of ['ru', 'rk', 'rp']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') $('rgo').click(); });

$('logout').onclick = async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch {}
  location.reload();
};

$('pgo').onclick = async () => {
  $('pmsg').textContent = '';
  const btn = $('pgo');
  btn.disabled = true;
  try {
    const r = await api('/api/password', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ old: $('po').value, pass: $('pn').value })
    });
    const j = await r.json().catch(() => ({}));
    const pcode = apiCode(j);
    if (r.status === 401 || pcode === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (r.status === 403 || pcode === 'csrf') { leaveApp(); $('err').textContent = t('e_csrf'); return; }
    $('pmsg').textContent = r.ok ? t('passOk')
      : pcode === 'weak' ? t('errWeak')
      : r.status === 429 ? t('errRate')
      : t('passBad');
    if (r.ok) { $('po').value = ''; $('pn').value = ''; }
  } catch (e) {
    $('pmsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
};

// ===== tabs: analysis / DNS / IP =====
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
  };
});

// ---------- trust & AI (reputation keys, LLM key, server status) ----------
async function loadTrustStatus() {
  try {
    const r = await api('/api/settings/reputation');
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
      const k = j.keys || {};
      $('repAbuseKey').value = (k.abusech && k.abusech.hasKey) ? '••••••••' : '';
      $('repVtKey').value = (k.vt && k.vt.hasKey) ? '••••••••' : '';
      $('repSbKey').value = (k.sb && k.sb.hasKey) ? '••••••••' : '';
      $('trustState').textContent = t('trustStateOn') + ': ' + (j.enabled ? t('trustEnabled') : t('trustDisabled'));
    }
  } catch {}
  try {
    const h = await api('/api/health?deep=1');
    const hj = await h.json().catch(() => ({}));
    if (hj.ml) $('trustState').textContent += ' · ML: ' + (hj.ml.state || 'absent');
    if (hj.llm) $('trustState').textContent += ' · LLM: ' + (hj.llm.state || 'off');
  } catch {}
}
$('trustSave').onclick = async () => {
  const btn = $('trustSave');
  btn.disabled = true;
  $('trustMsg').textContent = t('saving');
  const body = {};
  for (const [id, name] of [['repAbuseKey', 'abusech'], ['repVtKey', 'vt'], ['repSbKey', 'sb']]) {
    const v = $(id).value.trim();
    if (v && v !== '••••••••') body[name] = v;
  }
  try {
    const r = await api('/api/settings/reputation', { method: 'POST', body: JSON.stringify(body) });
    if (!r.ok) { $('trustMsg').textContent = t('errUpload'); return; }
    $('trustMsg').textContent = t('trustSaved');
    loadTrustStatus();
  } catch (e) {
    $('trustMsg').textContent = t('errNetwork') + e.message;
  } finally { btn.disabled = false; }
};
$('trustClear').onclick = async () => {
  try {
    await api('/api/settings/reputation', { method: 'POST', body: JSON.stringify({ abusech: '', vt: '', sb: '' }) });
  } catch {}
  $('repAbuseKey').value = ''; $('repVtKey').value = ''; $('repSbKey').value = '';
  $('trustMsg').textContent = t('trustCleared');
  loadTrustStatus();
};

function syncToolControls() {
  $('dnsDkimRow').hidden = $('dnsType').value !== 'dkim';
  $('mxRow').hidden = $('dnsSource').value !== 'mxtoolbox';
}
$('dnsType').onchange = syncToolControls;
$('dnsSource').onchange = syncToolControls;
syncToolControls();

const card = title => {
  const s = el('section', 'toolcard');
  if (title) s.append(el('h4', '', title));
  return s;
};
const listCard = (title, values) => {
  if (!values?.length) return null;
  const s = card(title);
  const ul = el('ul');
  values.forEach(v => ul.append(el('li', '', typeof v === 'object' ? JSON.stringify(v) : v)));
  s.append(ul);
  return s;
};
const geoCard = (geo, ptrNames, status, confidence) => {
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
  if (geo.location?.latitude !== null && geo.location?.latitude !== undefined) {
    addKV(dl, t('coordinatesLabel'), `${geo.location.latitude}, ${geo.location.longitude}`);
    addKV(dl, t('accuracyLabel'), geo.location.accuracyRadiusKm != null ? `${geo.location.accuracyRadiusKm} km` : null);
    addKV(dl, t('timezoneLabel'), geo.location.timeZone);
  }
  addKV(dl, t('ptrLabel'), (ptrNames || []).join(', '));
  if (confidence != null) addKV(dl, t('confidenceLabel'), Math.round(Number(confidence)) + '%');
  s.append(dl, el('p', 'hint', t('approxLabel')));
  return s;
};

function renderNativeDNS(d) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge(t('dnsSourceNative'), 'ok'), el('strong', '', `${d.domain} · ${d.type}`), el('span', 'summary', `${d.durationMs ?? '?'} ms`));
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

function renderMx(d) {
  const box = el('div', 'toolresult');
  const head = el('div', 'toolhead');
  head.append(badge(t('mxtoolbox'), d.status === 'ok' ? 'ok' : d.status === 'warning' ? 'warn' : 'bad'),
    el('strong', '', `${d.command} · ${d.argument}`), el('span', 'summary', `${d.durationMs ?? '?'} ms`));
  box.append(head);
  const dl = el('dl', 'kv');
  addKV(dl, t('statusLabel'), d.status);
  addKV(dl, t('reportingNameServer'), d.reportingNameServer);
  addKV(dl, t('durationLabel'), d.timeToComplete ? `${d.timeToComplete} ms` : null);
  addKV(dl, t('keyUsed'), d.keyUsed ? t('yesLabel') : t('keyNotUsed'));
  box.append(dl);
  for (const [key, label] of [['failed', 'failedLabel'], ['warnings', 'warningsLabel'], ['passed', 'passedLabel'], ['timeouts', 'timeoutsLabel']]) {
    const items = d.summary?.[key];
    if (!items?.length) continue;
    const s = card(t(label));
    const ul = el('ul');
    items.forEach(x => ul.append(el('li', '', `${x.name || ''}${x.info ? ': ' + x.info : ''}${x.details?.length ? ' — ' + x.details.join('; ') : ''}`)));
    s.append(ul); box.append(s);
  }
  if (d.information?.length) {
    const s = card(t('informationLabel'));
    const keys = [...new Set(d.information.flatMap(x => Object.keys(x)))].slice(0, 12);
    const table = el('table', 'datatable');
    const htr = el('tr');
    keys.forEach(k => htr.append(el('th', '', k)));
    table.append(htr);
    d.information.forEach(x => {
      const tr = el('tr');
      keys.forEach(k => tr.append(el('td', '', typeof x[k] === 'object' ? JSON.stringify(x[k]) : (x[k] ?? ''))));
      table.append(tr);
    });
    s.append(table); box.append(s);
  }
  if (d.transcript?.length) {
    const det = el('details');
    det.append(el('summary', '', t('transcriptLabel')), el('pre', 'rawtext', JSON.stringify(d.transcript, null, 2)));
    box.append(det);
  }
  if (d.raw) {
    const det = el('details');
    det.append(el('summary', '', t('rawLabel')), el('pre', 'rawtext', JSON.stringify(d.raw, null, 2)));
    box.append(det);
  }
  return box;
}

function paintDns(source, data) {
  $('dnsOut').textContent = '';
  $('dnsOut').append(source === 'mxtoolbox' ? renderMx(data) : renderNativeDNS(data));
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

function renderHistory(cases) {
  const out = $('histOut');
  out.textContent = '';
  if (!cases.length) {
    out.append(el('p', 'hint', t('historyEmpty')));
    return;
  }
  const table = el('table', 'datatable historytable');
  const htr = el('tr');
  [t('historyWhen'), t('historyFile'), t('historyAnalyst'), t('historyMessages'), t('historyVerdict'), t('historyScore'), ''].forEach(x => htr.append(el('th', '', x)));
  table.append(htr);
  for (const c of cases) {
    const tr = el('tr');
    const verdict = c.verdict ? verdictText(c.verdict) : '—';
    const file = el('td', '', c.file || '—');
    file.title = c.id;
    const action = el('td');
    const b = el('button', '', t('historyOpen'));
    b.type = 'button';
    b.onclick = () => openHistoryCase(c.id);
    action.append(b);
    tr.append(
      el('td', '', fmtDate(c.ts)),
      file,
      el('td', '', c.user || '—'),
      el('td', '', c.count ?? '—'),
      el('td', '', verdict),
      el('td', '', c.score ?? '—'),
      action
    );
    table.append(tr);
  }
  out.append(table);
}

async function loadHistory(force = false) {
  if (histLoading || (histLoaded && !force)) return;
  histLoading = true;
  $('histMsg').textContent = '';
  try {
    const q = $('histQ').value.trim();
    const r = await api('/api/cases?limit=100&q=' + encodeURIComponent(q));
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && apiCode(j) === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!r.ok) { $('histMsg').textContent = t('historyLoadFailed') + errText(apiCode(j) || r.status); return; }
    histCases = j.cases || [];
    histLoaded = true;
    renderHistory(histCases);
  } catch (e) {
    $('histMsg').textContent = t('historyLoadFailed') + e.message;
  } finally { histLoading = false; }
}

async function openHistoryCase(id) {
  $('histMsg').textContent = '';
  try {
    const r = await api(`/api/report/${encodeURIComponent(id)}?format=json`);
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && apiCode(j) === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (!r.ok) { $('histMsg').textContent = t('historyLoadFailed') + errText(apiCode(j) || r.status); return; }
    lastResults = [j];
    lastErrors = [];
    last = j;
    lastDns = null; lastIp = null;
    $('dnsOut').textContent = ''; $('ipOut').textContent = '';
    $('prog').textContent = '';
    step(t('historyLoaded'));
    step(t('stepScore') + ': ' + j.score + '/100');
    switchTab('tabAnalysis');
    renderAllResults([j]);
  } catch (e) {
    $('histMsg').textContent = t('historyLoadFailed') + e.message;
  }
}

$('histGo').onclick = () => loadHistory(true);
$('histRefresh').onclick = () => loadHistory(true);
$('histQ').addEventListener('keydown', e => { if (e.key === 'Enter') loadHistory(true); });

async function lookupDns() {
  $('dnsMsg').textContent = '';
  lastDns = null;
  $('dnsOut').textContent = '';
  const domain = $('dnsDomain').value.trim();
  if (!domain) { $('dnsMsg').textContent = t('dnsNeedDomain'); return; }
  const type = $('dnsType').value;
  const source = $('dnsSource').value;
  const selector = $('dnsSelector').value.trim();
  if (type === 'dkim' && !selector) { $('dnsMsg').textContent = t('dnsErr_selector'); return; }
  const btn = $('dnsGo');
  btn.disabled = true;
  try {
    const apiKey = source === 'mxtoolbox' ? $('mxkey').value.trim() : '';
    if (source === 'mxtoolbox') {
      if (apiKey) store.set('mxkey:' + user, apiKey); else store.del('mxkey:' + user);
    }
    const r = await api('/api/dns', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source, type, domain, selector, apiKey })
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 || apiCode(j) === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (r.status === 403 || apiCode(j) === 'csrf') { leaveApp(); $('err').textContent = t('e_csrf'); return; }
    if (!r.ok) {
      $('dnsMsg').textContent = toolErr(apiCode(j) || r.status) + (j.message ? ' — ' + j.message : '');
      return;
    }
    lastDns = { source, data: j };
    paintDns(source, j);
  } catch (e) {
    $('dnsMsg').textContent = t('dnsFailed') + e.message;
  } finally { btn.disabled = false; }
}

async function lookupIp() {
  $('ipMsg').textContent = '';
  lastIp = null;
  $('ipOut').textContent = '';
  const ip = $('ipAddr').value.trim();
  if (!ip) { $('ipMsg').textContent = t('ipNeed'); return; }
  const btn = $('ipGo');
  btn.disabled = true;
  try {
    const r = await api('/api/ip', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip })
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 || apiCode(j) === 'auth') { leaveApp(); $('err').textContent = t('e_auth'); return; }
    if (r.status === 403 || apiCode(j) === 'csrf') { leaveApp(); $('err').textContent = t('e_csrf'); return; }
    if (!r.ok) { $('ipMsg').textContent = toolErr(apiCode(j) || r.status); return; }
    lastIp = j;
    paintIp(j);
  } catch (e) {
    $('ipMsg').textContent = t('dnsFailed') + e.message;
  } finally { btn.disabled = false; }
}

$('dnsGo').onclick = lookupDns;
$('dnsDomain').addEventListener('keydown', e => { if (e.key === 'Enter') lookupDns(); });
$('dnsSelector').addEventListener('keydown', e => { if (e.key === 'Enter') lookupDns(); });
$('ipGo').onclick = lookupIp;
$('ipAddr').addEventListener('keydown', e => { if (e.key === 'Enter') lookupIp(); });
$('mxforget').onclick = () => {
  store.del('mxkey:' + user);
  store.del('mxkey');
  $('mxkey').value = '';
  $('dnsMsg').textContent = t('dnsKeyForgotten');
};
$('avatarUpload').onclick = uploadAvatar;
$('logsRefresh').onclick = () => loadLogs(true);


// ===== file picking: multi-file, folders, drag & drop, batched upload =====
const PICK_MAX = 10; // must stay <= the server's per-request limit
const PICK_TOTAL_MAX = 100; // hard cap for one analysis run (10 batches)
const PICK_FILE_MAX = 25 * 1024 * 1024; // server rejects message files above 25 MB
const PICK_PST_MAX = 500 * 1024 * 1024; // PST/OST containers get a separate cap
const OK_EXT = /\.(eml|msg|mbox|emlx|mht|mhtml|txt|pst|ost)$/i;
const PST_EXT = /\.(pst|ost)$/i;
let picked = []; // {f, path} — files that PASSED the preflight
let pfRejected = []; // {path, size, reason} — rejected by the last add, shown in the UI

const fSize = n => n >= 1073741824 ? (n / 1073741824).toFixed(1) + ' GB'
  : n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB'
    : n >= 1024 ? Math.round(n / 1024) + ' KB' : n + ' B';

function addFiles(fileList, prefix = '') {
  const items = Array.from(fileList || []).map(f => ({
    f,
    path: prefix ? prefix.replace(/\/+$/, '') + '/' + f.name
      : (typeof f.__path === 'string' && f.__path ? f.__path : (f.webkitRelativePath || f.name))
  }));
  addItems(items);
}

function addItems(items) {
  // Client-side preflight: reject every case the server would reject (or that
  // would just waste an upload) BEFORE Analyze is pressed, with a visible reason.
  const rejected = [];
  const seen = new Set(picked.map(x => x.path + '|' + x.f.size + '|' + x.f.lastModified));
  for (const { f, path } of items) {
    const pst = PST_EXT.test(f.name);
    const reason =
      !OK_EXT.test(f.name) ? 'pfBadExt'
        : f.size === 0 ? 'pfEmpty'
          : f.size > (pst ? PICK_PST_MAX : PICK_FILE_MAX) ? (pst ? 'pfPstTooLarge' : 'pfTooLarge')
            : null;
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
  list.textContent = '';
  const total = picked.reduce((s, x) => s + x.f.size, 0);
  const skipped = pfRejected.filter(x => x.reason !== 'pfDupe').length;
  const dupes = pfRejected.length - skipped;
  let msg = picked.length ? `${picked.length} ${t('pickFiles')} · ${fSize(total)}` : t('pickNone');
  if (skipped) msg += ` · ${skipped} ${t('pickSkipped')}`;
  if (dupes) msg += ` · ${dupes} ${t('pickDup')}`;
  if (picked.length > PICK_TOTAL_MAX) msg += ` · ${t('pickLimit')}${PICK_TOTAL_MAX}`;
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

$('f').onchange = () => { addFiles($('f').files); $('f').value = ''; };
$('fdir').onchange = () => { addFiles($('fdir').files); $('fdir').value = ''; };
$('fclear').onclick = () => { picked = []; pfRejected = []; renderPick(); };

// Folder-aware drag & drop: read directories recursively when the browser exposes entries.
async function entryFiles(entry, out, depth = 0) {
  if (!entry || depth > 8 || out.length > 2000) return;
  if (entry.isFile) {
    await new Promise(r => entry.file(f => {
      out.push({ f, path: (entry.fullPath || '/' + f.name).replace(/^\//, '') });
      r();
    }, r));
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
    const items = Array.from(dt.items || []);
    const entries = items.map(i => i.webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) {
      const out = [];
      for (const en of entries) await entryFiles(en, out);
      if (out.length) { addItems(out); return; }
    }
    addFiles(dt.files);
  });
}

if ($('fbtn')) $('fbtn').onclick = () => { const f = $('f'); if (f) f.click(); };
if ($('fdirBtn')) $('fdirBtn').onclick = () => { const f = $('fdir'); if (f) f.click(); };
if ($('aimodelSel')) $('aimodelSel').onchange = () => syncModelSel();
if ($('aicompact')) $('aicompact').onchange = () => { if (lastResults.length) renderAllResults(lastResults, lastErrors); };
if ($('exportCsv')) $('exportCsv').onclick = () => {
  const rows = (lastResults[0]?.ipInfo || []).map(x => [x.ip, x.geo?.country || '', x.geo?.city || '', x.geo?.asn ?? '', x.geo?.organization || '', x.geo?.location?.latitude ?? '', x.geo?.location?.longitude ?? '', (x.ptr || []).join('|'), x.server?.key || '', x.assessment?.verdict || '', x.confidence ?? '']);
  const csv = ['ip,country,city,asn,organization,latitude,longitude,ptr,server,assessment,confidence_percent', ...rows.map(r => r.map(v => '"' + String(v).replaceAll('"', '""') + '"').join(','))].join('\n');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })); a.download = 'mailsleuth-ips.csv'; a.click();
};

// ----- analysis controls: pause / resume, graceful stop, cancel -----
const sleep = ms => new Promise(r => setTimeout(r, ms));
const BATCH_TIMEOUT_MS = 5 * 60 * 1000; // one batch may not hang forever
let job = null; // {paused, stopped, cancelled, ac, timedOut}

function setRunState(msg, kind = '') {
  const elx = $('runState');
  if (!elx) return;
  elx.textContent = msg || '';
  elx.className = 'summary runstate' + (kind ? ' ' + kind : '');
  elx.hidden = !msg;
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
  while (job && job.paused && !job.stopped && !job.cancelled) await sleep(200);
  if (job && !job.stopped && !job.cancelled) setRunState(t('runRunning'));
}

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

$('run').onclick = async () => {
  if (job) return; // one analysis at a time
  const fromInput = [...Array.from($('f').files || []), ...Array.from($('fdir').files || [])];
  if (fromInput.length) { addFiles(fromInput); $('f').value = ''; $('fdir').value = ''; }
  const files = picked.slice();
  $('prog').textContent = '';
  $('out').textContent = '';
  if (!files.length) { $('out').textContent = t('noFile'); return; }
  if (files.length > PICK_TOTAL_MAX) { $('out').textContent = t('pickLimit') + PICK_TOTAL_MAX; return; }
  last = null; lastResults = []; lastErrors = [];
  $('aiout').textContent = '';
  job = { paused: false, stopped: false, cancelled: false, ac: null, timedOut: false };
  syncRunButtons();
  setRunState(t('runRunning'));
  const results = [], errors = [];
  let netErr = '';
  setProgress(5, true);
  try {
    step(t('stepValidate'));
    setProgress(15, true);
    const batches = [];
    for (let i = 0; i < files.length; i += PICK_MAX) batches.push(files.slice(i, i + PICK_MAX));
    for (let b = 0; b < batches.length; b++) {
      if (job.cancelled || job.stopped) break;
      await waitIfPaused();
      if (job.cancelled || job.stopped) break;
      if (batches.length > 1) step(`${t('stepUpload')} ${b + 1}/${batches.length}`);
      step(t('stepProcess'));
      setProgress(15 + Math.round(60 * b / batches.length), true);
      const fd = new FormData();
      for (const x of batches[b]) fd.append('files', x.f, x.f.name);
      const ac = new AbortController();
      job.ac = ac;
      job.timedOut = false;
      const timer = setTimeout(() => { if (job) job.timedOut = true; ac.abort(); }, BATCH_TIMEOUT_MS);
      let r;
      try {
        r = await api('/api/analyze', { method: 'POST', body: fd, signal: ac.signal });
      } finally {
        clearTimeout(timer);
        if (job) job.ac = null;
      }
      if (r.status === 401) {
        leaveApp();
        $('err').textContent = t('e_auth');
        hideProgress();
        job = null;
        syncRunButtons();
        return;
      }
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        if (Array.isArray(j.errors) && j.errors.length) errors.push(...j.errors);
        else errors.push({ file: batches[b].map(x => x.path).join(', '), error: apiCode(j) || 'upload' });
        if (r.status === 429) { job.stopped = true; setRunState(t('runStopped') + ' (' + t('errRate') + ')', 'warn'); }
        continue;
      }
      if (Array.isArray(j.results)) results.push(...j.results);
      else if (j.format) results.push(j);
      if (Array.isArray(j.errors)) errors.push(...j.errors);
      setProgress(15 + Math.round(60 * (b + 1) / batches.length), true);
    }
  } catch (e) {
    if (e && e.name === 'AbortError') {
      if (job && job.timedOut) setRunState(t('batchTimeout'), 'bad');
    } else {
      netErr = t('errNetwork') + (e && e.message ? e.message : String(e));
    }
  }

  const wasCancelled = !!(job && job.cancelled);
  const wasStopped = !!(job && job.stopped);
  const wasTimedOut = !!(job && job.timedOut);
  job = null;
  syncRunButtons();

  if (wasCancelled) {
    // Cancel discards everything this run produced (server-side cases stay in history).
    last = null; lastResults = []; lastErrors = [];
    $('prog').textContent = '';
    $('out').textContent = '';
    setProgress(0, false);
    hideProgress();
    setRunState(t('runCancelled'), 'bad');
    return;
  }

  if (!results.length) {
    if (netErr) {
      $('out').textContent = netErr;
      setRunState(netErr, 'bad');
    } else if (errors.length) {
      const box = el('div', 'f s3');
      box.append(el('strong', '', t('uploadErrors')));
      errors.forEach(e => box.append(el('div', '', `${e.file}: ${errText(e.error)}`)));
      $('out').append(box);
      setRunState(t('uploadErrors'), 'bad');
    } else if (wasTimedOut) {
      $('out').textContent = t('batchTimeout');
      setRunState(t('batchTimeout'), 'bad');
    } else if (wasStopped) {
      $('out').textContent = t('runStoppedNoResults');
      setRunState(t('runStoppedNoResults'), 'warn');
    } else {
      $('out').textContent = errText('upload');
      setRunState(t('uploadErrors'), 'bad');
    }
    hideProgress();
    return;
  }

  lastResults = results;
  lastErrors = errors;
  last = results.reduce((a, b) => (b.score > a.score || (b.score === a.score && a.verdict === 'clean' && b.verdict !== 'clean')) ? b : a);
  histLoaded = false;
  step(t('stepScore') + ': ' + last.score + '/100');
  setProgress(100, false);
  renderAllResults(results, errors);
  if (netErr) setRunState(netErr, 'bad');
  else if (wasTimedOut) setRunState(`${t('batchTimeout')} ${results.length}/${files.length}`, 'warn');
  else if (wasStopped) setRunState(`${t('runStopped')} ${results.length}/${files.length}`, 'warn');
  else setRunState('');
  setTimeout(() => hideProgress(), 1200);
};

$('ai').onclick = async () => {
  if (!last) { $('aiout').textContent = t('aiNeedResult'); return; }
  let u;
  try { u = new URL($('aiurl').value.trim()); }
  catch { $('aiout').textContent = t('aiBadUrl'); return; }
  const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(u.hostname);
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && local))) {
    $('aiout').textContent = t('aiBadUrl'); return;
  }
  const model = currentModel();
  if (!model) { $('aiout').textContent = t('aiNeedModel'); return; }
  const key = $('aikey').value.trim();
  if (!key) { $('aiout').textContent = t('aiNeedKey'); return; }
  store.set('aikey:' + user, key);
  store.set('aimodel:' + user, model);

  const btn = $('ai');
  btn.disabled = true;
  $('aiout').textContent = t('aiThinking');
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 60e3);
  try {
    const summary = {
      format: last.format, score: last.score, verdict: last.verdict, authSeen: last.authSeen,
      findings: last.findings.slice(0, 50).map(f => ({ severity: f.sev, type: f.type, evidence: f.evidence }))
    };
    const r = await fetch(u.href, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key },
      body: JSON.stringify({
        model,
        messages: [{
          role: 'user',
          content: `As an email forensics assistant, summarize these findings and give concrete next steps (${lang === 'vi' ? 'in Vietnamese' : 'in English'}). Do not invent facts.\n` + JSON.stringify(summary)
        }]
      }),
      signal: ctrl.signal, credentials: 'omit', referrerPolicy: 'no-referrer', mode: 'cors'
    });
    const j = await r.json().catch(() => null);
    if (!r.ok) throw new Error((j && (j.error?.message || j.error)) || ('HTTP ' + r.status));
    const raw = j?.choices?.[0]?.message?.content || t('aiEmpty');
    $('aiout').textContent = compactMode() ? filterCompactText(raw) : raw;
  } catch (e) {
    $('aiout').textContent = e.name === 'AbortError' ? t('aiTimeout') : t('aiError') + (e.message || e);
  } finally {
    clearTimeout(timer);
    btn.disabled = false;
  }
};

$('forgetai').onclick = () => {
  store.del('aikey:' + user);
  store.del('aikey'); // remove a value left by versions before per-user keys
  $('aikey').value = '';
  $('aiout').textContent = t('keyForgotten');
};

$('lang').onchange = () => {
  lang = $('lang').value === 'vi' ? 'vi' : 'en';
  try { localStorage.setItem('lang', lang); } catch {}
  applyLang();
};

$('mapkeySave').onclick = () => saveMapKey(false);
$('mapkeyClear').onclick = () => saveMapKey(true);

applyLang();

// Restore an existing session when the page is reloaded.
(async () => {
  try {
    const r = await fetch('/api/me');
    if (r.ok) enterApp(await r.json());
  } catch {}
})();
