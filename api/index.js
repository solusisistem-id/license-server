import crypto from 'crypto';

// =====================================================
// BILL MANAGEMENT - MULTI-APP LICENSE SERVER v2.0
// Fitur: Lifetime License + Multi-Application Support
// =====================================================

// Data storage (dalam memory - untuk production gunakan database)
let licenses = new Map();
let apps = new Map();

// Secret key untuk signing
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key-change-in-production';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token-change-in-production';

// =====================================================
// HELPER FUNCTIONS
// =====================================================

/**
 * Generate unique license key
 * Format: BM-APPNAME-XXXX-XXXX-XXXX (contoh: BM-BILL-A1B2-C3D4-E5F6)
 */
function generateLicenseKey(appId) {
  const appPrefix = appId.substring(0, 4).toUpperCase();
  const parts = [];
  for (let i = 0; i < 3; i++) {
    parts.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  }
  return `BM-${appPrefix}-${parts.join('-')}`;
}

/**
 * Generate unique app ID
 */
function generateAppId() {
  return `APP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

/**
 * Validate license key format
 */
function isValidLicenseFormat(key) {
  return /^BM-[A-Z0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/i.test(key);
}

/**
 * Check if request has valid admin token
 */
function isAdmin(req) {
  const token = req.headers.authorization || 
                req.query.adminToken || 
                req.body?.adminToken;
  return token === ADMIN_TOKEN;
}

/**
 * Send JSON response
 */
function sendResponse(res, status, data) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return res.status(status).json(data);
}

// =====================================================
// MAIN HANDLER
// =====================================================

export default async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return sendResponse(res, 200, { ok: true });
  }

  const { action } = req.query;

  try {
    switch (action) {
      // === LICENSE ENDPOINTS ===
      case 'validate':
        return await handleValidate(req, res);
      case 'activate':
        return await handleActivate(req, res);
      case 'deactivate':
        return await handleDeactivate(req, res);
      case 'info':
        return await handleInfo(req, res);
      
      // === ADMIN ENDPOINTS ===
      case 'generate':
        return await handleGenerate(req, res);
      case 'list':
        return await handleList(req, res);
      case 'revoke':
        return await handleRevoke(req, res);
      
      // === APP MANAGEMENT ENDPOINTS ===
      case 'app/create':
        return await handleAppCreate(req, res);
      case 'app/list':
        return await handleAppList(req, res);
      case 'app/info':
        return await handleAppInfo(req, res);
      case 'app/delete':
        return await handleAppDelete(req, res);
      
      // === HEALTH CHECK ===
      case 'health':
        return sendResponse(res, 200, { 
          status: 'ok', 
          version: '2.0.0',
          features: ['lifetime_license', 'multi_app']
        });
      
      default:
        return sendResponse(res, 400, { 
          success: false, 
          error: 'Action tidak valid',
          availableActions: [
            'validate', 'activate', 'deactivate', 'info',
            'generate', 'list', 'revoke',
            'app/create', 'app/list', 'app/info', 'app/delete',
            'health'
          ]
        });
    }
  } catch (error) {
    console.error('Error:', error);
    return sendResponse(res, 500, { 
      success: false, 
      error: 'Terjadi kesalahan server',
      message: error.message
    });
  }
}

// =====================================================
// LICENSE VALIDATION & ACTIVATION
// =====================================================

/**
 * Validate license key
 * GET /api?action=validate&key=LICENSE_KEY&email=USER_EMAIL
 */
async function handleValidate(req, res) {
  const { key, email, appId } = req.query;

  // Validasi input
  if (!key) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key diperlukan' 
    });
  }

  if (!isValidLicenseFormat(key)) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Format license key tidak valid' 
    });
  }

  const license = licenses.get(key.toUpperCase());

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      valid: false,
      error: 'License key tidak ditemukan' 
    });
  }

  // Cek status license
  if (license.status === 'revoked') {
    return sendResponse(res, 200, { 
      success: true,
      valid: false, 
      error: 'License telah dicabut/diblokir',
      reason: license.revokeReason
    });
  }

  // Cek appId jika diberikan
  if (appId && license.appId !== appId) {
    return sendResponse(res, 200, { 
      success: true,
      valid: false, 
      error: 'License tidak valid untuk aplikasi ini',
      expectedAppId: license.appId
    });
  }

  // Cek apakah sudah diaktifkan oleh email lain
  if (license.activatedEmail && email && license.activatedEmail !== email) {
    return sendResponse(res, 200, { 
      success: true,
      valid: false, 
      error: 'License sudah diaktifkan oleh akun lain',
      hint: 'Gunakan email yang sama saat aktivasi pertama kali'
    });
  }

  // License valid - LIFETIME (tidak ada expired)
  const app = apps.get(license.appId);
  
  return sendResponse(res, 200, { 
    success: true,
    valid: true,
    license: {
      key: key.toUpperCase(),
      appId: license.appId,
      appName: app?.name || 'Unknown App',
      type: license.type || 'lifetime',
      licenseType: 'LIFETIME', // Selalu lifetime
      activatedAt: license.activatedAt,
      activatedEmail: license.activatedEmail,
      maxDevices: license.maxDevices || 1,
      currentDevices: license.currentDevices || 0,
      features: license.features || [],
      createdAt: license.createdAt
    },
    app: app ? {
      id: app.id,
      name: app.name,
      version: app.version
    } : null
  });
}

/**
 * Activate license
 * POST /api?action=activate
 * Body: { key, email, deviceInfo?, appId? }
 */
async function handleActivate(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  const { key, email, deviceInfo, appId } = req.body;

  // Validasi input
  if (!key || !email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key dan email diperlukan' 
    });
  }

  if (!isValidLicenseFormat(key)) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Format license key tidak valid' 
    });
  }

  const license = licenses.get(key.toUpperCase());

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  // Cek status
  if (license.status === 'revoked') {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License telah dicabut/diblokir' 
    });
  }

  // Cek appId
  if (appId && license.appId !== appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License tidak valid untuk aplikasi ini' 
    });
  }

  // Cek apakah sudah diaktifkan oleh email lain
  if (license.activatedEmail && license.activatedEmail !== email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License sudah diaktifkan oleh email lain',
      hint: 'Gunakan email yang sama saat aktivasi pertama kali'
    });
  }

  // Cek jumlah device
  const currentDevices = license.currentDevices || 0;
  const maxDevices = license.maxDevices || 1;
  
  if (currentDevices >= maxDevices && !license.activatedEmail) {
    return sendResponse(res, 400, { 
      success: false, 
      error: `Maksimal ${maxDevices} device sudah terdaftar` 
    });
  }

  // Generate device ID
  const deviceId = crypto.createHash('md5').update(email + (deviceInfo?.name || 'default')).digest('hex').substring(0, 8);
  
  // Update license
  license.activatedAt = license.activatedAt || new Date().toISOString();
  license.activatedEmail = license.activatedEmail || email;
  license.currentDevices = (license.currentDevices || 0) + 1;
  license.deviceId = deviceId;
  license.deviceInfo = deviceInfo || {};
  license.lastUsed = new Date().toISOString();
  license.status = 'active';

  licenses.set(key.toUpperCase(), license);

  const app = apps.get(license.appId);

  return sendResponse(res, 200, { 
    success: true,
    message: 'License berhasil diaktifkan',
    license: {
      key: key.toUpperCase(),
      appId: license.appId,
      appName: app?.name || 'Unknown App',
      type: 'LIFETIME',
      activatedAt: license.activatedAt,
      deviceId: deviceId,
      maxDevices: maxDevices,
      features: license.features || []
    }
  });
}

/**
 * Deactivate license from device
 * POST /api?action=deactivate
 * Body: { key, email }
 */
async function handleDeactivate(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  const { key, email } = req.body;

  if (!key || !email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key dan email diperlukan' 
    });
  }

  const license = licenses.get(key.toUpperCase());

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  if (license.activatedEmail !== email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Email tidak sesuai dengan yang terdaftar' 
    });
  }

  // Reset device count
  license.currentDevices = Math.max(0, (license.currentDevices || 1) - 1);
  license.lastUsed = new Date().toISOString();

  if (license.currentDevices === 0) {
    license.status = 'inactive';
  }

  licenses.set(key.toUpperCase(), license);

  return sendResponse(res, 200, { 
    success: true,
    message: 'Device berhasil di-deactivate',
    remainingDevices: license.currentDevices
  });
}

/**
 * Get license info
 * GET /api?action=info&key=LICENSE_KEY
 */
async function handleInfo(req, res) {
  const { key } = req.query;

  if (!key) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key diperlukan' 
    });
  }

  const license = licenses.get(key.toUpperCase());

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  const app = apps.get(license.appId);

  return sendResponse(res, 200, { 
    success: true,
    license: {
      key: key.toUpperCase(),
      appId: license.appId,
      appName: app?.name || 'Unknown App',
      type: 'LIFETIME',
      status: license.status,
      createdAt: license.createdAt,
      activatedAt: license.activatedAt,
      activatedEmail: license.activatedEmail ? license.activatedEmail.replace(/(.{2}).*@/, '$1***@') : null,
      maxDevices: license.maxDevices,
      currentDevices: license.currentDevices || 0,
      features: license.features || [],
      lastUsed: license.lastUsed
    },
    app: app ? {
      id: app.id,
      name: app.name,
      description: app.description,
      version: app.version
    } : null
  });
}

// =====================================================
// ADMIN - LICENSE MANAGEMENT
// =====================================================

/**
 * Generate new license keys
 * POST /api?action=generate
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { appId, count, maxDevices, features, email? }
 */
async function handleGenerate(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { appId, count = 1, maxDevices = 1, features = [], email, notes } = req.body;

  // Validasi appId
  if (!appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'App ID diperlukan. Gunakan /api?action=app/list untuk melihat daftar aplikasi' 
    });
  }

  const app = apps.get(appId);
  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  const generatedKeys = [];

  for (let i = 0; i < count; i++) {
    const key = generateLicenseKey(appId);
    
    licenses.set(key, {
      key,
      appId: appId,
      type: 'lifetime',
      status: 'available',
      createdAt: new Date().toISOString(),
      maxDevices: maxDevices,
      currentDevices: 0,
      features: features,
      preAssignedEmail: email || null,
      notes: notes || null,
      // LIFETIME - tidak ada expiresAt
    });

    generatedKeys.push(key);
    
    // Update app stats
    app.totalLicenses = (app.totalLicenses || 0) + 1;
  }

  apps.set(appId, app);

  return sendResponse(res, 200, { 
    success: true,
    message: `${count} license key LIFETIME berhasil dibuat untuk aplikasi ${app.name}`,
    appId: appId,
    appName: app.name,
    licenseType: 'LIFETIME',
    keys: generatedKeys
  });
}

/**
 * List all licenses (with filters)
 * GET /api?action=list&appId=APP_ID&status=STATUS&adminToken=TOKEN
 */
async function handleList(req, res) {
  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { appId, status, limit = 100, offset = 0 } = req.query;
  
  let allLicenses = [];
  
  licenses.forEach((license) => {
    // Filter by appId
    if (appId && license.appId !== appId) return;
    
    // Filter by status
    if (status && license.status !== status) return;
    
    const app = apps.get(license.appId);
    
    allLicenses.push({
      key: license.key,
      appId: license.appId,
      appName: app?.name || 'Unknown',
      type: 'LIFETIME',
      status: license.status,
      createdAt: license.createdAt,
      activatedAt: license.activatedAt,
      activatedEmail: license.activatedEmail ? license.activatedEmail.replace(/(.{2}).*@/, '$1***@') : null,
      maxDevices: license.maxDevices,
      currentDevices: license.currentDevices || 0,
      lastUsed: license.lastUsed,
      notes: license.notes
    });
  });

  // Sort by createdAt desc
  allLicenses.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  // Pagination
  const total = allLicenses.length;
  allLicenses = allLicenses.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

  // Stats
  const stats = {
    total: licenses.size,
    available: 0,
    active: 0,
    revoked: 0
  };
  
  licenses.forEach(l => {
    if (l.status === 'available') stats.available++;
    else if (l.status === 'active') stats.active++;
    else if (l.status === 'revoked') stats.revoked++;
  });

  return sendResponse(res, 200, { 
    success: true,
    count: allLicenses.length,
    total: total,
    stats: stats,
    licenses: allLicenses
  });
}

/**
 * Revoke license
 * POST /api?action=revoke
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { key, reason }
 */
async function handleRevoke(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { key, reason } = req.body;

  if (!key) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key diperlukan' 
    });
  }

  const license = licenses.get(key.toUpperCase());
  
  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  // Revoke license
  license.status = 'revoked';
  license.revokedAt = new Date().toISOString();
  license.revokeReason = reason || 'No reason provided';
  
  licenses.set(key.toUpperCase(), license);

  return sendResponse(res, 200, { 
    success: true,
    message: 'License berhasil di-revoke',
    key: key.toUpperCase(),
    reason: license.revokeReason
  });
}

// =====================================================
// APP MANAGEMENT
// =====================================================

/**
 * Create new application
 * POST /api?action=app/create
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { name, description, version, features }
 */
async function handleAppCreate(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { name, description, version, features, website, category } = req.body;

  if (!name) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Nama aplikasi diperlukan' 
    });
  }

  // Generate unique app ID
  let appId;
  let attempts = 0;
  do {
    appId = generateAppId();
    attempts++;
    if (attempts > 10) {
      return sendResponse(res, 500, { 
        success: false, 
        error: 'Gagal generate App ID unik' 
      });
    }
  } while (apps.has(appId));

  const app = {
    id: appId,
    name: name,
    description: description || '',
    version: version || '1.0.0',
    features: features || [],
    website: website || '',
    category: category || 'general',
    createdAt: new Date().toISOString(),
    totalLicenses: 0,
    activeLicenses: 0,
    status: 'active'
  };

  apps.set(appId, app);

  return sendResponse(res, 201, { 
    success: true,
    message: 'Aplikasi berhasil didaftarkan',
    app: app
  });
}

/**
 * List all applications
 * GET /api?action=app/list
 */
async function handleAppList(req, res) {
  // Public endpoint - bisa dilihat tanpa admin token
  
  const allApps = [];
  
  apps.forEach((app) => {
    // Count licenses for this app
    let licenseCount = { total: 0, active: 0, available: 0 };
    licenses.forEach(l => {
      if (l.appId === app.id) {
        licenseCount.total++;
        if (l.status === 'active') licenseCount.active++;
        if (l.status === 'available') licenseCount.available++;
      }
    });
    
    allApps.push({
      id: app.id,
      name: app.name,
      description: app.description,
      version: app.version,
      category: app.category,
      website: app.website,
      status: app.status,
      licenseStats: licenseCount,
      createdAt: app.createdAt
    });
  });

  return sendResponse(res, 200, { 
    success: true,
    count: allApps.length,
    apps: allApps
  });
}

/**
 * Get app info
 * GET /api?action=app/info&appId=APP_ID
 */
async function handleAppInfo(req, res) {
  const { appId } = req.query;

  if (!appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'App ID diperlukan' 
    });
  }

  const app = apps.get(appId);

  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  // Count licenses
  let licenseStats = { total: 0, active: 0, available: 0, revoked: 0 };
  licenses.forEach(l => {
    if (l.appId === appId) {
      licenseStats.total++;
      if (l.status === 'active') licenseStats.active++;
      else if (l.status === 'available') licenseStats.available++;
      else if (l.status === 'revoked') licenseStats.revoked++;
    }
  });

  return sendResponse(res, 200, { 
    success: true,
    app: {
      ...app,
      licenseStats
    }
  });
}

/**
 * Delete application
 * POST /api?action=app/delete
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { appId }
 */
async function handleAppDelete(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { appId, deleteLicenses } = req.body;

  if (!appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'App ID diperlukan' 
    });
  }

  const app = apps.get(appId);

  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  // Check if has licenses
  let hasLicenses = false;
  licenses.forEach(l => {
    if (l.appId === appId) hasLicenses = true;
  });

  if (hasLicenses && !deleteLicenses) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Aplikasi memiliki license aktif. Set deleteLicenses=true untuk menghapus semua license juga.' 
    });
  }

  // Delete licenses if requested
  if (deleteLicenses) {
    const keysToDelete = [];
    licenses.forEach((l, key) => {
      if (l.appId === appId) keysToDelete.push(key);
    });
    keysToDelete.forEach(key => licenses.delete(key));
  }

  // Delete app
  apps.delete(appId);

  return sendResponse(res, 200, { 
    success: true,
    message: 'Aplikasi berhasil dihapus',
    deletedApp: app.name,
    deletedLicenses: deleteLicenses ? 'yes' : 'no'
  });
}
