/**
 * =====================================================
 * BILL MANAGEMENT - MULTI-APP LICENSE SERVER v3.0
 * =====================================================
 * 
 * Fitur:
 * - Lifetime License Support
 * - Multi-Application Support
 * - Vercel KV Persistent Storage (Redis)
 * 
 * Changelog v3.0:
 * - Upgrade dari memory storage ke Vercel KV
 * - Data sekarang persist (tidak hilang saat cold start)
 * - Performance lebih baik dengan Redis
 * 
 * Author: Bill Management Team
 * License: MIT
 */

import crypto from 'crypto';
import { 
  initializeData,
  saveApp, getApp, getAllApps, deleteApp, appExists,
  saveLicense, getLicense, getAllLicenses, deleteLicense, licenseExists, updateLicense,
  getLicenseStats, filterLicenses,
  exportAllData, importAllData, clearAllData,
  countLicensesByApp
} from './kv.js';

// =====================================================
// CONFIGURATION
// =====================================================

/**
 * Secret key untuk signing dan admin authentication
 * PENTING: Ganti nilai default di Vercel Environment Variables!
 */
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key-change-in-production';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token-change-in-production';

// =====================================================
// HELPER FUNCTIONS
// =====================================================

/**
 * Generate unique license key dengan format standar
 * 
 * Format: BM-{APP_PREFIX}-{RANDOM}-{RANDOM}-{RANDOM}
 * Contoh: BM-BILL-A1B2-C3D4-E5F6
 * 
 * @param {string} appId - ID aplikasi untuk prefix
 * @returns {string} License key yang di-generate
 */
function generateLicenseKey(appId) {
  // Ambil 4 karakter pertama dari appId sebagai prefix
  const appPrefix = appId.substring(0, 4).toUpperCase();
  
  // Generate 3 bagian random (masing-masing 4 karakter hex)
  const parts = [];
  for (let i = 0; i < 3; i++) {
    parts.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  }
  
  return `BM-${appPrefix}-${parts.join('-')}`;
}

/**
 * Generate unique app ID
 * 
 * Format: APP-XXXXXX (6 karakter hex)
 * Contoh: APP-A1B2C3
 * 
 * @returns {string} App ID yang di-generate
 */
function generateAppId() {
  return `APP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

/**
 * Validasi format license key
 * 
 * @param {string} key - License key yang akan divalidasi
 * @returns {boolean} true jika format valid
 */
function isValidLicenseFormat(key) {
  return /^BM-[A-Z0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/i.test(key);
}

/**
 * Cek apakah request memiliki admin token yang valid
 * 
 * @param {Object} req - Request object
 * @returns {boolean} true jika admin valid
 */
function isAdmin(req) {
  const token = req.headers.authorization || 
                req.query.adminToken || 
                req.body?.adminToken;
  return token === ADMIN_TOKEN;
}

/**
 * Kirim JSON response dengan CORS headers
 * 
 * @param {Object} res - Response object
 * @param {number} status - HTTP status code
 * @param {Object} data - Data yang akan dikirim
 * @returns {Object} Response object
 */
function sendResponse(res, status, data) {
  // CORS headers untuk membolehkan akses dari domain manapun
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return res.status(status).json(data);
}

/**
 * Mask email untuk privacy (tampilkan 2 karakter pertama + ***)
 * 
 * @param {string} email - Email yang akan di-mask
 * @returns {string} Email yang sudah di-mask
 */
function maskEmail(email) {
  if (!email) return null;
  return email.replace(/(.{2}).*@/, '$1***@');
}

// =====================================================
// MAIN HANDLER
// =====================================================

/**
 * Main API handler
 * Menangani semua request ke /api
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response
 */
export default async function handler(req, res) {
  // Handle CORS preflight request
  if (req.method === 'OPTIONS') {
    return sendResponse(res, 200, { ok: true });
  }

  // Inisialisasi data jika belum ada (untuk cold start)
  await initializeData();

  const { action } = req.query;

  try {
    // Route ke handler yang sesuai berdasarkan action
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
      
      // === BACKUP ENDPOINTS ===
      case 'backup':
        return await handleBackup(req, res);
      case 'restore':
        return await handleRestore(req, res);
      
      // === HEALTH CHECK ===
      case 'health':
        return sendResponse(res, 200, { 
          status: 'ok', 
          version: '3.0.0',
          storage: 'vercel-kv',
          features: ['lifetime_license', 'multi_app', 'persistent_storage']
        });
      
      default:
        return sendResponse(res, 400, { 
          success: false, 
          error: 'Action tidak valid',
          availableActions: [
            'validate', 'activate', 'deactivate', 'info',
            'generate', 'list', 'revoke',
            'app/create', 'app/list', 'app/info', 'app/delete',
            'backup', 'restore',
            'health'
          ]
        });
    }
  } catch (error) {
    console.error('[API] Error:', error);
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
 * Cek apakah license valid, aktif, dan sesuai dengan email/app
 * 
 * GET /api?action=validate&key=LICENSE_KEY&email=USER_EMAIL&appId=APP_ID
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan status validasi
 */
async function handleValidate(req, res) {
  const { key, email, appId } = req.query;

  // Validasi input wajib
  if (!key) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key diperlukan' 
    });
  }

  // Validasi format license key
  if (!isValidLicenseFormat(key)) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Format license key tidak valid. Format: BM-XXXX-XXXX-XXXX-XXXX' 
    });
  }

  // Ambil license dari database
  const license = await getLicense(key);

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      valid: false,
      error: 'License key tidak ditemukan' 
    });
  }

  // Cek status license (revoked = diblokir)
  if (license.status === 'revoked') {
    return sendResponse(res, 200, { 
      success: true,
      valid: false, 
      error: 'License telah dicabut/diblokir',
      reason: license.revokeReason
    });
  }

  // Cek appId jika diberikan (pastikan license untuk app yang benar)
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

  // License valid - ambil info app
  const app = await getApp(license.appId);
  
  return sendResponse(res, 200, { 
    success: true,
    valid: true,
    license: {
      key: key.toUpperCase(),
      appId: license.appId,
      appName: app?.name || 'Unknown App',
      type: 'LIFETIME', // Selalu lifetime
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
 * Activate license untuk user/device
 * Mengikat license ke email dan device tertentu
 * 
 * POST /api?action=activate
 * Body: { key, email, deviceInfo?, appId? }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan hasil aktivasi
 */
async function handleActivate(req, res) {
  // Hanya terima POST request
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  const { key, email, deviceInfo, appId } = req.body;

  // Validasi input wajib
  if (!key || !email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key dan email diperlukan' 
    });
  }

  // Validasi format license key
  if (!isValidLicenseFormat(key)) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Format license key tidak valid' 
    });
  }

  // Ambil license dari database
  const license = await getLicense(key);

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  // Cek status license
  if (license.status === 'revoked') {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License telah dicabut/diblokir' 
    });
  }

  // Cek appId (pastikan license untuk app yang benar)
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

  // Cek jumlah device yang sudah terdaftar
  const currentDevices = license.currentDevices || 0;
  const maxDevices = license.maxDevices || 1;
  
  if (currentDevices >= maxDevices && !license.activatedEmail) {
    return sendResponse(res, 400, { 
      success: false, 
      error: `Maksimal ${maxDevices} device sudah terdaftar` 
    });
  }

  // Generate device ID unik berdasarkan email dan device info
  const deviceId = crypto.createHash('md5')
    .update(email + (deviceInfo?.name || 'default'))
    .digest('hex')
    .substring(0, 8);
  
  // Siapkan data update
  const updates = {
    activatedAt: license.activatedAt || new Date().toISOString(),
    activatedEmail: license.activatedEmail || email,
    currentDevices: (license.currentDevices || 0) + 1,
    deviceId: deviceId,
    deviceInfo: deviceInfo || {},
    lastUsed: new Date().toISOString(),
    status: 'active'
  };

  // Update license di database
  await updateLicense(key, updates);
  
  // Ambil info app
  const app = await getApp(license.appId);

  return sendResponse(res, 200, { 
    success: true,
    message: 'License berhasil diaktifkan',
    license: {
      key: key.toUpperCase(),
      appId: license.appId,
      appName: app?.name || 'Unknown App',
      type: 'LIFETIME',
      activatedAt: updates.activatedAt,
      deviceId: deviceId,
      maxDevices: maxDevices,
      features: license.features || []
    }
  });
}

/**
 * Deactivate license dari device
 * Mengurangi jumlah device yang terdaftar
 * 
 * POST /api?action=deactivate
 * Body: { key, email }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan hasil deaktivasi
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

  const license = await getLicense(key);

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  // Pastikan email yang deactivate adalah email yang sama
  if (license.activatedEmail !== email) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Email tidak sesuai dengan yang terdaftar' 
    });
  }

  // Update device count
  const newDeviceCount = Math.max(0, (license.currentDevices || 1) - 1);
  
  await updateLicense(key, {
    currentDevices: newDeviceCount,
    lastUsed: new Date().toISOString(),
    status: newDeviceCount === 0 ? 'inactive' : 'active'
  });

  return sendResponse(res, 200, { 
    success: true,
    message: 'Device berhasil di-deactivate',
    remainingDevices: newDeviceCount
  });
}

/**
 * Get license info (detail lengkap)
 * 
 * GET /api?action=info&key=LICENSE_KEY
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan info license
 */
async function handleInfo(req, res) {
  const { key } = req.query;

  if (!key) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'License key diperlukan' 
    });
  }

  const license = await getLicense(key);

  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  const app = await getApp(license.appId);

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
      activatedEmail: maskEmail(license.activatedEmail),
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
 * Generate new license keys (Admin only)
 * 
 * POST /api?action=generate
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { appId, count, maxDevices, features, email?, notes? }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan license keys yang di-generate
 */
async function handleGenerate(req, res) {
  if (req.method !== 'POST') {
    return sendResponse(res, 405, { 
      success: false, 
      error: 'Method tidak diizinkan. Gunakan POST' 
    });
  }

  // Cek admin authorization
  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { appId, count = 1, maxDevices = 1, features = [], email, notes } = req.body;

  // Validasi appId wajib
  if (!appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'App ID diperlukan. Gunakan /api?action=app/list untuk melihat daftar aplikasi' 
    });
  }

  // Pastikan app exists
  const app = await getApp(appId);
  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  const generatedKeys = [];

  // Generate license keys sesuai jumlah yang diminta
  for (let i = 0; i < count; i++) {
    const key = generateLicenseKey(appId);
    
    // Simpan license baru ke database
    await saveLicense(key, {
      key,
      appId: appId,
      type: 'lifetime',
      status: 'available',
      createdAt: new Date().toISOString(),
      maxDevices: maxDevices,
      currentDevices: 0,
      features: features,
      preAssignedEmail: email || null,
      notes: notes || null
      // LIFETIME - tidak ada expiresAt
    });

    generatedKeys.push(key);
  }

  // Update total licenses count di app
  await updateApp(appId, {
    totalLicenses: (app.totalLicenses || 0) + count
  });

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
 * Helper: Update app data
 */
async function updateApp(appId, updates) {
  const app = await getApp(appId);
  if (app) {
    await saveApp(appId, { ...app, ...updates });
  }
}

/**
 * List all licenses (Admin only)
 * Support filtering dan pagination
 * 
 * GET /api?action=list&appId=APP_ID&status=STATUS&adminToken=TOKEN&limit=100&offset=0
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan daftar licenses
 */
async function handleList(req, res) {
  // Cek admin authorization
  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const { appId, status, limit = 100, offset = 0 } = req.query;
  
  // Gunakan filterLicenses helper
  const { total, licenses: filteredLicenses } = await filterLicenses({
    appId,
    status,
    limit: parseInt(limit),
    offset: parseInt(offset)
  });

  // Format response
  const formattedLicenses = filteredLicenses.map(license => {
    const app = getApp(license.appId); // Note: ini async tapi kita skip untuk performa
    
    return {
      key: license.key,
      appId: license.appId,
      appName: 'N/A', // Akan diisi di client jika perlu
      type: 'LIFETIME',
      status: license.status,
      createdAt: license.createdAt,
      activatedAt: license.activatedAt,
      activatedEmail: maskEmail(license.activatedEmail),
      maxDevices: license.maxDevices,
      currentDevices: license.currentDevices || 0,
      lastUsed: license.lastUsed,
      notes: license.notes
    };
  });

  // Get stats
  const stats = await getLicenseStats(appId);

  return sendResponse(res, 200, { 
    success: true,
    count: formattedLicenses.length,
    total: total,
    stats: stats,
    licenses: formattedLicenses
  });
}

/**
 * Revoke license (Admin only)
 * Memblokir license agar tidak bisa digunakan
 * 
 * POST /api?action=revoke
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { key, reason }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan hasil revoke
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

  const license = await getLicense(key);
  
  if (!license) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'License key tidak ditemukan' 
    });
  }

  // Update status ke revoked
  await updateLicense(key, {
    status: 'revoked',
    revokedAt: new Date().toISOString(),
    revokeReason: reason || 'No reason provided'
  });

  return sendResponse(res, 200, { 
    success: true,
    message: 'License berhasil di-revoke',
    key: key.toUpperCase(),
    reason: reason || 'No reason provided'
  });
}

// =====================================================
// APP MANAGEMENT
// =====================================================

/**
 * Create new application (Admin only)
 * Mendaftarkan aplikasi baru ke sistem license
 * 
 * POST /api?action=app/create
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { name, description?, version?, features?, website?, category? }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan app yang baru dibuat
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

  // Generate unique app ID dengan retry mechanism
  let appId;
  let attempts = 0;
  do {
    appId = generateAppId();
    attempts++;
    if (attempts > 10) {
      return sendResponse(res, 500, { 
        success: false, 
        error: 'Gagal generate App ID unik. Coba lagi.' 
      });
    }
  } while (await appExists(appId));

  // Siapkan data app
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

  // Simpan ke database
  await saveApp(appId, app);

  return sendResponse(res, 201, { 
    success: true,
    message: 'Aplikasi berhasil didaftarkan',
    app: app
  });
}

/**
 * List all applications (Public)
 * Menampilkan semua aplikasi yang terdaftar
 * 
 * GET /api?action=app/list
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan daftar aplikasi
 */
async function handleAppList(req, res) {
  // Public endpoint - tidak perlu admin token
  const apps = await getAllApps();
  
  const allApps = [];
  
  for (const appId in apps) {
    const app = apps[appId];
    
    // Hitung license stats untuk setiap app
    const licenseStats = await getLicenseStats(appId);
    
    allApps.push({
      id: app.id,
      name: app.name,
      description: app.description,
      version: app.version,
      category: app.category,
      website: app.website,
      status: app.status,
      licenseStats: licenseStats,
      createdAt: app.createdAt
    });
  }

  return sendResponse(res, 200, { 
    success: true,
    count: allApps.length,
    apps: allApps
  });
}

/**
 * Get app info by ID (Public)
 * 
 * GET /api?action=app/info&appId=APP_ID
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan info app
 */
async function handleAppInfo(req, res) {
  const { appId } = req.query;

  if (!appId) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'App ID diperlukan' 
    });
  }

  const app = await getApp(appId);

  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  // Get license stats
  const licenseStats = await getLicenseStats(appId);

  return sendResponse(res, 200, { 
    success: true,
    app: {
      ...app,
      licenseStats
    }
  });
}

/**
 * Delete application (Admin only)
 * 
 * POST /api?action=app/delete
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { appId, deleteLicenses? }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan hasil penghapusan
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

  const app = await getApp(appId);

  if (!app) {
    return sendResponse(res, 404, { 
      success: false, 
      error: 'App ID tidak ditemukan' 
    });
  }

  // Cek apakah ada licenses untuk app ini
  const licenseCount = await countLicensesByApp(appId);

  if (licenseCount > 0 && !deleteLicenses) {
    return sendResponse(res, 400, { 
      success: false, 
      error: `Aplikasi memiliki ${licenseCount} license. Set deleteLicenses=true untuk menghapus semua license juga.` 
    });
  }

  // Hapus licenses jika diminta
  if (deleteLicenses) {
    const licenses = await getAllLicenses();
    for (const key in licenses) {
      if (licenses[key].appId === appId) {
        await deleteLicense(key);
      }
    }
  }

  // Hapus app
  await deleteApp(appId);

  return sendResponse(res, 200, { 
    success: true,
    message: 'Aplikasi berhasil dihapus',
    deletedApp: app.name,
    deletedLicenses: deleteLicenses ? licenseCount : 0
  });
}

// =====================================================
// BACKUP & RESTORE
// =====================================================

/**
 * Backup all data (Admin only)
 * Export semua data untuk backup
 * 
 * GET /api?action=backup&adminToken=TOKEN
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan semua data
 */
async function handleBackup(req, res) {
  if (!isAdmin(req)) {
    return sendResponse(res, 401, { 
      success: false, 
      error: 'Unauthorized. Admin token diperlukan' 
    });
  }

  const data = await exportAllData();

  return sendResponse(res, 200, { 
    success: true,
    ...data
  });
}

/**
 * Restore data from backup (Admin only)
 * Import data dari backup
 * 
 * POST /api?action=restore
 * Headers: Authorization: ADMIN_TOKEN
 * Body: { apps, licenses }
 * 
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @returns {Object} Response dengan hasil restore
 */
async function handleRestore(req, res) {
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

  const { apps, licenses } = req.body;

  if (!apps && !licenses) {
    return sendResponse(res, 400, { 
      success: false, 
      error: 'Data apps atau licenses diperlukan' 
    });
  }

  await importAllData({ apps, licenses });

  return sendResponse(res, 200, { 
    success: true,
    message: 'Data berhasil di-restore',
    appsCount: apps ? Object.keys(apps).length : 0,
    licensesCount: licenses ? Object.keys(licenses).length : 0
  });
}
