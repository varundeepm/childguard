const express = require('express');
const cors = require('cors');
const twilio = require('twilio');
const { exec } = require('child_process');
const os = require('os');

const app = express();
const PORT = 5000;

// ============================================
// CONFIGURATION - CHANGE THESE VALUES
// ============================================
const TWILIO_ACCOUNT_SID = 'AC232fe9ef86fd51105da3e3d4acaef1af';
const TWILIO_AUTH_TOKEN = 'f1c6938708c15fb440f936513dce4757';
const TWILIO_PHONE_NUMBER = '+18782187370';
const REGISTERED_PHONE_NUMBER ='+919790637955';

// Monitoring settings
const MONITORING_INTERVAL = 10000; // Check every 10 seconds
const DNS_LOG_FILE = '/var/log/dns_queries.log'; // DNS log path (if available)
// ============================================

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Twilio Client
let twilioClient;
if (TWILIO_ACCOUNT_SID !== 'your_account_sid_here' && TWILIO_AUTH_TOKEN !== 'your_auth_token_here') {
  twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  console.log('✅ Twilio configured successfully');
} else {
  console.log('⚠️  Twilio not configured. Update credentials in server.js to enable SMS alerts');
}

// Storage
let appLogs = [];
let activeProcesses = new Map(); // Track currently running processes
const recentAlerts = new Map();
const ALERT_COOLDOWN = 300000; // 5 minutes

// Age-restricted and suspicious keywords
const AGE_RESTRICTED_KEYWORDS = [
  'porn', 'xxx', 'adult', 'sex', 'nsfw', 'xvideos', 'pornhub', 'xhamster',
  'redtube', 'youporn', 'tube8', 'spankwire', 'redwap', 'beeg',
  'gambling', 'casino', 'poker', 'betting', 'darkweb', 'onion'
];

const SUSPICIOUS_ACTIVITIES = {
  vpn: ['vpn', 'nordvpn', 'expressvpn', 'protonvpn', 'tunnelbear', 'windscribe', 
        'surfshark', 'cyberghost', 'hotspot shield', 'privatevpn'],
  incognito: ['incognito', 'private', 'inprivate', 'tor browser', 'tor.exe'],
  proxy: ['proxy', 'proxifier', 'socks', 'shadowsocks'],
  distracting: ['youtube', 'facebook', 'instagram', 'twitter', 'tiktok', 'reddit',
                'netflix', 'twitch', 'discord', 'whatsapp', 'telegram', 'snapchat', 'gaming']
};

/**
 * Send SMS alert via Twilio
 */
async function sendAlert(message) {
  if (!twilioClient) {
    console.warn('⚠️  Twilio not configured. Alert:', message);
    return false;
  }

  try {
    const msg = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: REGISTERED_PHONE_NUMBER
    });
    console.log('✅ SMS Alert sent:', msg.sid);
    return true;
  } catch (error) {
    console.error('❌ Failed to send SMS:', error.message);
    return false;
  }
}

/**
 * Check if alert should be sent (cooldown)
 */
function shouldSendAlert(alertKey) {
  const lastAlertTime = recentAlerts.get(alertKey);
  const now = Date.now();
  
  if (!lastAlertTime || (now - lastAlertTime) > ALERT_COOLDOWN) {
    recentAlerts.set(alertKey, now);
    return true;
  }
  return false;
}

/**
 * Detect anomalies and send alerts
 */
function detectAnomaliesAndAlert(appName, type = 'APP') {
  const lowerName = appName.toLowerCase();
  const alerts = [];

  // Check for age-restricted content
  for (const keyword of AGE_RESTRICTED_KEYWORDS) {
    if (lowerName.includes(keyword)) {
      const alertKey = `age_restricted_${keyword}`;
      if (shouldSendAlert(alertKey)) {
        const message = `🚨 AGE-RESTRICTED CONTENT DETECTED!\n\nType: ${type}\nApp/Site: ${appName}\nKeyword: ${keyword.toUpperCase()}\nTime: ${new Date().toLocaleString()}`;
        sendAlert(message);
        alerts.push('AGE_RESTRICTED');
      }
      break;
    }
  }

  // Check for VPN usage
  for (const vpn of SUSPICIOUS_ACTIVITIES.vpn) {
    if (lowerName.includes(vpn)) {
      const alertKey = `vpn_${vpn}`;
      if (shouldSendAlert(alertKey)) {
        const message = `🚨 VPN USAGE DETECTED!\n\nApp: ${appName}\nVPN: ${vpn.toUpperCase()}\nTime: ${new Date().toLocaleString()}`;
        sendAlert(message);
        alerts.push('VPN_USAGE');
      }
      break;
    }
  }

  // Check for incognito/private browsing
  for (const incog of SUSPICIOUS_ACTIVITIES.incognito) {
    if (lowerName.includes(incog)) {
      const alertKey = 'incognito_mode';
      if (shouldSendAlert(alertKey)) {
        const message = `🔒 INCOGNITO/PRIVATE MODE DETECTED!\n\nApp: ${appName}\nTime: ${new Date().toLocaleString()}`;
        sendAlert(message);
        alerts.push('INCOGNITO_MODE');
      }
      break;
    }
  }

  // Check for proxy usage
  for (const proxy of SUSPICIOUS_ACTIVITIES.proxy) {
    if (lowerName.includes(proxy)) {
      const alertKey = `proxy_${proxy}`;
      if (shouldSendAlert(alertKey)) {
        const message = `⚠️ PROXY DETECTED!\n\nApp: ${appName}\nProxy: ${proxy.toUpperCase()}\nTime: ${new Date().toLocaleString()}`;
        sendAlert(message);
        alerts.push('PROXY_USAGE');
      }
      break;
    }
  }

  // Check for distracting sites
  for (const site of SUSPICIOUS_ACTIVITIES.distracting) {
    if (lowerName.includes(site)) {
      const alertKey = `distraction_${site}`;
      if (shouldSendAlert(alertKey)) {
        const message = `⚠️ DISTRACTING SITE DETECTED!\n\nSite: ${site.toUpperCase()}\nApp: ${appName}\nTime: ${new Date().toLocaleString()}`;
        sendAlert(message);
        alerts.push('DISTRACTING_SITE');
      }
      break;
    }
  }

  return alerts.length > 0 ? alerts.join(', ') : 'None';
}

/**
 * Get running processes (Windows)
 */
function getWindowsProcesses() {
  return new Promise((resolve) => {
    exec('tasklist /fo csv /nh', (error, stdout) => {
      if (error) {
        console.error('Error getting Windows processes:', error);
        resolve([]);
        return;
      }

      const processes = stdout.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const match = line.match(/"([^"]+)"/);
          return match ? match[1] : '';
        })
        .filter(name => name && !name.includes('System') && !name.includes('svchost'));

      resolve([...new Set(processes)]); // Remove duplicates
    });
  });
}

/**
 * Get running processes (Linux/Mac)
 */
function getUnixProcesses() {
  return new Promise((resolve) => {
    exec('ps aux | awk \'{print $11}\'', (error, stdout) => {
      if (error) {
        console.error('Error getting Unix processes:', error);
        resolve([]);
        return;
      }

      const processes = stdout.split('\n')
        .filter(line => line.trim() && !line.startsWith('[') && !line.startsWith('/'))
        .map(line => line.split('/').pop())
        .filter(name => name.length > 0);

      resolve([...new Set(processes)]); // Remove duplicates
    });
  });
}

/**
 * Get active network connections (DNS queries)
 */
function getNetworkConnections() {
  return new Promise((resolve) => {
    const platform = os.platform();
    let command;

    if (platform === 'win32') {
      command = 'netstat -n | findstr ESTABLISHED';
    } else {
      command = 'netstat -n | grep ESTABLISHED';
    }

    exec(command, (error, stdout) => {
      if (error) {
        resolve([]);
        return;
      }

      const connections = stdout.split('\n')
        .filter(line => line.includes(':'))
        .map(line => {
          const parts = line.trim().split(/\s+/);
          return parts[1] || parts[0];
        })
        .filter(conn => conn);

      resolve(connections);
    });
  });
}

/**
 * Monitor system processes and log them
 */
async function monitorSystem() {
  try {
    const platform = os.platform();
    let processes;

    if (platform === 'win32') {
      processes = await getWindowsProcesses();
    } else {
      processes = await getUnixProcesses();
    }

    const now = new Date().toISOString();

    // Check each process
    for (const processName of processes) {
      if (!activeProcesses.has(processName)) {
        // New process detected
        activeProcesses.set(processName, now);

        const anomaly = detectAnomaliesAndAlert(processName, 'PROCESS');

        const log = {
          id: Date.now() + Math.random(),
          appName: processName,
          type: 'BACKGROUND_PROCESS',
          startTime: now,
          stopTime: now,
          anomaly,
          loggedAt: now,
          platform: platform
        };

        appLogs.push(log);
        console.log(`📝 New process detected: ${processName}${anomaly !== 'None' ? ' ⚠️ ANOMALY: ' + anomaly : ''}`);
      }
    }

    // Get network connections
    const connections = await getNetworkConnections();
    for (const conn of connections) {
      const anomaly = detectAnomaliesAndAlert(conn, 'DNS/NETWORK');
      
      if (anomaly !== 'None') {
        const log = {
          id: Date.now() + Math.random(),
          appName: conn,
          type: 'NETWORK_CONNECTION',
          startTime: now,
          stopTime: now,
          anomaly,
          loggedAt: now,
          platform: platform
        };

        appLogs.push(log);
        console.log(`🌐 Network connection: ${conn} ⚠️ ANOMALY: ${anomaly}`);
      }
    }

    // Clean up old processes (not seen in last check)
    const currentProcessSet = new Set(processes);
    for (const [processName] of activeProcesses) {
      if (!currentProcessSet.has(processName)) {
        activeProcesses.delete(processName);
      }
    }

  } catch (error) {
    console.error('Error monitoring system:', error);
  }
}

/**
 * Start automatic system monitoring
 */
let monitoringInterval;
function startMonitoring() {
  console.log('🔍 Starting system monitoring...');
  monitoringInterval = setInterval(monitorSystem, MONITORING_INTERVAL);
  monitorSystem(); // Run immediately
}

function stopMonitoring() {
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    console.log('⏹️  System monitoring stopped');
  }
}

// ============================================
// API ENDPOINTS
// ============================================

/**
 * POST /log-usage - Manual log entry
 */
app.post('/log-usage', (req, res) => {
  const { appName, startTime, stopTime } = req.body;

  if (!appName || !startTime || !stopTime) {
    return res.status(400).json({ 
      error: 'Missing required fields: appName, startTime, stopTime' 
    });
  }

  const anomaly = detectAnomaliesAndAlert(appName, 'MANUAL_ENTRY');

  const log = {
    id: Date.now() + Math.random(),
    appName,
    type: 'MANUAL_ENTRY',
    startTime: new Date(startTime).toISOString(),
    stopTime: new Date(stopTime).toISOString(),
    anomaly,
    loggedAt: new Date().toISOString()
  };

  appLogs.push(log);
  console.log('📝 Manual log entry:', log);

  res.json({ 
    message: 'Log saved successfully', 
    log,
    alertSent: anomaly !== 'None'
  });
});

/**
 * GET /get-logs - Retrieve filtered logs
 */
app.get('/get-logs', (req, res) => {
  const { startTime, stopTime } = req.query;

  if (!startTime || !stopTime) {
    return res.status(400).json({ 
      error: 'Missing required query parameters: startTime, stopTime' 
    });
  }

  const start = new Date(startTime);
  const stop = new Date(stopTime);

  const filteredLogs = appLogs.filter(log => {
    const logStart = new Date(log.startTime);
    return logStart >= start && logStart <= stop;
  });

  res.json(filteredLogs);
});

/**
 * GET /all-logs - Get all logs
 */
app.get('/all-logs', (req, res) => {
  res.json(appLogs);
});

/**
 * DELETE /clear-logs - Clear all logs
 */
app.delete('/clear-logs', (req, res) => {
  const count = appLogs.length;
  appLogs = [];
  activeProcesses.clear();
  recentAlerts.clear();
  res.json({ message: `Cleared ${count} logs` });
});

/**
 * POST /test-alert - Test SMS
 */
app.post('/test-alert', async (req, res) => {
  const success = await sendAlert('🧪 Test Alert: System monitoring is active!');
  res.json({ 
    message: success ? 'Test alert sent successfully' : 'Failed to send alert',
    success 
  });
});

/**
 * GET /stats - Usage statistics
 */
app.get('/stats', (req, res) => {
  const stats = {
    totalLogs: appLogs.length,
    anomalyCount: appLogs.filter(log => log.anomaly !== 'None').length,
    ageRestricted: appLogs.filter(log => log.anomaly.includes('AGE_RESTRICTED')).length,
    vpnUsage: appLogs.filter(log => log.anomaly.includes('VPN_USAGE')).length,
    incognitoMode: appLogs.filter(log => log.anomaly.includes('INCOGNITO_MODE')).length,
    proxyUsage: appLogs.filter(log => log.anomaly.includes('PROXY_USAGE')).length,
    distractingSites: appLogs.filter(log => log.anomaly.includes('DISTRACTING_SITE')).length,
    activeProcesses: activeProcesses.size,
    recentAlerts: recentAlerts.size
  };
  res.json(stats);
});

/**
 * POST /start-monitoring - Start system monitoring
 */
app.post('/start-monitoring', (req, res) => {
  if (monitoringInterval) {
    return res.json({ message: 'Monitoring already running' });
  }
  startMonitoring();
  res.json({ message: 'System monitoring started' });
});

/**
 * POST /stop-monitoring - Stop system monitoring
 */
app.post('/stop-monitoring', (req, res) => {
  stopMonitoring();
  res.json({ message: 'System monitoring stopped' });
});

/**
 * GET /monitoring-status - Check monitoring status
 */
app.get('/monitoring-status', (req, res) => {
  res.json({ 
    active: !!monitoringInterval,
    activeProcesses: activeProcesses.size,
    interval: MONITORING_INTERVAL
  });
});

/**
 * GET /health - Health check
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    twilioConfigured: !!twilioClient,
    monitoringActive: !!monitoringInterval,
    platform: os.platform()
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log('=====================================');
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`💻 Platform: ${os.platform()}`);
  console.log('=====================================');
  console.log(`📱 Twilio configured: ${!!twilioClient}`);
  console.log(`🔍 Auto-monitoring: ENABLED (${MONITORING_INTERVAL/1000}s interval)`);
  console.log('=====================================');
  
  if (!twilioClient) {
    console.log('\n⚠️  TO ENABLE SMS ALERTS:');
    console.log('1. Get Twilio credentials from https://www.twilio.com');
    console.log('2. Update configuration at top of server.js');
    console.log('3. Restart server');
    console.log('=====================================');
  }

  // Start automatic monitoring
  startMonitoring();
  
  console.log('\n✅ System monitoring started!');
  console.log('📊 Tracking:');
  console.log('   - All running processes');
  console.log('   - Network connections');
  console.log('   - Age-restricted content');
  console.log('   - VPN/Proxy usage');
  console.log('   - Incognito/Private browsing');
  console.log('   - Distracting sites');
  console.log('=====================================\n');
});

// Cleanup on exit
process.on('SIGINT', () => {
  console.log('\n⏹️  Shutting down...');
  stopMonitoring();
  process.exit();
});