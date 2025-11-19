<?php
        /**
         * ============================================================================
         * PHP Hosting Benchmark Dashboard
         * ============================================================================
         * 
         * A comprehensive PHP server monitoring and benchmarking tool designed to
         * evaluate hosting performance across multiple dimensions.
         * 
         * FEATURES:
         * - Real-time server metrics (CPU, Memory, Disk, Network)
         * - Performance benchmarking (CPU, Filesystem, Database, Cache)
         * - PHP configuration and extension information
         * - Network latency and concurrency testing
         * - Standalone MySQL/MariaDB performance testing
         * - Dark/Light mode support with modern UI
         * 
         * SECURITY NOTICE:
         * ⚠️ This script is intended for SERVER EVALUATION ONLY
         * ⚠️ DO NOT leave this file on a production server after testing
         * ⚠️ Always delete or restrict access after completing your benchmarks
         * ⚠️ This tool has diagnostic error reporting enabled by design
         * 
         * REQUIREMENTS:
         * - PHP 7.0 or higher (PHP 8.x recommended)
         * - Basic filesystem read/write permissions
         * - Optional: SQLite3, Redis, Memcached, GD for extended testing
         * 
         * USAGE:
         * 1. Upload this file to your web server
         * 2. Change the default password (required - script won't run with default)
         * 3. Access via web browser
         * 4. Run benchmarks and review results
         * 5. IMPORTANT: Delete this file after testing
         * 
         * @package    php-hosting-benchmark
         * @version    1.0.1
         * @license    MIT License
         * @author     loayai (ai generated code)
         * @link       https://github.com/loayai/php-hosting-benchmark
         * 
         * ============================================================================
         */

        // ============================================================================
        // SECURITY CONFIGURATION
        // ============================================================================

        /**
         * Admin credentials for dashboard access
         * 
         * ⚠️ SECURITY REQUIREMENT: YOU MUST CHANGE THE PASSWORD
         * 
         * The script will refuse to run with the default password to prevent
         * unauthorized access. Choose a strong, unique password.
         * 
         * Note: The username can remain 'admin' if desired, but changing it
         * provides an additional layer of security.
         */
        $ADMIN_USERNAME = 'admin';
        $ADMIN_PASSWORD = 'password'; // <--- Update this!

        /**
         * Benchmark Scoring Mode Configuration
         * 'modern' = 2025 scoring with strict thresholds (default)
         * 'light' = Legacy scoring with generous thresholds
         */
        $DEFAULT_SCORING_MODE = 'modern';  // Can be overridden by URL parameter

        /**
         * Security Check: Enforce password modification
         * 
         * This critical security check prevents the script from running with the default
         * password. If users forget to change the default password, the script will
         * display an error page and refuse to load.
         * 
         * This is a defense-in-depth measure to prevent unauthorized access in case
         * the file is accidentally deployed with default settings.
         */
        if ($ADMIN_PASSWORD === 'password') {
            // Attempt to load the main CSS for consistent styling
            $css = function_exists('get_main_css') ? get_main_css() : '';
            
            die(<<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Warning</title>
            <style>
                {$css}
                body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; font-family: sans-serif; }
                .alert-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); max-width: 500px; text-align: center; border-top: 6px solid #ef4444; }
                h2 { color: #ef4444; margin-top: 0; }
                code { background: #eee; padding: 4px 8px; border-radius: 4px; font-family: monospace; color: #333; }
            </style>
        </head>
        <body>
            <div class="alert-box">
                <h2>🛑 Security Halt</h2>
                <p>For your safety, this script is disabled until you change the default password.</p>
                <p>Please open this file in a text editor and change <code>$ADMIN_PASSWORD</code> to something unique.</p>
                <p><em>Default password detected: <strong>password</strong></em></p>
            </div>
        </body>
        </html>
    HTML
            );
        }

        // ============================================================================
        // STYLING & UI FUNCTIONS
        // ============================================================================

        /**
         * Returns the main CSS stylesheet with theme variables
         * Supports both light and dark mode
         * 
         * @return string CSS stylesheet content
         */
        function get_main_css() {
            return <<<CSS
        :root {
            --color-primary-950: #04103b;
            --color-primary-900: #0c1f5f;
            --color-primary-800: #153189;
            --color-primary-700: #1e40ad;
            --color-primary-600: #4564e4;
            --color-primary-500: #7685e4;
            --color-primary-400: #9ba4e6;
            --color-primary-300: #c0c5eb;
            --color-primary-200: #cfd2ed;
            --color-primary-100: #dee0f0;
            --color-primary-50: #f3f4f9;

            --bg-primary: #f5f7fa;
            --bg-secondary: radial-gradient(circle at top, var(--color-primary-800), var(--color-primary-900), var(--color-primary-950));
            --surface: rgba(255, 255, 255, 0.95);
            --surface-hover: rgba(255, 255, 255, 1);
            --text-primary: #1a2332;
            --text-secondary: #4a5568;
            --text-muted: rgba(24, 44, 102, 0.8);
            --border-color: rgba(23, 54, 135, 0.12);
            --border-color-strong: rgba(23, 54, 135, 0.2);
            --shadow-sm: 0 2px 8px rgba(4, 16, 59, 0.08);
            --shadow-md: 0 10px 30px rgba(4, 16, 59, 0.12);
            --shadow-lg: 0 20px 40px rgba(4, 16, 59, 0.35);

            --color-success: #10b981;
            --color-warning: #f59e0b;
            --color-danger: #ef4444;
            --color-info: #3b82f6;

            --chart-cpu: #8b5cf6;
            --chart-memory: #06b6d4;
            --chart-disk: #f59e0b;
            --chart-network: #10b981;
        }

        body.dark-mode {
            --bg-primary: #0f172a;
            --bg-secondary: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            --surface: rgba(30, 41, 59, 0.95);
            --surface-hover: rgba(30, 41, 59, 1);
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --text-muted: rgba(203, 213, 225, 0.8);
            --border-color: rgba(148, 163, 184, 0.12);
            --border-color-strong: rgba(148, 163, 184, 0.2);
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 10px 30px rgba(0, 0, 0, 0.4);
            --shadow-lg: 0 20px 40px rgba(0, 0, 0, 0.6);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            font-size: 14px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s ease, color 0.3s ease;
        }
        CSS;
        }

        // ============================================================================
        // AUTHENTICATION & SESSION MANAGEMENT
        // ============================================================================

        session_start();

        /**
         * Handle logout request
         */
        if (isset($_GET['logout'])) {
            session_destroy();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }

        /**
         * Process login form submission
         * Uses hash_equals() for constant-time comparison
         */
        if (isset($_POST['username']) && isset($_POST['password'])) {
            if (hash_equals($ADMIN_USERNAME, $_POST['username']) && hash_equals($ADMIN_PASSWORD, $_POST['password'])) {
                $_SESSION['authenticated'] = true;
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                $login_error = 'Invalid username or password';
            }
        }

        /**
         * Display login form if user is not authenticated
         */
        if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
                <title>Login Required</title>
                <style>
                    <?php echo get_main_css(); ?>
                    
                    body {
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        padding: 20px;
                    }
                    .login-container {
                        background: var(--surface);
                        padding: 40px;
                        border-radius: 20px;
                        box-shadow: var(--shadow-lg);
                        width: 100%;
                        max-width: 400px;
                        backdrop-filter: blur(10px);
                    }
                    .login-container h2 {
                        font-size: 28px;
                        font-weight: 700;
                        margin: 0 0 30px 0;
                        text-align: center;
                        color: var(--text-primary);
                    }
                    .form-group {
                        margin-bottom: 20px;
                    }
                    .form-group label {
                        display: block;
                        margin-bottom: 8px;
                        color: var(--text-secondary);
                        font-weight: 600;
                        font-size: 14px;
                    }
                    .form-group input {
                        width: 100%;
                        padding: 12px 16px;
                        border: 1px solid var(--border-color);
                        border-radius: 10px;
                        font-size: 14px;
                        color: var(--text-primary);
                        background: white;
                        transition: all 0.2s ease;
                    }
                    .form-group input:focus {
                        outline: none;
                        border-color: var(--color-primary-600);
                        box-shadow: 0 0 0 3px rgba(69, 100, 228, 0.1);
                    }
                    .login-btn {
                        width: 100%;
                        padding: 14px;
                        background: linear-gradient(135deg, var(--color-primary-600), var(--color-primary-500));
                        color: white;
                        border: none;
                        border-radius: 10px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        margin-top: 10px;
                    }
                    .login-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 10px 20px rgba(69, 100, 228, 0.3);
                    }
                    .login-btn:active {
                        transform: translateY(0);
                    }
                    .error {
                        background: rgba(239, 68, 68, 0.1);
                        color: #dc2626;
                        padding: 12px 16px;
                        border-radius: 10px;
                        margin-bottom: 20px;
                        text-align: center;
                        font-size: 14px;
                        border: 1px solid rgba(239, 68, 68, 0.2);
                    }
                </style>
            </head>
            <body>
                <div class="login-container">
                    <h2>🔒 Login Required</h2>
                    <?php if (isset($login_error)): ?>
                        <div class="error"><?php echo htmlspecialchars($login_error); ?></div>
                    <?php endif; ?>
                    <form method="POST" action="">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required autofocus>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit" class="login-btn">Login</button>
                    </form>
                </div>
            </body>
            </html>
            <?php
            exit;
        }

        // ============================================================================
        // INITIALIZATION & SECURITY HEADERS
        // ============================================================================

        /**
         * Error Reporting Configuration
         * 
         * Error reporting is intentionally ENABLED for this benchmark tool.
         * 
         * WHY? This tool needs to reveal server capabilities and limitations.
         * If a function is disabled or an extension is missing, you need to see
         * the error to understand your server's configuration.
         * 
         * IMPORTANT: This is appropriate for a diagnostic tool, but would NOT
         * be suitable for a production application.
         */
        error_reporting(E_ALL);
        ini_set('display_errors', '1');
        
        /**
         * Security Headers
         * 
         * Implements multiple layers of browser-level security:
         * - Content-Type: Prevents MIME-type sniffing attacks
         * - X-Frame-Options: Prevents clickjacking attacks
         * - X-XSS-Protection: Enables browser XSS filtering
         * - X-Robots-Tag: Prevents search engine indexing (important for security)
         */
        header("Content-Type: text/html; charset=utf-8");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: SAMEORIGIN");
        header("X-XSS-Protection: 1; mode=block");
        header("X-Robots-Tag: noindex, nofollow, noarchive, nosnippet");
        
        // Set timezone to UTC for consistent timestamp handling
        date_default_timezone_set('UTC');

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * Sanitize user input to prevent XSS and injection attacks
         * 
         * This function provides two sanitization modes:
         * 1. 'string' mode: Removes HTML tags and escapes special characters
         *    - Used for text that will be displayed in HTML
         *    - Prevents XSS attacks by encoding quotes and special chars
         * 
         * 2. 'alnum' mode: Strips all non-alphanumeric characters
         *    - Used for benchmark test names and identifiers
         *    - Prevents injection attacks by allowing only safe characters
         * 
         * @param string $input The user input to sanitize
         * @param string $type Sanitization mode: 'string' (default) or 'alnum'
         * @return string Sanitized and safe output
         */
        function sanitize_input($input, $type = 'string') {
                if ($type === 'string') {
                    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
                } elseif ($type === 'alnum') {
                    return preg_replace('/[^a-zA-Z0-9_]/', '', $input);
                }
                return $input;
            }

        /**
         * Script execution timer start
         * Used to calculate total page generation time displayed in footer
         */
        $time_start = microtime(true);

        /**
         * Format bytes into human-readable size (B, KB, MB, GB, TB)
         * 
         * @param int|float $size Size in bytes
         * @return string Formatted size string
         */
        function formatsize($size) {
                $units = ['B', 'KB', 'MB', 'GB', 'TB'];
                $size = max($size, 0);
                $pow = floor(($size ? log($size) : 0) / log(1024));
                $pow = min($pow, count($units) - 1);
                $size /= pow(1024, $pow);
                return round($size, 3) . ' ' . $units[$pow];
            }

        /**
         * Get current PHP memory usage
         * 
         * @return string Memory usage in MB
         */
        function memory_usage() {
            if (!function_exists('memory_get_usage')) return '0 MB';
            return round(memory_get_usage() / 1024 / 1024, 2) . ' MB';
        }

        // ============================================================================
        // SYSTEM INFORMATION FUNCTIONS
        // ============================================================================

        /**
         * Detect hosting environment type and restrictions
         * Determines if running on shared hosting, VPS, or dedicated server
         * 
         * @return array Environment information including type and restrictions
         */
        function detect_hosting_environment() {
                $env = [
                    'type' => 'shared', 
                    'has_proc_access' => false,
                    'has_system_access' => false,
                    'restrictions' => []
                ];

        if (@is_readable('/proc/cpuinfo') && @is_readable('/proc/meminfo') && @is_readable('/proc/uptime')) {
                    $env['has_proc_access'] = true;
                    $env['type'] = 'vps'; 
                }

        if (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', ini_get('disable_functions'))))) {
                    $test = @shell_exec('echo test 2>&1');
                    if (trim($test) === 'test') {
                        $env['has_system_access'] = true;
                        $env['type'] = 'dedicated';
                    }
                }

        $open_basedir = ini_get('open_basedir');
                if (!empty($open_basedir)) {
                    $env['restrictions'][] = 'open_basedir';
                }

                $disabled_functions = ini_get('disable_functions');
                if (!empty($disabled_functions)) {
                    $env['restrictions'][] = 'disabled_functions';
                }


            return $env;
        }

        /**
         * Get CPU information including model, cores, frequency, and cache
         * Falls back to PHP limits on restricted shared hosting
         * 
         * @return array CPU information
         */
        function get_cpu_info() {
                $cpu = [
                    'model' => 'N/A',
                    'cores' => 1,
                    'mhz' => '',
                    'cache' => '',
                    'bogomips' => '',
                    'restricted' => false
                ];

                if (@is_readable('/proc/cpuinfo')) {
                    $cpuinfo = @file_get_contents('/proc/cpuinfo');
                    if ($cpuinfo) {
                        if (preg_match('/model name\s*:\s*(.+)/i', $cpuinfo, $match)) {
                            $cpu['model'] = trim($match[1]);
                        }
                        if (preg_match('/cpu MHz\s*:\s*([\d\.]+)/i', $cpuinfo, $match)) {
                            $cpu['mhz'] = round($match[1] / 1000, 3);
                        }
                        if (preg_match('/cache size\s*:\s*([\d]+)\s*KB/i', $cpuinfo, $match)) {
                            $cpu['cache'] = $match[1];
                        }
                        if (preg_match('/bogomips\s*:\s*([\d\.]+)/i', $cpuinfo, $match)) {
                            $cpu['bogomips'] = $match[1];
                        }
                        $cpu['cores'] = substr_count($cpuinfo, 'processor');
                    }
                } else {

                    $cpu['model'] = 'N/A - Restricted on shared hosting';
                    $cpu['restricted'] = true;
                }

            return $cpu;
        }

        /**
         * Calculate CPU usage percentages by reading /proc/stat
         * Measures user, system, idle, and other CPU states
         * 
         * @return array CPU usage percentages
         */
        function get_cpu_usage() {
                $cpu_usage = ['user' => 0, 'sys' => 0, 'nice' => 0, 'idle' => 0, 'iowait' => 0, 'irq' => 0, 'softirq' => 0];

                if (@is_readable('/proc/stat')) {
                    $stat1 = @file_get_contents('/proc/stat');
                    if ($stat1 && preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat1, $matches1)) {

        usleep(100000); // 0.1 seconds - efficient for live dashboard 

                        $stat2 = @file_get_contents('/proc/stat');
                        if ($stat2 && preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat2, $matches2)) {
                            $dif = [];
                            $dif['user'] = $matches2[1] - $matches1[1];
                            $dif['nice'] = $matches2[2] - $matches1[2];
                            $dif['sys'] = $matches2[3] - $matches1[3];
                            $dif['idle'] = $matches2[4] - $matches1[4];
                            $dif['iowait'] = $matches2[5] - $matches1[5];
                            $dif['irq'] = $matches2[6] - $matches1[6];
                            $dif['softirq'] = $matches2[7] - $matches1[7];

                            $total = array_sum($dif);
                            if ($total > 0) {
                                foreach ($dif as $key => $val) {
                                    $cpu_usage[$key] = round(($val / $total) * 100, 0);
                                }
                            }
                        }
                    }
                }

            return $cpu_usage;
        }

        /**
         * Get system memory information including total, used, free, cached, and swap
         * Falls back to PHP memory_limit on restricted shared hosting
         * 
         * @return array Memory information in MB
         */
        function get_memory_info() {
                $memory = [
                    'total' => 0, 'free' => 0, 'used' => 0, 'percent' => 0,
                    'buffers' => 0, 'cached' => 0, 'real_used' => 0, 'real_free' => 0, 'real_percent' => 0,
                    'swap_total' => 0, 'swap_used' => 0, 'swap_free' => 0, 'swap_percent' => 0,
                    'restricted' => false, 'is_php_limit' => false
                ];

                if (@is_readable('/proc/meminfo')) {
                    $meminfo = @file_get_contents('/proc/meminfo');
                    if ($meminfo) {
                        if (preg_match('/MemTotal:\s+(\d+)\s+kB/i', $meminfo, $match)) {
                            $memory['total'] = round($match[1] / 1024, 2);
                        }
                        if (preg_match('/MemFree:\s+(\d+)\s+kB/i', $meminfo, $match)) {
                            $memory['free'] = round($match[1] / 1024, 2);
                        }
                        if (preg_match('/Buffers:\s+(\d+)\s+kB/i', $meminfo, $match)) {
                            $memory['buffers'] = round($match[1] / 1024, 2);
                        }
                        if (preg_match('/^Cached:\s+(\d+)\s+kB/im', $meminfo, $match)) {
                            $memory['cached'] = round($match[1] / 1024, 2);
                        }
                        if (preg_match('/SwapTotal:\s+(\d+)\s+kB/i', $meminfo, $match)) {
                            $memory['swap_total'] = round($match[1] / 1024, 2);
                        }
                        if (preg_match('/SwapFree:\s+(\d+)\s+kB/i', $meminfo, $match)) {
                            $memory['swap_free'] = round($match[1] / 1024, 2);
                        }

                        $memory['used'] = $memory['total'] - $memory['free'];
                        $memory['percent'] = $memory['total'] > 0 ? round(($memory['used'] / $memory['total']) * 100, 2) : 0;
                        $memory['real_used'] = $memory['total'] - $memory['free'] - $memory['cached'] - $memory['buffers'];
                        $memory['real_free'] = $memory['total'] - $memory['real_used'];
                        $memory['real_percent'] = $memory['total'] > 0 ? round(($memory['real_used'] / $memory['total']) * 100, 2) : 0;
                        $memory['swap_used'] = $memory['swap_total'] - $memory['swap_free'];
                        $memory['swap_percent'] = $memory['swap_total'] > 0 ? round(($memory['swap_used'] / $memory['swap_total']) * 100, 2) : 0;
                    }
                } else {

                    $memory['restricted'] = true;
                    $memory['is_php_limit'] = true;

                    $limit = ini_get('memory_limit');
                    if ($limit == '-1') {
                        $memory['total'] = 512; 
                    } elseif (preg_match('/^(\d+)(.)$/', $limit, $matches)) {
                        $memory_limit_mb = $matches[1];
                        if (strtoupper($matches[2]) == 'G') {
                            $memory_limit_mb *= 1024;
                        } elseif (strtoupper($matches[2]) == 'K') {
                            $memory_limit_mb /= 1024;
                        }
                        $memory['total'] = $memory_limit_mb;
                    }

        if (function_exists('memory_get_usage')) {
                        $memory['used'] = round(memory_get_usage(true) / 1024 / 1024, 2);
                        $memory['free'] = $memory['total'] - $memory['used'];
                        $memory['percent'] = $memory['total'] > 0 ? round(($memory['used'] / $memory['total']) * 100, 2) : 0;
                        $memory['real_used'] = $memory['used'];
                        $memory['real_free'] = $memory['free'];
                        $memory['real_percent'] = $memory['percent'];
                    }
                }

            return $memory;
        }

        /**
         * Get system uptime from /proc/uptime
         * 
         * @return string Formatted uptime string (e.g., "5 Days 12 Hours 30 Minutes")
         */
        function get_uptime() {
                if (@is_readable('/proc/uptime')) {
                    $uptime = @file_get_contents('/proc/uptime');
                    if ($uptime) {
                        $uptime_seconds = (int)explode(' ', $uptime)[0];
                        $days = floor($uptime_seconds / 86400);
                        $hours = floor(($uptime_seconds % 86400) / 3600);
                        $minutes = floor(($uptime_seconds % 3600) / 60);

                        $result = '';
                        if ($days > 0) $result .= $days . ' Days ';
                        if ($hours > 0) $result .= $hours . ' Hours ';
                        $result .= $minutes . ' Minutes';

                        return $result;
                    }
                }
            return 'N/A - Restricted on shared hosting';
        }

        /**
         * Get system load average (1min, 5min, 15min)
         * 
         * @return string Load average values
         */
        function get_load_average() {
                if (function_exists('sys_getloadavg')) {
                    $load = sys_getloadavg();
                    return implode(' ', array_map(function($v) { return round($v, 2); }, $load));
                }

                if (@is_readable('/proc/loadavg')) {
                    $load = @file_get_contents('/proc/loadavg');
                    if ($load) {
                        $parts = explode(' ', $load);
                        return $parts[0] . ' ' . $parts[1] . ' ' . $parts[2] . ' ' . $parts[3];
                    }
                }

            return 'N/A';
        }

        /**
         * Get network interface statistics (RX/TX bytes)
         * Reads from /proc/net/dev
         * 
         * @return array Network interfaces with RX/TX data
         */
        function get_network_info() {
                $interfaces = [];

                if (@is_readable('/proc/net/dev')) {
                    $net_dev = @file('/proc/net/dev');
                    if ($net_dev) {
                        foreach ($net_dev as $line) {
                            if (preg_match('/^\s*([^:]+):\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/', $line, $match)) {
                                $interface = trim($match[1]);
                                $interfaces[$interface] = [
                                    'rx' => (int)$match[2],
                                    'tx' => (int)$match[3]
                                ];
                            }
                        }
                    }
                }

            return $interfaces;
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - SCORING
        // ============================================================================

        /**
         * Calculate performance score (0-10) based on execution time
         * Uses tiered scoring: excellent (9-10), good (7-9), average (5-7), poor (2-5), very poor (0-2)
         * 
         * @param float $time Execution time in seconds
         * @param float $excellent Threshold for excellent performance
         * @param float $good Threshold for good performance
         * @param float $average Threshold for average performance
         * @param float $poor Threshold for poor performance
         * @return float Score from 0 to 10
         */
        /**
         * Scoring thresholds for different benchmark modes
         * Format: [excellent, good, average, poor] in seconds
         */
        $SCORING_THRESHOLDS = [
            'modern' => [
                // CPU & Memory Tests
                'cpu_int' => [0.4, 0.9, 1.8, 3.0],
                'cpu_float' => [0.5, 1.0, 1.8, 3.5],
                'cpu_text' => [0.35, 0.7, 1.4, 3.0],
                'cpu_binary' => [0.12, 0.25, 0.6, 1.5],
                'string' => [0.03, 0.08, 0.25, 0.6],
                'array' => [0.4, 0.9, 1.8, 3.5],
                'hash' => [0.25, 0.6, 1.2, 2.5],
                'json' => [0.3, 0.7, 1.5, 3.5],
                
                // Filesystem Tests
                'io' => [0.008, 0.04, 0.15, 0.5],
                'fs_write' => [0.1, 0.25, 0.6, 1.5],
                'fs_copy' => [0.2, 0.5, 1.2, 3.0],
                'fs_small' => [0.15, 0.5, 1.5, 4.0],
                
                // Database Tests
                'db_import' => [0.01, 0.03, 0.10, 0.4],
                'db_simple' => [0.02, 0.08, 0.25, 0.8],
                'db_complex' => [0.15, 0.4, 1.0, 2.5],
                
                // Cache Tests
                'opcache_performance' => [0.01, 0.05, 0.15, 0.4],
                'cache_write' => [0.02, 0.06, 0.15, 0.4],
                'cache_read' => [0.015, 0.04, 0.10, 0.25],
                'cache_mixed' => [0.018, 0.05, 0.12, 0.30],
                
                // Network Tests
                'network' => [0.1, 0.3, 0.8, 2.0],
                'network_latency_ms' => [2, 10, 40, 100],  // Note: in milliseconds
                'concurrency' => [0.0005, 0.002, 0.01, 0.1],
                
                // Advanced Tests (add these new ones)
                'regex' => [0.5, 1.2, 2.5, 5.0],
                'large_json' => [0.8, 2.0, 4.0, 8.0],
                'xml_parsing' => [0.6, 1.5, 3.0, 6.0],
                'password_hashing' => [3.0, 5.0, 8.0, 12.0],  // Intentionally slow
                'datetime' => [0.5, 1.2, 2.5, 5.0],
                'csv' => [0.3, 0.8, 2.0, 4.0],
                'session' => [0.4, 1.0, 2.5, 5.0],
                'image' => [0.8, 2.0, 4.0, 8.0]
            ],
            
            'light' => [
                // Use current/original thresholds
                'cpu_int' => [0.8, 1.5, 3.0, 6.0],
                'cpu_float' => [0.8, 1.8, 3.5, 7.0],
                'cpu_text' => [0.8, 2.0, 4.0, 8.0],
                'cpu_binary' => [0.5, 1.5, 3.0, 6.0],
                'string' => [0.5, 1.5, 3.0, 6.0],
                'array' => [0.8, 2.0, 4.0, 8.0],
                'hash' => [0.8, 1.8, 3.5, 7.0],
                'json' => [0.8, 2.0, 4.0, 8.0],
                
                'io' => [0.2, 0.5, 1.0, 2.0],
                'fs_write' => [0.8, 1.8, 3.5, 7.0],
                'fs_copy' => [1.0, 2.5, 5.0, 9.0],
                'fs_small' => [1.5, 3.5, 7.0, 12.0],
                
                'db_import' => [0.8, 1.8, 3.5, 7.0],
                'db_simple' => [0.5, 1.2, 2.5, 5.0],
                'db_complex' => [0.8, 2.0, 4.0, 8.0],
                
                'opcache_performance' => [0.5, 1.5, 3.0, 5.0],
                'cache_write' => [0.1, 0.25, 0.5, 1.0],
                'cache_read' => [0.08, 0.2, 0.4, 0.8],
                'cache_mixed' => [0.09, 0.22, 0.45, 0.9],
                
                'network' => [2.0, 4.0, 7.0, 12.0],
                'network_latency_ms' => [50, 150, 300, 500],
                'concurrency' => [0.1, 0.3, 0.8, 1.5],
                
                'regex' => [2.0, 4.5, 8.0, 14.0],
                'large_json' => [3.0, 6.0, 10.0, 16.0],
                'xml_parsing' => [2.5, 5.0, 9.0, 15.0],
                'password_hashing' => [8.0, 12.0, 18.0, 25.0],
                'datetime' => [2.5, 5.0, 8.0, 13.0],
                'csv' => [1.5, 3.5, 6.0, 10.0],
                'session' => [2.0, 4.5, 8.0, 14.0],
                'image' => [3.0, 6.0, 10.0, 16.0]
            ]
        ];

        function calculate_score($time, $excellent, $good, $average, $poor, $aggressive = true) {
                if ($time <= 0) return 0;
                
                if ($aggressive) {
                    // Modern 2025 scoring curve - stricter
                    if ($time <= $excellent) {
                        $ratio = $time / $excellent;
                        return 10 - ($ratio * 1.0);  // 10 to 9
                    } elseif ($time <= $good) {
                        $ratio = ($time - $excellent) / ($good - $excellent);
                        return 9 - ($ratio * 2);  // 9 to 7
                    } elseif ($time <= $average) {
                        $ratio = ($time - $good) / ($average - $good);
                        return 7 - ($ratio * 3);  // 7 to 4
                    } elseif ($time <= $poor) {
                        $ratio = ($time - $average) / ($poor - $average);
                        return 4 - ($ratio * 3);  // 4 to 1
                    } else {
                        return max(0, 1 - (($time - $poor) / $poor));  // 1 to 0
                    }
                } else {
                    // Legacy scoring curve - more generous
                    if ($time <= $excellent) {
                        $ratio = $time / $excellent;
                        return min(10, 9 + (1 - $ratio));
                    } elseif ($time <= $good) {
                        $ratio = ($time - $excellent) / ($good - $excellent);
                        return 9 - ($ratio * 2);
                    } elseif ($time <= $average) {
                        $ratio = ($time - $good) / ($average - $good);
                        return 7 - ($ratio * 2);
                    } elseif ($time <= $poor) {
                        $ratio = ($time - $average) / ($poor - $average);
                        return 5 - ($ratio * 3);
                    } else {
                        $ratio = min(($time - $poor) / $poor, 1);
                        return max(0, 2 - ($ratio * 2));
                    }
                }
            }

        // ============================================================================
        // BENCHMARK FUNCTIONS - CPU PERFORMANCE
        // ============================================================================

        /**
         * Benchmark CPU performance with large text processing operations
         * Tests string manipulation, case conversion, search, and replace operations
         * 
         * @return float Execution time in seconds
         */
        function benchmark_cpu_operations_large_text() {
                $start = microtime(true);
                $maxTime = 15.0;

                $text = str_repeat('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent vitae eros eget tellus tristique bibendum. ', 2000);

                for ($i = 0; $i < 5000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;

        $upper = strtoupper($text);
                    $lower = strtolower($text);
                    $len = strlen($text);
                    $pos = strpos($text, 'amet');

        $replaced = str_replace('Lorem', 'Test', $text);
                    $words = explode(' ', substr($text, 0, 500));
                    $trimmed = trim($text);
                    $encoded = htmlspecialchars(substr($text, 0, 200), ENT_QUOTES, 'UTF-8');
                }
            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark CPU performance with binary operations
         * Tests bitwise operations (AND, OR, XOR, shifts) and modulo operations
         * 
         * @return float Execution time in seconds
         */
        function benchmark_cpu_random_binary_operations() {
                $start = microtime(true);
                $maxTime = 15.0;

        for ($i = 0; $i < 2000000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;
                    $a = mt_rand(1, 1000000);
                    $b = mt_rand(1, 1000000);
                    $c = $a & $b;
                    $d = $a | $b;
                    $e = $a ^ $b;
                    $f = $a << 2;
                    $g = $b >> 2;

        $h = ($a + $b) % 1000000;
                    $j = abs($a - $b);
                    $k = (int)($a / max($b, 1));
                }
            return round((microtime(true) - $start), 3);
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - FILESYSTEM PERFORMANCE
        // ============================================================================

        /**
         * Benchmark filesystem write performance
         * 
         * Tests sequential file writes with metadata operations to evaluate disk I/O.
         * This benchmark measures:
         * - Raw write throughput
         * - fsync() performance (disk flush)
         * - Filesystem metadata operations (filesize, filemtime)
         * 
         * IMPORTANT: Uses __DIR__ instead of sys_get_temp_dir() to ensure testing
         * on actual disk storage, not RAM-based tmpfs which would give unrealistic
         * results on some Linux systems.
         * 
         * @return float Execution time in seconds (lower is better)
         */
        function benchmark_filesystem_write() {
                $start = microtime(true);
                $maxTime = 20.0;
                // Test on actual disk, not tmpfs/ramdisk for realistic results
                $testFile = __DIR__ . DIRECTORY_SEPARATOR . 'bench_write_' . uniqid() . '.tmp';
                $data = str_repeat('A', 10240); // 10KB per write 

                try {
                    $fp = fopen($testFile, 'wb');
                    if ($fp === false) {
                        error_log('Filesystem Write benchmark failed: Cannot open file for writing');
                        return 0;
                    }

                    for ($i = 0; $i < 5000; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;
                        
                        if (fwrite($fp, $data) === false) {
                            error_log('Filesystem Write benchmark failed at iteration ' . $i . ': Cannot write to file');
                            fclose($fp);
                            return 0;
                        }

                        // Force disk flush every 100 iterations to test true IOPS
                        if ($i % 100 == 0) {
                            if (function_exists('fsync')) {
                                fsync($fp);
                            }
                            fflush($fp); // Fallback if fsync not available
                            clearstatcache();
                            filesize($testFile);
                            filemtime($testFile);
                        }
                    }
                    
                    fclose($fp);
                } catch (Exception $e) {
                    error_log('Filesystem Write benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    if (file_exists($testFile)) {
                        unlink($testFile);
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark filesystem copy and access performance
         * Tests file copying with content verification
         * 
         * @return float Execution time in seconds
         */
        function benchmark_filesystem_copy_access() {
                $start = microtime(true);
                $maxTime = 20.0;
                // Use __DIR__ to test actual disk (not tmpfs/ramdisk)
                $sourceFile = __DIR__ . DIRECTORY_SEPARATOR . 'bench_source_' . uniqid() . '.tmp';
                $data = str_repeat('Test data for benchmark. This simulates a typical file. ', 500); 

                try {
                    if (file_put_contents($sourceFile, $data) === false) {
                        error_log('Filesystem Copy benchmark failed: Cannot create source file');
                        return 0;
                    }

                    for ($i = 0; $i < 2000; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;
                        $destFile = __DIR__ . DIRECTORY_SEPARATOR . 'bench_dest_' . $i . '.tmp';
                        if (copy($sourceFile, $destFile)) {
                            $content = file_get_contents($destFile);

                            if ($content !== false && strlen($content) > 0) {
                                if (file_exists($destFile)) {
                                    unlink($destFile);
                                }
                            }
                        } else {
                            error_log('Filesystem Copy benchmark failed at iteration ' . $i . ': Cannot copy file');
                            return 0;
                        }
                    }
                } catch (Exception $e) {
                    error_log('Filesystem Copy benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    if (file_exists($sourceFile)) {
                        unlink($sourceFile);
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark small file I/O operations
         * 
         * Simulates real-world PHP application behavior with many small files:
         * - Session files (typical: 100-500 bytes)
         * - Cache entries (JSON data structures)
         * - Configuration files
         * 
         * This test creates 100 small files and performs random read/write operations
         * to evaluate:
         * - Directory lookup performance
         * - Small file I/O speed
         * - JSON encode/decode overhead
         * - File locking behavior
         * 
         * Random access pattern (vs sequential) tests filesystem performance under
         * realistic load where files are accessed unpredictably.
         * 
         * @return float Execution time in seconds (lower is better)
         */
        function benchmark_filesystem_small_io() {
                $start = microtime(true);
                $maxTime = 20.0;
                $baseDir = __DIR__ . DIRECTORY_SEPARATOR . 'bench_io_' . uniqid();
                
                if (!mkdir($baseDir)) {
                    return 0;
                }

                try {
                    $files = [];
                    // Pre-create 100 file paths (simulating cache/session files)
                    for ($i = 0; $i < 100; $i++) {
                        $files[$i] = $baseDir . DIRECTORY_SEPARATOR . 'file_' . $i . '.tmp';
                    }

                    // Random Read/Write operations - forces directory lookups and seeks
                    for ($i = 0; $i < 5000; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;

                        $fileIndex = mt_rand(0, 99);
                        $file = $files[$fileIndex];
                        
                        // Write random small JSON
                        $data = json_encode([
                            'id' => $i, 
                            'val' => mt_rand(1, 1000), 
                            'text' => str_repeat('x', mt_rand(10, 100)),
                            'ts' => microtime(true)
                        ]);

                        if (file_put_contents($file, $data) === false) {
                            error_log('Filesystem Small I/O benchmark failed: Cannot write');
                            return 0;
                        }
                        
                        // Read back immediately
                        $content = file_get_contents($file);
                        if ($content === false) {
                            error_log('Filesystem Small I/O benchmark failed: Cannot read');
                            return 0;
                        }
                        
                        // Verify content (CPU overhead)
                        $decoded = json_decode($content, true);
                        if (!$decoded || $decoded['id'] !== $i) {
                            // Silent corruption check
                        }
                    }
                } catch (Exception $e) {
                    error_log('Filesystem Small I/O benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    // Cleanup
                    foreach ($files as $f) {
                        if (file_exists($f)) unlink($f);
                    }
                    if (is_dir($baseDir)) rmdir($baseDir);
                }

            return round((microtime(true) - $start), 3);
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - DATABASE PERFORMANCE
        // ============================================================================

        /**
         * Benchmark database bulk insert performance using SQLite
         * Tests large batch inserts with indexes and transactions
         * Measures disk I/O performance and PHP's SQLite driver efficiency
         * 
         * @return float Execution time in seconds, 0 if SQLite3 not available
         */
        function benchmark_database_import_large() {
                if (!class_exists('SQLite3')) return 0;

                $start = microtime(true);
                $maxTime = 25.0;
                $dbFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bench_db_' . uniqid() . '.sqlite';
                $db = null;

                try {
                    $db = new SQLite3($dbFile);
                    $db->enableExceptions(true);

        $db->exec('CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT, email TEXT, value INTEGER, data TEXT, created_at TEXT)');
                    $db->exec('CREATE INDEX idx_name ON test_table(name)');
                    $db->exec('CREATE INDEX idx_value ON test_table(value)');

                    $stmt = $db->prepare('INSERT INTO test_table (name, email, value, data, created_at) VALUES (:name, :email, :value, :data, :created_at)');

                    $db->exec('BEGIN TRANSACTION');
                    for ($i = 0; $i < 5000; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;
                        $stmt->bindValue(':name', 'User_' . $i, SQLITE3_TEXT);
                        $stmt->bindValue(':email', 'user' . $i . '@example.com', SQLITE3_TEXT);
                        $stmt->bindValue(':value', mt_rand(1, 10000), SQLITE3_INTEGER);
                        $stmt->bindValue(':data', str_repeat('x', 200), SQLITE3_TEXT); 
                        $stmt->bindValue(':created_at', date('Y-m-d H:i:s'), SQLITE3_TEXT);
                        $stmt->execute();
                        $stmt->reset();
                    }
                    $db->exec('COMMIT');

                    $stmt->close();
                } catch (Exception $e) {
                    error_log('Database Import benchmark failed: ' . $e->getMessage());
                    return 0; // Return 0 to indicate test failure
                } finally {
                    if ($db) {
                        $db->close();
                    }
                    if (file_exists($dbFile)) {
                        unlink($dbFile);
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark simple database queries using SQLite
         * Tests basic SELECT queries with WHERE clauses and indexes
         * Measures disk I/O performance and PHP's SQLite driver efficiency
         * 
         * @return float Execution time in seconds, 0 if SQLite3 not available
         */
        function benchmark_database_simple_queries() {
                if (!class_exists('SQLite3')) return 0;

                $start = microtime(true);
                $maxTime = 25.0;
                $dbFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bench_db_' . uniqid() . '.sqlite';
                $db = null;

                try {
                    $db = new SQLite3($dbFile);
                    $db->enableExceptions(true);

                    $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, status INTEGER)');
                    $db->exec('CREATE INDEX idx_username ON users(username)');

                    $insertStmt = $db->prepare('INSERT INTO users (username, email, status) VALUES (:username, :email, :status)');

                    $db->exec('BEGIN TRANSACTION');
                    for ($i = 0; $i < 500; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;
                        $insertStmt->bindValue(':username', 'user' . $i, SQLITE3_TEXT);
                        $insertStmt->bindValue(':email', 'user' . $i . '@test.com', SQLITE3_TEXT);
                        $insertStmt->bindValue(':status', mt_rand(0, 1), SQLITE3_INTEGER);
                        $insertStmt->execute();
                        $insertStmt->reset();
                    }
                    $db->exec('COMMIT');

                    $selectStmt = $db->prepare('SELECT * FROM users WHERE id = :id');
                    $selectByNameStmt = $db->prepare('SELECT * FROM users WHERE username = :username');

                    for ($i = 0; $i < 2000; $i++) { 
                        if ((microtime(true) - $start) > $maxTime) break;

        if ($i % 2 == 0) {
                            $selectStmt->bindValue(':id', mt_rand(1, 500), SQLITE3_INTEGER);
                            $result = $selectStmt->execute();
                            if ($result) {
                                $row = $result->fetchArray(SQLITE3_ASSOC);
                                $result->finalize();
                            }
                            $selectStmt->reset();
                        } else {
                            $selectByNameStmt->bindValue(':username', 'user' . mt_rand(1, 500), SQLITE3_TEXT);
                            $result = $selectByNameStmt->execute();
                            if ($result) {
                                $row = $result->fetchArray(SQLITE3_ASSOC);
                                $result->finalize();
                            }
                            $selectByNameStmt->reset();
                        }
                    }

                    $insertStmt->close();
                    $selectStmt->close();
                    $selectByNameStmt->close();
                } catch (Exception $e) {
                    error_log('Database Simple Queries benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    if ($db) {
                        $db->close();
                    }
                    if (file_exists($dbFile)) {
                        unlink($dbFile);
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark complex database queries using SQLite
         * Tests GROUP BY, ORDER BY, and aggregation operations
         * Measures disk I/O performance and PHP's SQLite driver efficiency
         * 
         * @return float Execution time in seconds, 0 if SQLite3 not available
         */
        function benchmark_database_complex_queries() {
                if (!class_exists('SQLite3')) return 0;

                $start = microtime(true);
                $maxTime = 30.0; 
                $dbFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bench_db_' . uniqid() . '.sqlite';
                $db = null;

                try {
                    $db = new SQLite3($dbFile);
                    $db->enableExceptions(true);

                    // Create more realistic e-commerce schema
                    $db->exec('CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, level INTEGER)');
                    $db->exec('CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)');
                    $db->exec('CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total REAL, status TEXT, date TEXT)');
                    $db->exec('CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER, product_id INTEGER, qty INTEGER, price REAL)');

                    $db->exec('CREATE INDEX idx_c_email ON customers(email)');
                    $db->exec('CREATE INDEX idx_p_cat ON products(category)');
                    $db->exec('CREATE INDEX idx_o_cust ON orders(customer_id)');
                    $db->exec('CREATE INDEX idx_oi_order ON order_items(order_id)');

                    // Seed data - heavier load
                    $db->exec('BEGIN TRANSACTION');
                    
                    // 1000 Customers
                    $stmtC = $db->prepare('INSERT INTO customers (name, email, level) VALUES (:name, :email, :level)');
                    for ($i = 0; $i < 1000; $i++) {
                        $stmtC->bindValue(':name', 'Customer ' . $i, SQLITE3_TEXT);
                        $stmtC->bindValue(':email', 'cust' . $i . '@shop.com', SQLITE3_TEXT);
                        $stmtC->bindValue(':level', mt_rand(1, 5), SQLITE3_INTEGER);
                        $stmtC->execute();
                        $stmtC->reset();
                    }
                    $stmtC->close();

                    // 500 Products
                    $stmtP = $db->prepare('INSERT INTO products (name, price, category) VALUES (:name, :price, :cat)');
                    $cats = ['Electronics', 'Books', 'Home', 'Garden', 'Toys'];
                    for ($i = 0; $i < 500; $i++) {
                        $stmtP->bindValue(':name', 'Product ' . $i, SQLITE3_TEXT);
                        $stmtP->bindValue(':price', mt_rand(10, 1000), SQLITE3_FLOAT);
                        $stmtP->bindValue(':cat', $cats[array_rand($cats)], SQLITE3_TEXT);
                        $stmtP->execute();
                        $stmtP->reset();
                    }
                    $stmtP->close();

                    // 2000 Orders with Items
                    $stmtO = $db->prepare('INSERT INTO orders (customer_id, total, status, date) VALUES (:cid, :total, :status, :date)');
                    $stmtOI = $db->prepare('INSERT INTO order_items (order_id, product_id, qty, price) VALUES (:oid, :pid, :qty, :price)');
                    
                    for ($i = 0; $i < 2000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;
                        
                        $stmtO->bindValue(':cid', mt_rand(1, 1000), SQLITE3_INTEGER);
                        $stmtO->bindValue(':total', mt_rand(50, 5000), SQLITE3_FLOAT);
                        $stmtO->bindValue(':status', mt_rand(0,1) ? 'completed' : 'pending', SQLITE3_TEXT);
                        $stmtO->bindValue(':date', date('Y-m-d'), SQLITE3_TEXT);
                        $stmtO->execute();
                        $oid = $db->lastInsertRowID();
                        $stmtO->reset();

                        // Add 1-5 items per order
                        $items = mt_rand(1, 5);
                        for ($j = 0; $j < $items; $j++) {
                            $stmtOI->bindValue(':oid', $oid, SQLITE3_INTEGER);
                            $stmtOI->bindValue(':pid', mt_rand(1, 500), SQLITE3_INTEGER);
                            $stmtOI->bindValue(':qty', mt_rand(1, 3), SQLITE3_INTEGER);
                            $stmtOI->bindValue(':price', mt_rand(10, 100), SQLITE3_FLOAT);
                            $stmtOI->execute();
                            $stmtOI->reset();
                        }
                    }
                    
                    $db->exec('COMMIT');
                    $stmtO->close();
                    $stmtOI->close();

                    // Complex E-commerce Reporting Query (JOINs + Aggregation)
                    // "Find top spending customers by category"
                    $query = "
                        SELECT c.name, p.category, SUM(oi.qty * oi.price) as total_spend
                        FROM customers c
                        JOIN orders o ON c.id = o.customer_id
                        JOIN order_items oi ON o.id = oi.order_id
                        JOIN products p ON oi.product_id = p.id
                        WHERE o.status = 'completed'
                        GROUP BY c.id, p.category
                        ORDER BY total_spend DESC
                        LIMIT 20
                    ";

                    for ($i = 0; $i < 50; $i++) { // 50 Heavy queries
                        if ((microtime(true) - $start) > $maxTime) break;
                        $result = $db->query($query);
                        if ($result) {
                            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {} // Fetch all
                            $result->finalize();
                        }
                    }

                } catch (Exception $e) {
                    error_log('Database Complex Queries benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    if ($db) {
                        $db->close();
                    }
                    if (file_exists($dbFile)) {
                        unlink($dbFile);
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Comprehensive standalone database performance benchmark (MySQL/MariaDB)
         * 
         * This function performs an extensive evaluation of database performance by
         * testing multiple aspects with multi-pass sampling to ensure accuracy:
         * 
         * TEST PHASES:
         * 1. Connection Latency (5 samples, outliers removed)
         *    - Measures TCP connection + authentication time
         *    - Scores: <2ms=10pts, <5ms=8pts, <10ms=5pts, <20ms=2pts
         * 
         * 2. Write Throughput (5 runs of 10,000 inserts each)
         *    - Tests bulk INSERT performance with transactions
         *    - Includes UUID generation, mixed data types, and 500-char text
         *    - Scores: >10k rows/s=15pts, >7.5k=12pts, >5k=9pts, >2.5k=5pts
         * 
         * 3. Read Throughput (5 runs of 2,000 queries each)
         *    - Tests indexed SELECT performance with WHERE clauses
         *    - Scores: >8k q/s=15pts, >6k=12pts, >4k=9pts, >2k=5pts
         * 
         * 4. CPU Performance (5 runs of 100 SHA2 operations)
         *    - Tests cryptographic hashing with aggregation
         *    - Measures database CPU capabilities
         *    - Scores: <200ms=10pts, <500ms=8pts, <800ms=6pts, <1000ms=4pts
         * 
         * SCORING: Total points out of 50, scaled to 0-10 score
         * 
         * SECURITY: Creates temporary table with random name, cleaned up on exit
         * 
         * @param string $host Database hostname or IP address
         * @param string $dbname Database name (must exist and be accessible)
         * @param string $user Database username with CREATE/INSERT/SELECT privileges
         * @param string $pass Database password
         * @param int $port Database port (default: 3306 for MySQL)
         * @return array ['success' => bool, 'score' => float, 'metrics' => array, 'error' => string]
         */
        function benchmark_database_standalone($host, $dbname, $user, $pass, $port = 3306) {
            $metrics = [];
            $points = 0;
            $maxPoints = 50; // Total available points (scaled to 0-10 score)

            try {
                // Connection Test - Multi-pass sampling (5 runs)
                $connLatencies = [];
                for ($run = 0; $run < 5; $run++) {
                    // Close and reconnect for each test
                    if (isset($pdo)) unset($pdo);
                    
                    $connStart = microtime(true);
                    $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
                    $pdo = new PDO($dsn, $user, $pass, [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                    ]);
                    $connEnd = microtime(true);
                    $connLatencies[] = ($connEnd - $connStart) * 1000;
                    
                    // Small delay between tests
                    usleep(10000); // 10ms
                }
                
                // Remove outliers and average
                sort($connLatencies);
                array_shift($connLatencies); // Remove fastest (best)
                array_pop($connLatencies);   // Remove slowest (worst)
                $connLatency = round(array_sum($connLatencies) / count($connLatencies), 2);
                $metrics['connection_latency'] = $connLatency;
                $metrics['connection_samples'] = 5;

                // Score connection latency: Punish anything over 5ms (localhost preference)
                if ($connLatency < 2) $points += 10;       // Lightning fast
                elseif ($connLatency < 5) $points += 8;    // Fast localhost
                elseif ($connLatency < 10) $points += 5;   // OK localhost
                elseif ($connLatency < 20) $points += 2;   // Slow connection
                else $points += 0;                          // Too slow

                // Generate random table name
                $tableName = 'bench_temp_' . bin2hex(random_bytes(8));

                // Create temporary table
                $createTableSQL = "CREATE TABLE `{$tableName}` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `uuid` VARCHAR(36) NOT NULL,
                    `int_col` INT NOT NULL,
                    `float_col` FLOAT NOT NULL,
                    `text_col` TEXT NOT NULL,
                    INDEX `idx_int_col` (`int_col`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
                $pdo->exec($createTableSQL);

                // Write Test - Multi-pass sampling (5 runs of 10,000 inserts each)
                $writeThroughputs = [];
                
                for ($run = 0; $run < 5; $run++) {
                    // Clear table before each run (except first)
                    if ($run > 0) {
                        $pdo->exec("TRUNCATE TABLE `{$tableName}`");
                    }
                    
                    $writeStart = microtime(true);
                    $pdo->beginTransaction();
                    $stmt = $pdo->prepare("INSERT INTO `{$tableName}` (uuid, int_col, float_col, text_col) VALUES (?, ?, ?, ?)");
                    
                    for ($i = 0; $i < 10000; $i++) {
                        $uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                            mt_rand(0, 0xffff),
                            mt_rand(0, 0x0fff) | 0x4000,
                            mt_rand(0, 0x3fff) | 0x8000,
                            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
                        );
                        $intVal = mt_rand(1, 10000);
                        $floatVal = mt_rand(1, 10000) / 100.0;
                        // Larger text payload: 500 characters of random data
                        $textVal = str_repeat(substr(md5(mt_rand()), 0, 10), 50) . '_' . $i;
                        
                        $stmt->execute([$uuid, $intVal, $floatVal, $textVal]);
                    }
                    $pdo->commit();
                    $writeEnd = microtime(true);
                    $writeTime = $writeEnd - $writeStart;
                    $writeThroughputs[] = 10000 / $writeTime;
                    
                    // Small delay between runs
                    usleep(50000); // 50ms
                }
                
                // Remove outliers and average
                sort($writeThroughputs);
                array_shift($writeThroughputs); // Remove fastest
                array_pop($writeThroughputs);   // Remove slowest
                $writeThroughput = round(array_sum($writeThroughputs) / count($writeThroughputs), 2);
                $metrics['write_throughput'] = $writeThroughput;
                $metrics['write_samples'] = 5;

                // Score write throughput: Require NVMe speeds for top marks
                if ($writeThroughput > 10000) $points += 15;      // NVMe beast
                elseif ($writeThroughput > 7500) $points += 12;   // Fast SSD
                elseif ($writeThroughput > 5000) $points += 9;    // Good SSD
                elseif ($writeThroughput > 2500) $points += 5;    // Average
                else $points += 1;                                 // Slow

                // Read Test - Multi-pass sampling (5 runs of 2,000 queries each)
                $readThroughputs = [];
                
                for ($run = 0; $run < 5; $run++) {
                    $readStart = microtime(true);
                    $selectStmt = $pdo->prepare("SELECT * FROM `{$tableName}` WHERE int_col = ?");
                    
                    for ($i = 0; $i < 2000; $i++) {
                        $randInt = mt_rand(1, 10000);
                        $selectStmt->execute([$randInt]);
                        $selectStmt->fetchAll();
                    }
                    $readEnd = microtime(true);
                    $readTime = $readEnd - $readStart;
                    $readThroughputs[] = 2000 / $readTime;
                    
                    // Small delay between runs
                    usleep(30000); // 30ms
                }
                
                // Remove outliers and average
                sort($readThroughputs);
                array_shift($readThroughputs); // Remove fastest
                array_pop($readThroughputs);   // Remove slowest
                $readThroughput = round(array_sum($readThroughputs) / count($readThroughputs), 2);
                $metrics['read_throughput'] = $readThroughput;
                $metrics['read_samples'] = 5;

                // Score read throughput: Strict performance requirements
                if ($readThroughput > 8000) $points += 15;        // Elite performance
                elseif ($readThroughput > 6000) $points += 12;    // Excellent
                elseif ($readThroughput > 4000) $points += 9;     // Very good
                elseif ($readThroughput > 2000) $points += 5;     // Average
                else $points += 1;                                 // Slow

                // CPU Test - Multi-pass sampling (5 runs of 100 SHA2 operations each)
                $cpuTimes = [];
                
                for ($run = 0; $run < 5; $run++) {
                    $cpuStart = microtime(true);
                    $cryptoStmt = $pdo->prepare("SELECT COUNT(*) as cnt, 
                        SUM(CAST(CONV(SUBSTRING(SHA2(text_col, 256), 1, 8), 16, 10) AS UNSIGNED)) as hash_sum,
                        AVG(LENGTH(text_col)) as avg_len
                        FROM `{$tableName}`");
                    
                    for ($i = 0; $i < 100; $i++) {
                        $cryptoStmt->execute();
                        $cryptoStmt->fetch();
                    }
                    $cpuEnd = microtime(true);
                    $cpuTimes[] = ($cpuEnd - $cpuStart) * 1000;
                    
                    // Small delay between runs
                    usleep(30000); // 30ms
                }
                
                // Remove outliers and average
                sort($cpuTimes);
                array_shift($cpuTimes); // Remove fastest
                array_pop($cpuTimes);   // Remove slowest
                $cpuTime = round(array_sum($cpuTimes) / count($cpuTimes), 2);
                $metrics['cpu_time'] = $cpuTime;
                $metrics['cpu_samples'] = 5;

                // Score CPU time: Steeper curve for cryptographic operations
                if ($cpuTime < 200) $points += 10;            // Elite CPU
                elseif ($cpuTime < 500) $points += 8;         // Very good
                elseif ($cpuTime < 800) $points += 6;         // Good
                elseif ($cpuTime < 1000) $points += 4;        // Average
                else $points += 1;                             // Slow

                // Calculate final score (0-10)
                $score = round(($points / $maxPoints) * 10, 2);

                return [
                    'success' => true,
                    'score' => $score,
                    'metrics' => $metrics
                ];

            } catch (PDOException $e) {
                return [
                    'success' => false,
                    'error' => $e->getMessage(),
                    'score' => 0,
                    'metrics' => []
                ];
            } catch (Exception $e) {
                return [
                    'success' => false,
                    'error' => $e->getMessage(),
                    'score' => 0,
                    'metrics' => []
                ];
            } finally {
                if (isset($pdo) && isset($tableName)) {
                    try {
                        @$pdo->exec("DROP TABLE IF EXISTS `{$tableName}`");
                    } catch (Exception $e) {
                        // Ignore cleanup errors
                    }
                }
            }
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - CACHE PERFORMANCE
        // ============================================================================

        /**
         * Establish connection to object cache service (Redis or Memcached)
         * 
         * This function attempts to detect and connect to available caching services
         * in the following order:
         * 
         * 1. Redis (port 6379) - Preferred for performance and features
         * 2. Memcached (port 11211) - Fallback option
         * 
         * Connection attempts use short timeouts (1 second) to avoid hanging
         * if services are not available. All connection errors are suppressed
         * with @ operator as cache unavailability is an expected condition.
         * 
         * @return array|null Returns ['type' => 'redis'|'memcached', 'conn' => object]
         *                    or null if no cache service is available
         */
        function get_cache_connection() {
                // Try Redis first (fastest and most feature-rich)
                if (class_exists('Redis')) {
                    try {
                        $redis = new Redis();
                        // Connect with 1 second timeout to localhost Redis
                        if (@$redis->connect('127.0.0.1', 6379, 1)) {
                            // Verify connection is alive
                            @$redis->ping();
                            return ['type' => 'redis', 'conn' => $redis];
                        }
                    } catch (Exception $e) {
                        // Redis extension exists but connection failed - this is normal
                    }
                }

                // Fallback to Memcached
                if (class_exists('Memcached')) {
                    try {
                        $memcached = new Memcached();
                        $memcached->addServer('127.0.0.1', 11211);
                        // Test connection by getting server stats
                        $stats = @$memcached->getStats();
                        if ($stats && count($stats) > 0) {
                            return ['type' => 'memcached', 'conn' => $memcached];
                        }
                    } catch (Exception $e) {
                        // Memcached extension exists but connection failed - this is normal
                    }
                }

                // No cache service available
            return null;
        }

        /**
         * Clean up benchmark test cache keys from Redis/Memcached
         * 
         * After benchmark tests complete, this function removes all temporary keys
         * created during cache performance testing. Keys follow the pattern
         * 'phpprobe_key_*' to avoid conflicts with actual cached data.
         * 
         * IMPORTANT: For Redis, this uses the SCAN command (non-blocking) instead
         * of KEYS (blocking) to prevent performance impact on production servers.
         * If SCAN is unavailable, cleanup is skipped rather than risk blocking
         * the Redis instance.
         * 
         * @return void
         */
        function cleanup_cache_keys() {
                $cache_info = get_cache_connection();
                if (!$cache_info) return;

                $cache = $cache_info['conn'];
                $type = $cache_info['type'];

                if ($type === 'redis') {
                    // Use SCAN (non-blocking) to iterate through keys
                    // SCAN is production-safe as it doesn't block the Redis server
                    try {
                        $iterator = null;
                        // Iterate through matching keys using SCAN cursor
                        while ($keys = $cache->scan($iterator, 'phpprobe_key_*', 100)) {
                            if ($keys && is_array($keys)) {
                                foreach ($keys as $key) {
                                    $cache->del($key);
                                }
                            }
                            // Iterator becomes 0 when complete
                            if ($iterator === 0) break; 
                        }
                    } catch (Exception $e) {
                        // If SCAN fails, skip cleanup rather than using blocking KEYS
                        // This is safer for production Redis servers with large keyspaces
                        error_log('Redis cache cleanup skipped: SCAN not available or failed - ' . $e->getMessage());
                    }
            }
            // Note: Memcached keys auto-expire after 60 seconds, so cleanup isn't critical
        }

        /**
         * Check if object cache (Redis/Memcached) is available
         * 
         * @return string|int Cache type ('redis' or 'memcached') or 0 if unavailable
         */
        function benchmark_object_cache_enabled() {
                $cache = get_cache_connection();
                if (!$cache) return 0;
            return $cache['type'];
        }

        /**
         * Benchmark object cache write performance
         * Tests cache write operations with data serialization
         * 
         * @return float Execution time in seconds, 0 if cache unavailable
         */
        function benchmark_object_cache_write() {
                $start = microtime(true);
                $maxTime = 15.0;

                $cache_info = get_cache_connection();
                if (!$cache_info) return 0; 

                $cache = $cache_info['conn'];
                $type = $cache_info['type'];

                try {
                    for ($i = 0; $i < 5000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;

                        $key = 'phpprobe_key_' . $i;
                        $value = ['data' => str_repeat('x', 100), 'timestamp' => time()];

                        if ($type === 'redis') {
                            $cache->setex($key, 60, serialize($value));
                        } else {
                            $cache->set($key, $value, 60);
                        }
                    }
                } catch (Exception $e) {
                    error_log('Cache Write benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    cleanup_cache_keys();
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark object cache read performance
         * Tests cache read operations with data unserialization
         * 
         * @return float Execution time in seconds, 0 if cache unavailable
         */
        function benchmark_object_cache_read() {
                $start = microtime(true);
                $maxTime = 15.0;

                $cache_info = get_cache_connection();
                if (!$cache_info) return 0;

                $cache = $cache_info['conn'];
                $type = $cache_info['type'];

                try {

                    for ($i = 0; $i < 5000; $i++) {
                        $key = 'phpprobe_key_' . $i;
                        $value = ['data' => str_repeat('x', 100), 'timestamp' => time()];

                        if ($type === 'redis') {
                            $cache->setex($key, 60, serialize($value));
                        } else {
                            $cache->set($key, $value, 60);
                        }
                    }

                    $readStart = microtime(true);

                    for ($i = 0; $i < 5000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;

                        $key = 'phpprobe_key_' . mt_rand(0, 4999);

                        if ($type === 'redis') {
                            $value = $cache->get($key);
                            if ($value) unserialize($value);
                        } else {
                            $value = $cache->get($key);
                        }
                    }

                    return round((microtime(true) - $readStart), 3);
                } catch (Exception $e) {
                    error_log('Cache Read benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                cleanup_cache_keys();
            }
        }

        /**
         * Benchmark mixed cache operations (70% read, 30% write)
         * Simulates realistic cache usage patterns
         * 
         * @return float Execution time in seconds, 0 if cache unavailable
         */
        function benchmark_object_cache_mixed() {
                $start = microtime(true);
                $maxTime = 15.0;

                $cache_info = get_cache_connection();
                if (!$cache_info) return 0;

                $cache = $cache_info['conn'];
                $type = $cache_info['type'];

                try {
                    for ($i = 0; $i < 3000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;

        if (mt_rand(1, 100) <= 70 && $i > 100) {
                            $key = 'phpprobe_key_' . mt_rand(0, $i - 1);

                            if ($type === 'redis') {
                                $value = $cache->get($key);
                                if ($value) unserialize($value);
                            } else {
                                $value = $cache->get($key);
                            }
                        } else {
                            $key = 'phpprobe_key_' . $i;
                            $value = ['data' => str_repeat('x', 100), 'timestamp' => time()];

                            if ($type === 'redis') {
                                $cache->setex($key, 60, serialize($value));
                            } else {
                                $cache->set($key, $value, 60);
                            }
                        }
                    }
                } catch (Exception $e) {
                    error_log('Cache Mixed Operations benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    cleanup_cache_keys();
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Check if OPcache is enabled
         * 
         * @return int 1 if enabled, 0 if disabled or unavailable
         */
        function benchmark_opcache_enabled() {

                if (!function_exists('opcache_get_status')) {
                    return 0; 
                }

                $status = @opcache_get_status(false);
                if (!$status || !isset($status['opcache_enabled'])) {
                    return 0;
                }

            return $status['opcache_enabled'] ? 1 : 0;
        }

        /**
         * Benchmark OPcache performance
         * Tests PHP file inclusion speed with OPcache enabled
         * 
         * @return float Execution time in seconds, 0 if OPcache unavailable
         */
        function benchmark_opcache_performance() {
                if (!function_exists('opcache_get_status')) {
                    return 0;
                }

                $start = microtime(true);
                $maxTime = 3.0;  

        $testFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'opcache_test_' . uniqid() . '.php';
        $testCode = '<?php $x = 50; $result = array_sum(range(1, $x));';

        try {
                    if (file_put_contents($testFile, $testCode) === false) {
                        error_log('OPcache Performance benchmark failed: Cannot create test file');
                        return 0;
                    }

                    $iterations = 0;
                    $maxIterations = 200;  

                    for ($i = 0; $i < $maxIterations; $i++) {

                        if ($i > 0 && $i % 20 == 0) {
                            if ((microtime(true) - $start) > $maxTime) {
                                break;
                            }
                        }

                        include $testFile;
                        $iterations++;
                    }

                    return round((microtime(true) - $start), 3);

                } catch (Exception $e) {
                    error_log('OPcache Performance benchmark failed: ' . $e->getMessage());
                    return 0;
                } finally {
                    if (file_exists($testFile)) {
                        unlink($testFile);
                    }
                }
            }

            function get_opcache_info() {
                if (!function_exists('opcache_get_status')) {
                    return [
                        'enabled' => false,
                        'status' => 'Not Available'
                    ];
                }

                $status = @opcache_get_status(false);
                if (!$status) {
                    return [
                        'enabled' => false,
                        'status' => 'Disabled'
                    ];
                }

                $config = @opcache_get_configuration();

                return [
                    'enabled' => $status['opcache_enabled'] ?? false,
                    'status' => ($status['opcache_enabled'] ?? false) ? 'Enabled' : 'Disabled',
                    'memory_used' => isset($status['memory_usage']['used_memory']) ? 
                        formatsize($status['memory_usage']['used_memory']) : 'N/A',
                    'memory_free' => isset($status['memory_usage']['free_memory']) ? 
                        formatsize($status['memory_usage']['free_memory']) : 'N/A',
                    'memory_wasted' => isset($status['memory_usage']['wasted_memory']) ? 
                        formatsize($status['memory_usage']['wasted_memory']) : 'N/A',
                    'hit_rate' => isset($status['opcache_statistics']['opcache_hit_rate']) ? 
                        round($status['opcache_statistics']['opcache_hit_rate'], 2) . '%' : 'N/A',
                    'cached_scripts' => $status['opcache_statistics']['num_cached_scripts'] ?? 0,
                    'cached_keys' => $status['opcache_statistics']['num_cached_keys'] ?? 0,
                    'max_cached_keys' => $status['opcache_statistics']['max_cached_keys'] ?? 0,
                    'hits' => $status['opcache_statistics']['hits'] ?? 0,
                    'misses' => $status['opcache_statistics']['misses'] ?? 0,
                    'jit_enabled' => isset($config['directives']['opcache.jit']) && 
                        $config['directives']['opcache.jit'] !== 'disable' && 
                        $config['directives']['opcache.jit'] !== '0',
                    'jit_buffer_size' => isset($config['directives']['opcache.jit_buffer_size']) ? 
                        $config['directives']['opcache.jit_buffer_size'] : 'N/A'
            ];
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - NETWORK PERFORMANCE
        // ============================================================================

        /**
         * Benchmark network speed and connectivity
         * Tests DNS resolution, TCP connections, and file downloads
         * 
         * @return float Execution time in seconds
         */
        function benchmark_network_speed() {
                $start = microtime(true);
                $maxTime = 15.0;

        $dnsTargets = ['google.com', 'cloudflare.com', 'github.com'];
                foreach ($dnsTargets as $domain) {
                    if ((microtime(true) - $start) > $maxTime) break;
                    gethostbyname($domain);
                }

        $latencyTargets = [
                    'tcp://1.1.1.1:80',
                    'tcp://8.8.8.8:53',
                    'ssl://www.cloudflare.com:443'
                ];

                foreach ($latencyTargets as $target) {
                    if ((microtime(true) - $start) > $maxTime) break;
                    $fp = stream_socket_client($target, $errno, $errstr, 2);
                    if ($fp) fclose($fp);
                }

        $downloadSuccess = false;
                $testUrls = [
                    'https://speed.cloudflare.com/__down?bytes=1000000',  
                    'https://gra.proof.ovh.net/files/1Mb.dat',                 
                    'https://syd.proof.ovh.net/files/1Mb.dat',               
                    'https://sgp.proof.ovh.net/files/1Mb.dat',
                    'https://bhs.proof.ovh.net/files/1Mb.dat',
                    'https://fra.proof.ovh.net/files/1Mb.dat',	
                ];

                $context = stream_context_create([
                    'http' => [
                        'timeout' => 5,
                        'user_agent' => 'PHP-Benchmark/2.1'
                    ],
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true
                    ]
                ]);

                foreach ($testUrls as $url) {
                    if ((microtime(true) - $start) > $maxTime) break;

                    $downloadStart = microtime(true);
                    try {
                        $data = file_get_contents($url, false, $context);
                        $downloadTime = microtime(true) - $downloadStart;

                        if ($data !== false && strlen($data) > 500000) { 
                            $downloadSuccess = true;
                            break; 
                        }
                    } catch (Exception $e) {
                        error_log('Network benchmark failed for ' . $url . ': ' . $e->getMessage());
                        // Continue to next URL
                    }
                }

                if (!$downloadSuccess && function_exists('curl_init')) {
                    foreach ($testUrls as $url) {
                        if ((microtime(true) - $start) > $maxTime) break;

                        $ch = curl_init($url);
                        curl_setopt_array($ch, [
                            CURLOPT_RETURNTRANSFER => true,
                            CURLOPT_TIMEOUT => 5,
                            CURLOPT_CONNECTTIMEOUT => 3,
                            CURLOPT_SSL_VERIFYPEER => true,
                            CURLOPT_SSL_VERIFYHOST => 2,
                            CURLOPT_USERAGENT => 'PHP-Benchmark/2.1'
                        ]);

                        $downloadStart = microtime(true);
                        $data = curl_exec($ch);
                        $downloadTime = microtime(true) - $downloadStart;
                        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                        curl_close($ch);

                        if ($data !== false && strlen($data) > 500000 && $httpCode == 200) {
                            $downloadSuccess = true;
                            break;
                        }
                    }
                }

                if (!$downloadSuccess) {
                    return 0; // Fail if no download succeeded
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark network latency to multiple global endpoints
         * 
         * Measures network connectivity quality by testing:
         * 1. DNS resolution speed for multiple domains
         * 2. HTTP connection establishment (via cURL CONNECT_TIME)
         * 
         * Tests three globally distributed services:
         * - google.com - Global presence with edge locations
         * - cloudflare.com - Global CDN with fast response
         * - github.com - Developer-focused, globally available
         * 
         * Lower latency indicates:
         * - Good network routing to internet backbones
         * - Fast DNS server response
         * - Low packet loss and jitter
         * 
         * Important for applications making external API calls, webhooks,
         * or fetching remote resources.
         * 
         * @return float Average latency in milliseconds (lower is better), 0 if unable to measure
         */
        function benchmark_network_latency() {
                $start = microtime(true);
                $maxTime = 3.0;
                $timeout = 1.5;
                $latencies = [];

                $dnsDomains = ['google.com', 'cloudflare.com', 'github.com'];
                foreach ($dnsDomains as $domain) {
                    if ((microtime(true) - $start) > $maxTime) break;
                    $dnsStart = microtime(true);
                    $ip = gethostbyname($domain);
                    if ($ip !== $domain) { 
                        $latencies[] = (microtime(true) - $dnsStart) * 1000; 
                    }
                    if ((microtime(true) - $dnsStart) > $timeout) break;
                }

        if (function_exists('curl_init')) {
                    $testUrl = 'https://www.google.com';
                    $curlStart = microtime(true);
                    $ch = curl_init();
                    curl_setopt_array($ch, [
                        CURLOPT_URL => $testUrl,
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_TIMEOUT => $timeout,
                        CURLOPT_CONNECTTIMEOUT => $timeout,
                        CURLOPT_NOBODY => true,
                        CURLOPT_SSL_VERIFYPEER => true,
                        CURLOPT_SSL_VERIFYHOST => 2
                    ]);
                    curl_exec($ch);
                    $connectTime = curl_getinfo($ch, CURLINFO_CONNECT_TIME);
                    curl_close($ch);

                    if ($connectTime > 0 && $connectTime < $timeout) {
                        $latencies[] = $connectTime * 1000; 
                    }
                }

                if (empty($latencies)) {
                    return 0; 
                }

            return round(array_sum($latencies) / count($latencies), 2);
        }

        /**
         * Benchmark server concurrency handling (stress test)
         * 
         * This function is called MULTIPLE TIMES IN PARALLEL (15 simultaneous requests)
         * by JavaScript code to simulate real-world concurrent load. This tests:
         * 
         * WEB SERVER CAPABILITIES:
         * - Apache/Nginx worker pool size and configuration
         * - PHP-FPM process manager settings (pm.max_children)
         * - Request queuing behavior under load
         * - Session locking impact (mitigated by session_write_close)
         * 
         * WHAT IT MEASURES:
         * - Average response time under concurrent load
         * - System stability with multiple simultaneous PHP processes
         * - CPU + I/O performance when resources are contested
         * 
         * REAL-WORLD RELEVANCE:
         * Production websites rarely serve one request at a time. This test
         * reveals how your server handles traffic spikes and concurrent users.
         * 
         * Each request performs realistic work (CPU math + file I/O) rather than
         * just sleeping, to properly stress the system.
         * 
         * @return float Execution time in seconds for this single request
         */
        /**
         * Worker function for concurrency test
         * Performs the actual CPU and I/O work for a single request
         */
        function benchmark_concurrency_worker() {
                $start = microtime(true);
                
                // Simulate realistic work: CPU + I/O (not just usleep)
                $result = 0;
                
                // CPU work: Math operations to load processor
                // Reduced iterations (20000) to test concurrency behavior, not raw CPU
                for ($i = 0; $i < 20000; $i++) {
                    $result += sqrt($i) * sin($i);
                }
                
                // Small I/O work (test real disk, not ramdisk)
                $testFile = __DIR__ . DIRECTORY_SEPARATOR . 'bench_concurrency_' . uniqid() . '.tmp';
                $ioSuccess = false;
                try {
                    $data = json_encode(['iteration' => $result, 'time' => microtime(true)]);
                    if (file_put_contents($testFile, $data) !== false) {
                        if (file_get_contents($testFile) !== false) {
                             $ioSuccess = true;
                        }
                    }
                } catch (Exception $e) {
                    error_log('Concurrency benchmark I/O failed: ' . $e->getMessage());
                } finally {
                    if (file_exists($testFile)) {
                        unlink($testFile);
                    }
                }

                if (!$ioSuccess) return 0; // Fail if I/O failed
                
            return round((microtime(true) - $start), 4);
        }

        /**
         * Get the full URL of the current script
         */
        function get_self_url() {
            $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https" : "http";
            $host = $_SERVER['HTTP_HOST'];
            $uri = $_SERVER['REQUEST_URI'];
            // Remove query string to get clean script path
            $uri = strtok($uri, '?');
            return $protocol . "://" . $host . $uri;
        }

        /**
         * Manager function for concurrency test
         * Uses curl_multi to fire parallel requests to the worker endpoint
         */
        function benchmark_concurrency() {
            // Check if curl is available
            if (!function_exists('curl_multi_init')) {
                // Fallback to single worker execution (not concurrent, but better than error)
                return benchmark_concurrency_worker();
            }

            $count = 15; // Number of parallel requests
            $mh = curl_multi_init();
            $handles = [];
            $url = get_self_url() . '?act=worker&type=concurrency';
            
            // Create handles
            for ($i = 0; $i < $count; $i++) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                // Add a random parameter to prevent caching
                curl_setopt($ch, CURLOPT_URL, $url . '&r=' . mt_rand());
                
                curl_multi_add_handle($mh, $ch);
                $handles[] = $ch;
            }

            // Execute handles
            $running = null;
            $start = microtime(true);
            do {
                curl_multi_exec($mh, $running);
                curl_multi_select($mh);
            } while ($running > 0);
            
            $totalTime = microtime(true) - $start;

            // Collect results and close handles
            $successCount = 0;
            foreach ($handles as $ch) {
                $info = curl_getinfo($ch);
                if ($info['http_code'] == 200) {
                    $successCount++;
                }
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
            }
            curl_multi_close($mh);

            // If fewer than half succeeded, consider it a failure
            if ($successCount < ($count / 2)) {
                return 0;
            }
            
            // Return total batch time (not average) to properly measure parallelism
            // A well-parallelized server completes 15 requests in ~0.2s (parallel)
            // A serial/throttled server takes 3.0s+ (queued execution)
            return round($totalTime, 4); 
        }

        // ============================================================================
        // BENCHMARK FUNCTIONS - BASIC CPU OPERATIONS
        // ============================================================================

        /**
         * Benchmark integer arithmetic operations
         * Tests basic CPU computational speed with integer math
         * 
         * @return float Execution time in seconds
         */
        function benchmark_cpu_int() {
                $start = microtime(true);
                $maxTime = 15.0;
                $result = 0;
                for ($i = 0; $i < 20000000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;
                    $x = $i + $i;
                    $y = $i * 2;
                    $z = $x - $y + $i;
                    $result += $z;
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark floating-point arithmetic operations
         * Tests CPU performance with mathematical functions (sqrt, pow, log, sin, cos)
         * 
         * @return float Execution time in seconds
         */
        function benchmark_cpu_float() {
                $start = microtime(true);
                $maxTime = 15.0;
                $pi = pi();
                $e = exp(1);
                $result = 0.0;

                for ($i = 0; $i < 5000000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;

        $x = ($i % 10000) + 1;
                    $result += sqrt($pi * $x);
                    $result += pow($x, 0.5);
                    $result += log($x + 1) * $e;
                    $result += abs(sin($x * 0.1) * cos($x * 0.1));
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark file I/O operations
         * Tests sequential file reading with pointer rewinding
         * 
         * @return float Execution time in seconds
         */
        function benchmark_io() {
                $start = microtime(true);
                $maxTime = 15.0;
                
                try {
                    $fp = fopen(__FILE__, 'r');
                    if ($fp === false) {
                        error_log('File I/O benchmark failed: Cannot open file for reading');
                        return 0;
                    }
                    
                    for ($i = 0; $i < 10000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;
                        fread($fp, 1024);
                        rewind($fp);
                    }
                    fclose($fp);
                } catch (Exception $e) {
                    error_log('File I/O benchmark failed: ' . $e->getMessage());
                    return 0;
                }
                
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark string manipulation operations
         * Tests case conversion, substring, search, replace, and trimming
         * 
         * @return float Execution time in seconds
         */
        function benchmark_string() {
                $start = microtime(true);
                $maxTime = 15.0;
                $str = 'The quick brown fox jumps over the lazy dog. This is a more realistic test string with multiple sentences.';
                $longStr = str_repeat($str, 50);

                for ($i = 0; $i < 500000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;
                    $upper = strtoupper($str);
                    $lower = strtolower($str);
                    $len = strlen($longStr);
                    $sub = substr($longStr, 0, 100);
                    $replaced = str_replace('fox', 'cat', $str);
                    $pos = strpos($longStr, 'dog');
                    $trimmed = trim($str);
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark array operations
         * Tests reversing, summing, filtering, mapping, merging, and sorting
         * 
         * @return float Execution time in seconds
         */
        function benchmark_array() {
                $start = microtime(true);
                $maxTime = 15.0;

        $baseArr = range(1, 500); 

                // Calibrated for realistic micro-benchmark duration (~0.5-0.7s on modern hardware)
                for ($i = 0; $i < 25000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;

                    $arr = $baseArr;
                    $reversed = array_reverse($arr);
                    $sum = array_sum($arr);
                    $filtered = array_filter($arr, function($v) { return $v > 250; });
                    $mapped = array_map(function($v) { return $v * 2; }, array_slice($arr, 0, 100));
                    $merged = array_merge($arr, $filtered);
                    sort($arr);
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark hashing operations
         * Tests MD5, SHA1, SHA256, SHA512, and CRC32 algorithms
         * 
         * @return float Execution time in seconds
         */
        function benchmark_hash() {
                $start = microtime(true);
                $maxTime = 15.0;
                $str = 'benchmark test string for hashing with more data to make it realistic';

                for ($i = 0; $i < 200000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;
                    $data = $str . $i;
                    $md5 = md5($data);
                    $sha1 = sha1($data);
                    if (function_exists('hash')) {
                        $sha256 = hash('sha256', $data);
                        $sha512 = hash('sha512', $data);
                    }
                    if (function_exists('crc32')) {
                        $crc = crc32($data);
                    }
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Benchmark JSON encoding and decoding operations
         * Tests serialization/deserialization of complex nested data structures
         * 
         * @return float Execution time in seconds
         */
        function benchmark_json() {
                $start = microtime(true);
                $maxTime = 15.0;

                $data = [
                    'name' => 'Test User',
                    'email' => 'test@example.com',
                    'age' => 30,
                    'active' => true,
                    'roles' => ['admin', 'user', 'moderator'],
                    'metadata' => [
                        'created' => '2024-01-01',
                        'updated' => '2024-01-15',
                        'preferences' => ['theme' => 'dark', 'lang' => 'en']
                    ],
                    'items' => range(1, 50)
                ];

                for ($i = 0; $i < 200000; $i++) { 
                    if ((microtime(true) - $start) > $maxTime) break;
                    $json = json_encode($data);
                    $decoded = json_decode($json, true);

                    if (is_array($decoded) && isset($decoded['name'])) {
                        $name = $decoded['name'];
                    }
                }
            return round((microtime(true) - $start), 4);
        }

        /**
         * Check database extension availability
         * Tests for MySQLi, PDO, SQLite3, PostgreSQL, MongoDB, Redis, and Memcached
         * 
         * @return array Database support status
         */
        function benchmark_database_support() {
                $results = [];

        if (class_exists('mysqli')) {
                    $results['MySQL (mysqli)'] = '✓ Available';
                } else {
                    $results['MySQL (mysqli)'] = '✗ Not Available';
                }

        if (class_exists('PDO')) {
                    $drivers = PDO::getAvailableDrivers();
                    $results['PDO'] = '✓ Available (' . implode(', ', $drivers) . ')';
                } else {
                    $results['PDO'] = '✗ Not Available';
                }

        if (class_exists('SQLite3')) {
                    $ver = SQLite3::version();
                    $results['SQLite3'] = '✓ v' . $ver['versionString'];
                } else {
                    $results['SQLite3'] = '✗ Not Available';
                }

        $results['PostgreSQL'] = function_exists('pg_connect') ? '✓ Available' : '✗ Not Available';

        $results['MongoDB'] = class_exists('MongoDB\Driver\Manager') ? '✓ Available' : '✗ Not Available';

        $results['Redis'] = class_exists('Redis') ? '✓ Available' : '✗ Not Available';

        $results['Memcached'] = class_exists('Memcached') ? '✓ Available' : '✗ Not Available';

            return $results;
        }

        /**
         * Benchmark regular expression operations
         * Tests email, URL, phone number, and HTML pattern matching
         * 
         * @return float Execution time in seconds
         */
        function benchmark_regex() {
                $start = microtime(true);
                $maxTime = 15.0;

        $emailPattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
                $urlPattern = '/^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)$/';
                $phonePattern = '/^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/';

                $testEmails = [];
                $testUrls = [];
                for ($j = 0; $j < 100; $j++) {
                    $testEmails[] = "user{$j}@example{$j}.com";
                    $testUrls[] = "https://www.example{$j}.com/path/to/page?id={$j}";
                }

                for ($i = 0; $i < 50000; $i++) {
                    if ((microtime(true) - $start) > $maxTime) break;

        foreach ($testEmails as $email) {
                        preg_match($emailPattern, $email);
                    }

        foreach (array_slice($testUrls, 0, 10) as $url) {
                        preg_match($urlPattern, $url);
                    }

        preg_match($phonePattern, '+1-234-567-8900');

        $html = '<div class="test">Content</div><p>Paragraph</p>';
                    preg_match_all('/<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)/', $html, $matches);
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark large JSON processing operations
         * Tests encoding/decoding of large nested data structures with filtering
         * 
         * @return float Execution time in seconds
         */
        function benchmark_large_json() {
                $start = microtime(true);
                $maxTime = 15.0;

        $largeData = [];
                for ($i = 0; $i < 500; $i++) {
                    $largeData[] = [
                        'id' => $i,
                        'name' => 'Product ' . $i,
                        'description' => 'This is a detailed description for product ' . $i . ' with lots of text.',
                        'price' => rand(10, 1000) / 10,
                        'stock' => rand(0, 100),
                        'categories' => ['Category A', 'Category B', 'Category C'],
                        'attributes' => [
                            'color' => 'Blue',
                            'size' => 'Medium',
                            'weight' => rand(1, 50),
                            'dimensions' => ['length' => rand(1, 100), 'width' => rand(1, 100), 'height' => rand(1, 100)]
                        ],
                        'reviews' => [
                            ['user' => 'User ' . $i, 'rating' => rand(1, 5), 'comment' => 'Great product!'],
                            ['user' => 'User ' . ($i + 1), 'rating' => rand(1, 5), 'comment' => 'Good value.']
                        ]
                    ];
                }

                $jsonString = json_encode($largeData);
                $jsonSize = strlen($jsonString);

                for ($i = 0; $i < 5000; $i++) {
                    if ((microtime(true) - $start) > $maxTime) break;

        $decoded = json_decode($jsonString, true);

        if (is_array($decoded) && count($decoded) > 0) {
                        $firstItem = $decoded[0];
                        $filtered = array_filter($decoded, function($item) {
                            return isset($item['price']) && $item['price'] > 50;
                        });
                    }

        $reEncoded = json_encode(array_slice($decoded, 0, 10));
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark XML parsing operations
         * Tests SimpleXML parsing and element iteration
         * 
         * @return float Execution time in seconds
         */
        function benchmark_xml_parsing() {
                $start = microtime(true);
                $maxTime = 15.0;

        $xmlContent = '<?xml version="1.0" encoding="UTF-8"?><root>';
                for ($i = 0; $i < 200; $i++) {
                    $xmlContent .= '<item id="' . $i . '">';
                    $xmlContent .= '<title>Item Title ' . $i . '</title>';
                    $xmlContent .= '<description>This is a description for item ' . $i . '</description>';
                    $xmlContent .= '<price>' . (rand(10, 1000) / 10) . '</price>';
                    $xmlContent .= '<category>Category ' . ($i % 10) . '</category>';
                    $xmlContent .= '<attributes><color>Blue</color><size>M</size></attributes>';
                    $xmlContent .= '</item>';
                }
                $xmlContent .= '</root>';

                for ($i = 0; $i < 3000; $i++) {
                    if ((microtime(true) - $start) > $maxTime) break;

        $xml = @simplexml_load_string($xmlContent);

                    if ($xml) {

                        foreach ($xml->item as $item) {
                            $id = (string)$item['id'];
                            $title = (string)$item->title;
                            $price = (float)$item->price;
                            if ($price > 50) {
                                $filtered = $item;
                            }
                        }
                    }
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark password hashing operations
         * Tests bcrypt password hashing and verification
         * 
         * @return float Execution time in seconds
         */
        function benchmark_password_hashing() {
                $start = microtime(true);
                $maxTime = 15.0;

                $passwords = [];
                for ($j = 0; $j < 20; $j++) {
                    $passwords[] = 'password' . $j . rand(1000, 9999);
                }

                $hashes = [];
                $count = 0;

                for ($i = 0; $i < 500; $i++) {
                    if ((microtime(true) - $start) > $maxTime) break;

                    $password = $passwords[$i % 20];

        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
                    $hashes[] = $hash;

        if (count($hashes) > 0) {
                        password_verify($password, $hashes[count($hashes) - 1]);
                    }

                    $count++;
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark date/time operations
         * Tests DateTime creation, formatting, timezone conversion, and calculations
         * 
         * @return float Execution time in seconds
         */
        function benchmark_datetime_operations() {
                $start = microtime(true);
                $maxTime = 15.0;

                $timezones = ['America/New_York', 'Europe/London', 'Asia/Tokyo', 'Australia/Sydney'];

                for ($i = 0; $i < 100000; $i++) {
                    if ((microtime(true) - $start) > $maxTime) break;

        $date1 = new DateTime('2024-01-01 10:00:00', new DateTimeZone('UTC'));
                    $date2 = new DateTime('2024-12-31 23:59:59', new DateTimeZone('UTC'));

        $formatted1 = $date1->format('Y-m-d H:i:s');
                    $formatted2 = $date2->format('l, F j, Y');

        $diff = $date1->diff($date2);
                    $days = $diff->days;

        $date1->modify('+1 month');
                    $date1->modify('+15 days');

        $tz = $timezones[$i % 4];
                    $date1->setTimezone(new DateTimeZone($tz));

        $timestamp = $date1->getTimestamp();
                    $fromTimestamp = (new DateTime())->setTimestamp($timestamp);
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark CSV processing operations
         * Tests CSV file creation, reading, and data filtering
         * 
         * @return float Execution time in seconds
         */
        function benchmark_csv_processing() {
                $start = microtime(true);
                $maxTime = 15.0;

                $csvFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bench_csv_' . uniqid() . '.csv';

                try {

                    $fp = fopen($csvFile, 'w');
                    if (!$fp) return 0;

        fputcsv($fp, ['ID', 'Name', 'Email', 'Phone', 'Address', 'City', 'Country', 'ZIP', 'Total']);
                    for ($j = 0; $j < 1000; $j++) {
                        fputcsv($fp, [
                            $j,
                            'Customer ' . $j,
                            'customer' . $j . '@example.com',
                            '+1-234-567-' . str_pad($j, 4, '0', STR_PAD_LEFT),
                            $j . ' Main Street',
                            'City ' . ($j % 50),
                            'Country ' . ($j % 10),
                            str_pad($j, 5, '0', STR_PAD_LEFT),
                            rand(100, 10000) / 10
                        ]);
                    }
                    fclose($fp);

        for ($i = 0; $i < 100; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;

                        $fp = fopen($csvFile, 'r');
                        if (!$fp) break;

                        $headers = fgetcsv($fp);
                        $data = [];
                        while (($row = fgetcsv($fp)) !== false) {
                            $record = array_combine($headers, $row);

                            if (isset($record['Total']) && (float)$record['Total'] > 500) {
                                $data[] = $record;
                            }
                        }
                        fclose($fp);
                    }
                } finally {
                    @unlink($csvFile);
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark session file operations
         * Simulates session file creation, reading, and cleanup
         * 
         * @return float Execution time in seconds
         */
        function benchmark_session_operations() {
                $start = microtime(true);
                $maxTime = 15.0;

                $sessionDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bench_sessions_' . uniqid();
                @mkdir($sessionDir);

                try {
                    for ($i = 0; $i < 10000; $i++) {
                        if ((microtime(true) - $start) > $maxTime) break;

        $sessionId = 'sess_' . md5('session' . $i);
                        $sessionFile = $sessionDir . DIRECTORY_SEPARATOR . $sessionId;

        $sessionData = serialize([
                            'user_id' => $i,
                            'username' => 'user' . $i,
                            'email' => 'user' . $i . '@example.com',
                            'login_time' => time(),
                            'preferences' => ['theme' => 'dark', 'lang' => 'en'],
                            'cart' => ['item1', 'item2', 'item3']
                        ]);

                        file_put_contents($sessionFile, $sessionData);

        $content = file_get_contents($sessionFile);
                        $data = unserialize($content);

        if ($i % 100 == 0) {
                            @unlink($sessionFile);
                        }
                    }
                } finally {

                    $files = glob($sessionDir . DIRECTORY_SEPARATOR . '*');
                    if ($files) {
                        foreach ($files as $file) {
                            @unlink($file);
                        }
                    }
                    @rmdir($sessionDir);
                }

            return round((microtime(true) - $start), 3);
        }

        /**
         * Benchmark image processing operations using GD library
         * Tests image creation, drawing, and resizing operations
         * 
         * @return float Execution time in seconds, 0 if GD not available
         */
        function benchmark_image_operations() {
                $start = microtime(true);
                $maxTime = 15.0;

                if (!function_exists('imagecreate')) {
                    return 0; 
                }

                for ($i = 0; $i < 200; $i++) { // Reduced iterations, increased complexity
                    if ((microtime(true) - $start) > $maxTime) break;

                    $width = 1200;
                    $height = 900;
                    $img = imagecreatetruecolor($width, $height);
                    if (!$img) continue;

                    // Fill background
                    $bg = imagecolorallocate($img, 240, 240, 240);
                    imagefill($img, 0, 0, $bg);

                    // Draw random complex shapes
                    for ($j = 0; $j < 50; $j++) {
                        $color = imagecolorallocatealpha($img, mt_rand(0, 255), mt_rand(0, 255), mt_rand(0, 255), mt_rand(0, 50));
                        imagefilledellipse($img, mt_rand(0, $width), mt_rand(0, $height), mt_rand(10, 200), mt_rand(10, 200), $color);
                    }

                    // Add text with scaling
                    $text_color = imagecolorallocate($img, 0, 0, 0);
                    imagestring($img, 5, 50, 50, 'Heavy Image Benchmark ' . $i, $text_color);

                    // 1. Resizing (Resampling) - CPU intensive
                    $newWidth = 600;
                    $newHeight = 450;
                    $resized = imagecreatetruecolor($newWidth, $newHeight);
                    if ($resized) {
                        imagecopyresampled($resized, $img, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
                        
                        // 2. Apply Filter (Grayscale) - CPU intensive
                        if (function_exists('imagefilter')) {
                            imagefilter($resized, IMG_FILTER_GRAYSCALE);
                            imagefilter($resized, IMG_FILTER_CONTRAST, -5);
                        }

                        imagedestroy($resized);
                    }

                    imagedestroy($img);
                }

            return round((microtime(true) - $start), 3);
        }

        // ============================================================================
        // PHP CONFIGURATION FUNCTIONS
        // ============================================================================

        /**
         * Get detailed PHP extension information with versions
         * 
         * @return array Extension names with their versions
         */
        function get_php_extensions_detailed() {
                $extensions = get_loaded_extensions();
                $detailed = [];

                foreach ($extensions as $ext) {
                    $version = phpversion($ext);
                    $detailed[$ext] = $version ?: 'loaded';
                }

            return $detailed;
        }

        /**
         * Check availability of important PHP functions by category
         * 
         * @return array Function availability grouped by category
         */
        function check_important_functions() {
                $functions = [
                    'File Operations' => ['fopen', 'fread', 'fwrite', 'file_get_contents', 'file_put_contents', 'unlink', 'mkdir'],
                    'Network' => ['curl_init', 'fsockopen', 'gethostbyname', 'dns_get_record'],
                    'Compression' => ['gzencode', 'gzdecode', 'gzcompress', 'gzuncompress', 'bz2compress', 'bz2decompress'],
                    'Cryptography' => ['md5', 'sha1', 'hash', 'openssl_encrypt', 'openssl_decrypt', 'password_hash'],
                    'Image' => ['imagecreate', 'imagecreatefromjpeg', 'imagejpeg', 'imagepng', 'imagegif', 'imagewebp'],
                    'Mail' => ['mail', 'imap_open'],
                    'Session' => ['session_start', 'session_destroy', 'session_id'],
                    'Execution' => ['exec', 'system', 'shell_exec', 'passthru', 'proc_open'],
                    'System' => ['sys_getloadavg', 'disk_free_space', 'disk_total_space', 'getenv', 'putenv']
                ];

                $results = [];
                foreach ($functions as $category => $funcs) {
                    $results[$category] = [];
                    foreach ($funcs as $func) {
                        $results[$category][$func] = function_exists($func);
                    }
                }

            return $results;
        }

        /**
         * Get current timezone information
         * 
         * @return array Timezone details including offset, abbreviation, and DST status
         */
        function get_timezone_info() {
                return [
                    'current' => date_default_timezone_get(),
                    'offset' => date('P'),
                    'abbreviation' => date('T'),
                    'dst' => date('I') ? 'Yes' : 'No'
            ];
        }

        /**
         * Get server software versions
         * Detects Apache, PHP, cURL, GD, ImageMagick, libxml, and ICU versions
         * 
         * @return array Software versions
         */
        function get_server_software_versions() {
                $versions = [];

        if (function_exists('apache_get_version')) {
                    $versions['Apache'] = apache_get_version();
                }

        $versions['PHP'] = PHP_VERSION;
                $versions['PHP SAPI'] = php_sapi_name();
                $versions['Zend Engine'] = zend_version();

        if (defined('OPENSSL_VERSION_TEXT')) {
                    $versions['OpenSSL'] = OPENSSL_VERSION_TEXT;
                }

        if (function_exists('curl_version')) {
                    $curl = curl_version();
                    $versions['cURL'] = $curl['version'];
                    $versions['cURL SSL'] = $curl['ssl_version'];
                }

        if (function_exists('gd_info')) {
                    $gd = gd_info();
                    $versions['GD'] = $gd['GD Version'];
                }

        if (class_exists('Imagick')) {
                    $imagick = new Imagick();
                    $version = $imagick->getVersion();
                    $versions['ImageMagick'] = $version['versionString'];
                }

        if (defined('LIBXML_DOTTED_VERSION')) {
                    $versions['libxml'] = LIBXML_DOTTED_VERSION;
                }

        if (defined('INTL_ICU_VERSION')) {
                    $versions['ICU'] = INTL_ICU_VERSION;
                }

            return $versions;
        }

        /**
         * Get PHP configuration limits
         * 
         * @return array PHP limits including memory, execution time, upload sizes, etc.
         */
        function get_php_limits() {
                return [
                    'memory_limit' => ini_get('memory_limit'),
                    'post_max_size' => ini_get('post_max_size'),
                    'upload_max_filesize' => ini_get('upload_max_filesize'),
                    'max_execution_time' => ini_get('max_execution_time') . 's',
                    'max_input_time' => ini_get('max_input_time') . 's',
                    'max_input_vars' => ini_get('max_input_vars'),
                    'default_socket_timeout' => ini_get('default_socket_timeout') . 's',
                    'max_file_uploads' => ini_get('max_file_uploads'),
            ];
        }

        /**
         * Get HTTP connection information
         * 
         * @return array Connection details including protocol, method, HTTPS status, user agent
         */
        function get_connection_info() {
                return [
                    'Protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'N/A',
                    'Request Method' => $_SERVER['REQUEST_METHOD'] ?? 'N/A',
                    'HTTPS' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'Yes' : 'No',
                    'User Agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'N/A',
                    'Accept Encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'N/A',
                    'Accept Language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'N/A',
            ];
        }

        // ============================================================================
        // DATA COLLECTION & INITIALIZATION
        // ============================================================================

        $hosting_env = detect_hosting_environment();

            $server_info = [
                'server_id' => php_uname(),
                'server_os' => PHP_OS . ' Kernel version: ' . php_uname('r'),
                'server_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'N/A',
                'server_hostname' => php_uname('n'),
                'server_name' => $_SERVER['SERVER_NAME'] ?? 'N/A',
                'server_addr' => $_SERVER['SERVER_ADDR'] ?? @gethostbyname($_SERVER['SERVER_NAME']),
                'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'N/A',
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
                'server_port' => $_SERVER['SERVER_PORT'] ?? 'N/A',
                'server_admin' => $_SERVER['SERVER_ADMIN'] ?? 'N/A',
                'root_path' => $_SERVER['DOCUMENT_ROOT'] ?? dirname(__FILE__),
                'prober_path' => __FILE__,
                'current_time' => date('Y-m-d H:i:s'),
                'uptime' => get_uptime(),
                'hosting_type' => $hosting_env['type'] == 'shared' ? 'Shared Hosting' : 'Hosting',
            ];

            $cpu_info = get_cpu_info();
            $cpu_usage = get_cpu_usage();
            $memory_info = get_memory_info();
            $load_avg = get_load_average();
            $network_info = get_network_info();
            $network_total_rx = 0;
            $network_total_tx = 0;
            foreach ($network_info as $iface => $ifaceData) {
                $network_total_rx += $ifaceData['rx'];
                $network_total_tx += $ifaceData['tx'];
            }
            $network_interfaces = !empty($network_info) ? implode(', ', array_keys($network_info)) : 'N/A';
            $timezone_info = get_timezone_info();
            $versions = get_server_software_versions();
            $php_limits = get_php_limits();
            $connection_info = get_connection_info();
            $opcache_info = get_opcache_info();

        $disk_total = @disk_total_space(".") ? @disk_total_space(".") : 0;
        $disk_free = @disk_free_space(".") ? @disk_free_space(".") : 0;
        $disk_used = $disk_total - $disk_free;
        $disk_percent = $disk_total > 0 ? round(($disk_used / $disk_total) * 100, 2) : 0;

        $mem_format = [];
            if ($memory_info['total'] >= 1024) {
                $mem_format['total'] = round($memory_info['total'] / 1024, 3) . ' G';
                $mem_format['used'] = round($memory_info['used'] / 1024, 3) . ' G';
                $mem_format['free'] = round($memory_info['free'] / 1024, 3) . ' G';
                $mem_format['cached'] = round($memory_info['cached'] / 1024, 3) . ' G';
                $mem_format['buffers'] = round($memory_info['buffers'] / 1024, 3) . ' G';
                $mem_format['real_used'] = round($memory_info['real_used'] / 1024, 3) . ' G';
                $mem_format['real_free'] = round($memory_info['real_free'] / 1024, 3) . ' G';
                $mem_format['swap_total'] = round($memory_info['swap_total'] / 1024, 3) . ' G';
                $mem_format['swap_used'] = round($memory_info['swap_used'] / 1024, 3) . ' G';
                $mem_format['swap_free'] = round($memory_info['swap_free'] / 1024, 3) . ' G';
            } else {
                $mem_format['total'] = $memory_info['total'] . ' M';
                $mem_format['used'] = $memory_info['used'] . ' M';
                $mem_format['free'] = $memory_info['free'] . ' M';
                $mem_format['cached'] = $memory_info['cached'] . ' M';
                $mem_format['buffers'] = $memory_info['buffers'] . ' M';
                $mem_format['real_used'] = $memory_info['real_used'] . ' M';
                $mem_format['real_free'] = $memory_info['real_free'] . ' M';
                $mem_format['swap_total'] = $memory_info['swap_total'] . ' M';
                $mem_format['swap_used'] = $memory_info['swap_used'] . ' M';
                $mem_format['swap_free'] = $memory_info['swap_free'] . ' M';
            }

        // ============================================================================
        // API ENDPOINTS
        // ============================================================================

        if (isset($_GET['act'])) {
            // Handle worker request for concurrency test
            if ($_GET['act'] === 'worker' && isset($_GET['type']) && $_GET['type'] === 'concurrency') {
                $time = benchmark_concurrency_worker();
                header('Content-Type: application/json');
                echo json_encode(['time' => $time]);
                exit;
            }
            $action = sanitize_input($_GET['act'], 'alnum');

            /**
             * Display PHP information
             */
            if ($action === 'phpinfo') {
                phpinfo();
                exit;
            }

            /**
             * Handle TCP ping/latency test requests
             */
            if ($action === 'ping' && isset($_GET['target'])) {
                    header('Content-Type: application/json');
                    $target = trim($_GET['target']);
                    $port = isset($_GET['port']) ? (int)$_GET['port'] : 80;
                    $count = isset($_GET['count']) ? min((int)$_GET['count'], 10) : 4; 

        if ($port < 1 || $port > 65535) {
                        echo json_encode(['error' => 'Invalid port number']);
                        exit;
                    }

        if (empty($target) || strlen($target) > 255) {
                        echo json_encode(['error' => 'Invalid target']);
                        exit;
                    }

        if (!preg_match('/^[a-zA-Z0-9\.\-]+$/', $target)) {
                        echo json_encode(['error' => 'Invalid target format. Use hostname or IP only.']);
                        exit;
                    }

                    $results = [];
                    $successful = 0;
                    $failed = 0;
                    $totalTime = 0;
                    $minTime = PHP_FLOAT_MAX;
                    $maxTime = 0;

                    for ($i = 0; $i < $count; $i++) {
                        $start = microtime(true);
                        $errno = 0;
                        $errstr = '';

        $fp = @stream_socket_client(
                            "tcp://{$target}:{$port}",
                            $errno,
                            $errstr,
                            3,
                            STREAM_CLIENT_CONNECT
                        );

                        $time = (microtime(true) - $start) * 1000; 

                        if ($fp) {
                            fclose($fp);
                            $results[] = [
                                'success' => true,
                                'time' => round($time, 2),
                                'seq' => $i + 1
                            ];
                            $successful++;
                            $totalTime += $time;
                            $minTime = min($minTime, $time);
                            $maxTime = max($maxTime, $time);
                        } else {
                            $results[] = [
                                'success' => false,
                                'error' => $errstr ?: 'Connection timeout',
                                'seq' => $i + 1
                            ];
                            $failed++;
                        }

        if ($i < $count - 1) {
                            usleep(200000); 
                        }
                    }

                    $response = [
                        'target' => $target,
                        'port' => $port,
                        'results' => $results,
                        'summary' => [
                            'sent' => $count,
                            'received' => $successful,
                            'lost' => $failed,
                            'loss_percent' => round(($failed / $count) * 100, 1)
                        ]
                    ];

                    if ($successful > 0) {
                        $response['summary']['min'] = round($minTime, 2);
                        $response['summary']['max'] = round($maxTime, 2);
                        $response['summary']['avg'] = round($totalTime / $successful, 2);
                    }

                echo json_encode($response);
                exit;
            }

            /**
             * Helper: Run a specific benchmark test and calculate score
             * 
             * @param string $type Benchmark type
             * @return array Result and score
             */
            function run_benchmark_test($type, $scoring_mode = null) {
                global $SCORING_THRESHOLDS, $DEFAULT_SCORING_MODE;
                
                // Determine scoring mode
                if ($scoring_mode === null) {
                    $scoring_mode = isset($_GET['scoring']) ? $_GET['scoring'] : $DEFAULT_SCORING_MODE;
                }
                
                // Validate scoring mode
                if (!isset($SCORING_THRESHOLDS[$scoring_mode])) {
                    $scoring_mode = $DEFAULT_SCORING_MODE;
                }
                
                $result = 0;
                $score = 0;
                
                try {
                    // Get the appropriate thresholds
                    $lookup_type = $type;
                    if ($type === 'network_latency') $lookup_type = 'network_latency_ms';
                    
                    $thresholds = isset($SCORING_THRESHOLDS[$scoring_mode][$lookup_type]) 
                        ? $SCORING_THRESHOLDS[$scoring_mode][$lookup_type] 
                        : [1.0, 2.0, 4.0, 8.0]; // Fallback defaults
                    
                    // Determine if we should use aggressive scoring (modern mode)
                    $aggressive = ($scoring_mode === 'modern');
                    
                    // Define tests that benefit from sampling (fast execution, prone to jitter)
                    $sampleable_tests = [
                        'cpu_int', 'cpu_float', 'cpu_text', 'cpu_binary', 
                        'string', 'array', 'hash', 'json',
                        'io', 'fs_write', 'fs_copy', 'fs_small',
                        'db_import', 'db_simple', 'db_complex',
                        'opcache_performance', 'cache_write', 'cache_read', 'cache_mixed',
                        'regex', 'large_json', 'xml_parsing', 'password_hashing', 'datetime', 'csv', 'session', 'image'
                    ];

                    // Determine sample count
                    // Modern mode: 3 samples for accuracy
                    // Light mode: 1 sample for speed
                    // Network/Concurrency: Always 1 sample to avoid timeouts/excessive load
                    $sample_count = 1;
                    if ($scoring_mode === 'modern' && in_array($type, $sampleable_tests)) {
                        $sample_count = 3;
                    }

                    $total_result = 0;
                    $valid_samples = 0;

                    for ($i = 0; $i < $sample_count; $i++) {
                        $current_result = 0;
                        
                        switch ($type) {
                            case 'cpu_int': $current_result = benchmark_cpu_int(); break;
                            case 'cpu_float': $current_result = benchmark_cpu_float(); break;
                            case 'io': $current_result = benchmark_io(); break;
                            case 'string': $current_result = benchmark_string(); break;
                            case 'array': $current_result = benchmark_array(); break;
                            case 'hash': $current_result = benchmark_hash(); break;
                            case 'json': $current_result = benchmark_json(); break;
                            case 'cpu_text': $current_result = benchmark_cpu_operations_large_text(); break;
                            case 'cpu_binary': $current_result = benchmark_cpu_random_binary_operations(); break;
                            case 'fs_write': $current_result = benchmark_filesystem_write(); break;
                            case 'fs_copy': $current_result = benchmark_filesystem_copy_access(); break;
                            case 'fs_small': $current_result = benchmark_filesystem_small_io(); break;
                            case 'db_import': $current_result = benchmark_database_import_large(); break;
                            case 'db_simple': $current_result = benchmark_database_simple_queries(); break;
                            case 'db_complex': $current_result = benchmark_database_complex_queries(); break;
                            case 'cache_enabled': 
                                $current_result = benchmark_object_cache_enabled(); 
                                // Non-numeric result, break loop
                                $total_result = $current_result;
                                $valid_samples = 1;
                                $i = $sample_count; 
                                break;
                            case 'opcache_enabled': 
                                $current_result = benchmark_opcache_enabled(); 
                                // Boolean result, break loop
                                $total_result = $current_result;
                                $valid_samples = 1;
                                $i = $sample_count;
                                break;
                            case 'opcache_performance': $current_result = benchmark_opcache_performance(); break;
                            case 'cache_write': $current_result = benchmark_object_cache_write(); break;
                            case 'cache_read': $current_result = benchmark_object_cache_read(); break;
                            case 'cache_mixed': $current_result = benchmark_object_cache_mixed(); break;
                            case 'network': $current_result = benchmark_network_speed(); break;
                            case 'network_latency': $current_result = benchmark_network_latency(); break;
                            case 'concurrency': $current_result = benchmark_concurrency(); break;
                            case 'regex': $current_result = benchmark_regex(); break;
                            case 'large_json': $current_result = benchmark_large_json(); break;
                            case 'xml_parsing': $current_result = benchmark_xml_parsing(); break;
                            case 'password_hashing': $current_result = benchmark_password_hashing(); break;
                            case 'datetime': $current_result = benchmark_datetime_operations(); break;
                            case 'csv': $current_result = benchmark_csv_processing(); break;
                            case 'session': $current_result = benchmark_session_operations(); break;
                            case 'image': $current_result = benchmark_image_operations(); break;
                        }

                        // Accumulate numeric results
                        if (is_numeric($current_result)) {
                            $total_result += $current_result;
                            $valid_samples++;
                        } else if ($i === 0) {
                            // For non-numeric first result (like 'redis'), keep it
                            $total_result = $current_result;
                            $valid_samples = 1;
                            break; // Don't sample non-numeric tests
                        }
                        
                        // Small pause between samples to let system settle
                        if ($sample_count > 1) usleep(50000);
                    }

                    // Calculate average
                    if ($valid_samples > 0 && is_numeric($total_result)) {
                        $result = round($total_result / $valid_samples, 4);
                    } else {
                        $result = is_numeric($total_result) ? round($total_result, 4) : $total_result;
                    }

                    // Calculate score based on average result
                    // Handle special non-numeric cases first
                    if ($type === 'cache_enabled') {
                        $score = ($result === 'redis' || $result === 'memcached') ? 10 : 0;
                    } elseif ($type === 'opcache_enabled') {
                        $score = $result ? 10 : 0;
                    } else {
                        // Standard numeric scoring
                        $score = $result > 0 ? calculate_score($result, $thresholds[0], $thresholds[1], $thresholds[2], $thresholds[3], $aggressive) : 0;
                    }

                    
                    return ['result' => $result, 'score' => $score, 'mode' => $scoring_mode];
                    
                } catch (Throwable $e) {
                    return ['error' => 'Benchmark failed: ' . $e->getMessage(), 'result' => 0, 'score' => 0];
                }
            }

            /**
             * Handle single benchmark test request
             */
            if ($action === 'benchmark' && isset($_GET['type'])) {
                // Release the session lock so parallel requests can run concurrently
                // Without this, PHP's default session locking causes all 15 requests to queue up
                session_write_close();
                
                @set_time_limit(30);
                if (ob_get_level()) ob_end_clean();
                header('Content-Type: application/json');
                
                $type = sanitize_input($_GET['type'], 'alnum');
                $result = run_benchmark_test($type);
                echo json_encode($result);
                exit;
            }

            /**
             * Handle custom database benchmark request
             */
            if ($action === 'db_custom_bench' && $_SERVER['REQUEST_METHOD'] === 'POST') {
                @set_time_limit(120); // Extended timeout for multi-pass sampling (5 runs per test)
                if (ob_get_level()) ob_end_clean();
                header('Content-Type: application/json');

                // Retrieve and sanitize POST parameters
                $host = isset($_POST['db_host']) ? trim($_POST['db_host']) : '';
                $dbname = isset($_POST['db_name']) ? trim($_POST['db_name']) : '';
                $user = isset($_POST['db_user']) ? trim($_POST['db_user']) : '';
                $pass = isset($_POST['db_pass']) ? $_POST['db_pass'] : '';
                $port = isset($_POST['db_port']) ? (int)$_POST['db_port'] : 3306;

                // Validate required fields
                if (empty($host) || empty($dbname) || empty($user)) {
                    echo json_encode([
                        'success' => false,
                        'error' => 'Host, Database Name, and Username are required fields.'
                    ]);
                    exit;
                }

                // Validate port
                if ($port < 1 || $port > 65535) {
                    echo json_encode([
                        'success' => false,
                        'error' => 'Invalid port number. Must be between 1 and 65535.'
                    ]);
                    exit;
                }

                // Run the benchmark
                $result = benchmark_database_standalone($host, $dbname, $user, $pass, $port);
                echo json_encode($result);
                exit;
            }

        }

        /**
         * Handle AJAX update requests for real-time data
         */
        if (isset($_GET['ajax']) && $_GET['ajax'] === 'update') {
                @set_time_limit(5); // Quick timeout for update requests
                header('Content-Type: application/json');

                $memory = get_memory_info();
                $cpu = get_cpu_usage();
                $load = get_load_average();
                $disk_t = @disk_total_space(".");
                $disk_f = @disk_free_space(".");
                $disk_u = $disk_t - $disk_f;
                $disk_p = $disk_t > 0 ? round(($disk_u / $disk_t) * 100, 2) : 0;
                $net = get_network_info();

                echo json_encode([
                    'memory' => $memory,
                    'cpu' => $cpu,
                    'load' => $load,
                    'disk_used' => round($disk_u / (1024*1024*1024), 3),
                    'disk_free' => round($disk_f / (1024*1024*1024), 3),
                    'disk_percent' => $disk_p,
                    'network' => $net,
                    'time' => date('Y-m-d H:i:s'),
                    'uptime' => get_uptime()
                ]);
            exit;
        }

        // ============================================================================
        // HTML OUTPUT
        // ============================================================================

        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
        <title>Hosting Benchmark</title>
        <style>
        <?php echo get_main_css(); ?>

        body {
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0;
        }

        .dashboard-header {
            background: var(--surface);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 30px;
            margin: 0 20px 0 20px;
            margin-top: 20px;
            border-radius: 20px 20px 0 0;
            box-shadow: var(--shadow-md);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }

        .dashboard-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .dashboard-title h1 {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            margin: 0;
        }

        .dashboard-title .version-badge {
            background: linear-gradient(135deg, var(--color-primary-600), var(--color-primary-500));
            color: white;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .theme-toggle {
            background: var(--surface-hover);
            border: 1px solid var(--border-color);
            border-radius: 999px;
            padding: 8px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            color: var(--text-primary);
            transition: all 0.2s ease;
        }

        .theme-toggle:hover {
            background: var(--color-primary-50);
            border-color: var(--color-primary-300);
            transform: translateY(-1px);
        }

        body.dark-mode .theme-toggle:hover {
            background: var(--color-primary-900);
        }

        .tab-navigation {
            background: var(--surface);
            padding: 0 30px;
            margin: 0 20px;
            border-bottom: 2px solid var(--border-color);
            display: flex;
            gap: 5px;
            overflow-x: auto;
        }

        .tab-button {
            background: transparent;
            border: none;
            padding: 16px 24px;
            font-size: 15px;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.2s ease;
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab-button:hover {
            color: var(--color-primary-600);
            background: rgba(69, 100, 228, 0.05);
        }

        .tab-button.active {
            color: var(--color-primary-600);
            border-bottom-color: var(--color-primary-600);
            font-weight: 600;
        }

        .tab-button i {
            font-size: 16px;
        }

        .tab-content {
            display: none;
            padding: 30px;
            margin: 0 20px 20px 20px;
            background: var(--surface);
            border-radius: 0 0 20px 20px;
            box-shadow: var(--shadow-lg);
            animation: fadeIn 0.3s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: var(--shadow-sm);
            display: flex;
            flex-direction: column;
            gap: 12px;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
            border-color: var(--color-primary-300);
        }

        .summary-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .summary-card-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            background: linear-gradient(135deg, var(--color-primary-600), var(--color-primary-500));
            color: white;
        }

        .summary-label {
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }

        .summary-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.2;
        }

        .summary-meta {
            font-size: 13px;
            color: var(--text-muted);
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .summary-chip {
            align-self: flex-start;
            padding: 4px 12px;
            border-radius: 999px;
            background: rgba(69, 100, 228, 0.1);
            color: var(--color-primary-600);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .chart-container {
            position: relative;
            height: 200px;
            margin-top: 12px;
        }

        .gauge-container {
            position: relative;
            width: 120px;
            height: 120px;
            margin: 16px auto 0;
        }

        .table-wrapper {
            width: 100%;
            overflow-x: auto;
            overflow-y: visible;
            -webkit-overflow-scrolling: touch;
            margin-bottom: 24px;
        }

        .table-wrapper table {
            margin-bottom: 0;
        }

        /* Auto-wrap tables in scrollable container on mobile */
        .tab-content {
            overflow-x: visible;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            margin-bottom: 24px;
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-sm);
            min-width: 100%;
            display: table;
        }

        #benchmark_results_table th,
        #benchmark_results_table td {
            overflow: visible;
            position: relative;
        }

        th {
            background: linear-gradient(135deg, var(--color-primary-50), var(--color-primary-100));
            color: var(--color-primary-900);
            padding: 16px;
            text-align: left;
            font-size: 14px;
            letter-spacing: 0.5px;
            font-weight: 600;
            text-transform: uppercase;
            position: relative;
        }

        body.dark-mode th {
            background: linear-gradient(135deg, var(--color-primary-900), var(--color-primary-800));
            color: var(--color-primary-100);
        }

        th.sortable {
            cursor: pointer;
            user-select: none;
        }

        th.sortable:hover {
            background: var(--color-primary-100);
        }

        th.sortable::after {
            content: '⇅';
            margin-left: 8px;
            opacity: 0.3;
            font-size: 12px;
        }

        th.sortable.asc::after {
            content: '↑';
            opacity: 1;
        }

        th.sortable.desc::after {
            content: '↓';
            opacity: 1;
        }

        td {
            padding: 12px 16px;
            border-top: 1px solid var(--border-color);
            color: var(--text-primary);
            position: relative;
            overflow: visible;
        }

        tr:hover td {
            background: rgba(69, 100, 228, 0.03);
        }

        tr:nth-child(even) td {
            background: rgba(247, 248, 252, 0.3);
        }

        body.dark-mode tr:nth-child(even) td {
            background: rgba(15, 23, 42, 0.3);
        }

        .table-search {
            margin-bottom: 16px;
            position: relative;
        }

        .table-search input {
            width: 100%;
            padding: 12px 16px 12px 44px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 14px;
            background: var(--surface);
            color: var(--text-primary);
            transition: all 0.2s ease;
        }

        .table-search input:focus {
            outline: none;
            border-color: var(--color-primary-600);
            box-shadow: 0 0 0 3px rgba(69, 100, 228, 0.1);
        }

        .table-search i {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }

        .collapsible-header {
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px;
            background: var(--color-primary-50);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            transition: all 0.2s ease;
        }

        body.dark-mode .collapsible-header {
            background: var(--color-primary-900);
        }

        .collapsible-header:hover {
            background: var(--color-primary-100);
        }

        .collapsible-header i {
            transition: transform 0.3s ease;
        }

        .collapsible-header.collapsed i {
            transform: rotate(-90deg);
        }

        .collapsible-content {
            max-height: 2000px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .collapsible-content.collapsed {
            max-height: 0;
        }

        .progress-bar {
            background: var(--border-color);
            height: 24px;
            border-radius: 12px;
            overflow: hidden;
            margin: 8px 0;
            position: relative;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--color-primary-600), var(--color-primary-500));
            transition: width 0.5s ease;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 11px;
            font-weight: 600;
        }

        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .progress-orange { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
        .progress-red { background: linear-gradient(90deg, #ef4444, #f87171); }
        .progress-blue { background: linear-gradient(90deg, #3b82f6, #60a5fa); }
        .progress-green { background: linear-gradient(90deg, #10b981, #34d399); }

        .text-red { color: var(--color-danger); }
        .text-blue { color: var(--color-info); }
        .text-green { color: var(--color-success); }
        .text-orange { color: var(--color-warning); }

        .module-list {
            font-family: 'Courier New', 'Monaco', monospace;
            font-size: 12px;
            line-height: 1.8;
            color: var(--text-secondary);
        }

        .btn {
            padding: 10px 20px;
            background: var(--color-primary-600);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            margin: 4px;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-sm);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn:hover {
            background: var(--color-primary-500);
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn:disabled {
            background: var(--text-muted);
            cursor: not-allowed;
            box-shadow: none;
            opacity: 0.6;
        }

        .btn-success { background: var(--color-success); }
        .btn-success:hover { background: #059669; }

        .btn-danger { background: var(--color-danger); }
        .btn-danger:hover { background: #dc2626; }

        .btn-warning { background: var(--color-warning); }
        .btn-warning:hover { background: #d97706; }

        .btn-info { background: var(--color-info); }
        .btn-info:hover { background: #2563eb; }

        .btn-secondary {
            background: var(--text-secondary);
            color: white;
        }
        .btn-secondary:hover {
            background: var(--text-primary);
        }

        body.dark-mode .btn-secondary {
            background: rgba(51, 65, 85, 0.8);
            color: var(--text-primary);
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        body.dark-mode .btn-secondary:hover {
            background: rgba(71, 85, 105, 0.9);
            border-color: rgba(148, 163, 184, 0.4);
        }

        .alert {
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            border-left: 4px solid;
        }

        .alert i {
            font-size: 20px;
            margin-top: 2px;
        }

        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--color-info);
            color: var(--text-primary);
        }

        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border-color: var(--color-warning);
            color: var(--text-primary);
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border-color: var(--color-success);
            color: var(--text-primary);
        }

        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--color-danger);
            color: var(--text-primary);
        }

        .benchmark-result {
            font-weight: 600;
            color: var(--text-primary);
        }

        .score-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 999px;
            font-weight: 600;
            color: white;
            min-width: 60px;
            text-align: center;
            font-size: 13px;
            box-shadow: var(--shadow-sm);
        }

        .score-0-2 { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .score-2-5 { background: linear-gradient(135deg, #f97316, #ea580c); }
        .score-5-6 { background: linear-gradient(135deg, #eab308, #ca8a04); }
        .score-6-7 { background: linear-gradient(135deg, #84cc16, #65a30d); }
        .score-7-8 { background: linear-gradient(135deg, #22c55e, #16a34a); }
        .score-8-9 { background: linear-gradient(135deg, #10b981, #059669); }
        .score-9-10 { background: linear-gradient(135deg, var(--color-primary-600), var(--color-primary-700)); }

        .icon {
            display: inline-block;
            font-style: normal;
            font-weight: normal;
            line-height: 1;
        }

        .icon-server::before { content: "🖥️"; }
        .icon-moon::before { content: "🌙"; }
        .icon-sun::before { content: "☀️"; }
        .icon-export::before { content: "📤"; }
        .icon-dashboard::before { content: "📊"; }
        .icon-chart::before { content: "📈"; }
        .icon-php::before { content: "🐘"; }
        .icon-info::before { content: "ℹ️"; }
        .icon-warning::before { content: "⚠️"; }
        .icon-pie::before { content: "📊"; }
        .icon-cpu::before { content: "⚙️"; }
        .icon-memory::before { content: "💾"; }
        .icon-database::before { content: "💿"; }
        .icon-disk::before { content: "💽"; }
        .icon-clock::before { content: "🕐"; }
        .icon-network::before { content: "🌐"; }
        .icon-download::before { content: "⬇️"; }
        .icon-upload::before { content: "⬆️"; }
        .icon-ethernet::before { content: "🔌"; }
        .icon-stopwatch::before { content: "⏱️"; }
        .icon-play::before { content: "▶️"; }
        .icon-star::before { content: "⭐"; }

        .gauge-chart {
            position: relative;
            width: 140px;
            height: 140px;
            margin: 0 auto;
        }

        .gauge-container {
            position: relative;
            width: 120px;
            height: 120px;
            margin: 0 auto;
        }

        .circular-progress {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient(
                var(--gauge-color, #8b5cf6) 0deg,
                var(--gauge-color, #8b5cf6) calc(var(--gauge-percent, 0) * 3.6deg),
                rgba(148, 163, 184, 0.1) calc(var(--gauge-percent, 0) * 3.6deg),
                rgba(148, 163, 184, 0.1) 360deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }

        .circular-progress::before {
            content: '';
            position: absolute;
            width: 90px;
            height: 90px;
            border-radius: 50%;
            background: var(--surface);
        }

        .gauge-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            z-index: 1;
        }

        .gauge-value-number {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1;
        }

        .gauge-value-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }

        #networkSparkline {
            width: 100%;
            height: 80px;
            display: block;
        }

        #networkSparklineLine {
            fill: none;
            stroke: #3b82f6;
            stroke-width: 2;
        }

        #networkSparklineArea {
            fill: url(#sparklineGradient);
            stroke: none;
        }

        .loading {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(69, 100, 228, 0.3);
            border-top-color: var(--color-primary-600);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-left: 8px;
            vertical-align: middle;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 500;
        }

        .status-indicator-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .status-healthy {
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-success);
        }

        .status-healthy .status-indicator-dot {
            background: var(--color-success);
        }

        .status-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--color-warning);
        }

        .status-warning .status-indicator-dot {
            background: var(--color-warning);
        }

        .status-danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--color-danger);
        }

        .status-danger .status-indicator-dot {
            background: var(--color-danger);
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--border-color);
        }

        .section-title {
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .section-title i {
            color: var(--color-primary-600);
        }

        input[type="text"],
        input[type="number"],
        select,
        textarea {
            padding: 10px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 14px;
            background: var(--surface);
            color: var(--text-primary);
            transition: all 0.2s ease;
        }

        input:focus,
        select:focus,
        textarea:focus {
            outline: none;
            border-color: var(--color-primary-600);
            box-shadow: 0 0 0 3px rgba(69, 100, 228, 0.1);
        }

        label {
            display: block;
            font-weight: 500;
            margin-bottom: 6px;
            color: var(--text-primary);
        }

        @media (max-width: 1024px) {
            .summary-grid {
                grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            }
        }

        @media (max-width: 768px) {
            body {
                font-size: 13px;
            }

            .dashboard-header {
                padding: 16px 20px;
                margin: 10px 10px 0 10px;
            }

            .dashboard-title h1 {
                font-size: 22px;
            }

            .tab-navigation {
                padding: 0 15px;
                margin: 0 10px;
            }

            .tab-button {
                padding: 12px 16px;
                font-size: 14px;
            }

            .tab-content {
                padding: 20px 15px;
                margin: 0 10px 10px 10px;
            }

            .summary-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }

            .summary-card {
                padding: 18px;
            }

            .summary-value {
                font-size: 28px;
            }

            .tab-content {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
            }

            .table-wrapper {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                margin-left: -15px;
                margin-right: -15px;
                padding-left: 15px;
                padding-right: 15px;
            }

            table {
                font-size: 13px;
                min-width: 600px;
                display: table;
            }

            th, td {
                padding: 10px 12px;
                white-space: nowrap;
            }

            /* Allow some cells to wrap if needed */
            td[colspan],
            th[colspan] {
                white-space: normal;
            }

            .btn {
                padding: 8px 16px;
                font-size: 13px;
            }

            .section-title {
                font-size: 18px;
            }
        }

        .benchmark-info-icon {
            display: inline-block;
            width: 16px;
            height: 16px;
            line-height: 16px;
            text-align: center;
            background: var(--color-primary-600);
            color: white;
            border-radius: 50%;
            font-size: 11px;
            font-weight: bold;
            cursor: help;
            margin-right: 6px;
            vertical-align: middle;
            position: relative;
        }

        .benchmark-info-icon:hover {
            background: var(--color-primary-500);
        }

        .benchmark-tooltip {
            visibility: hidden;
            opacity: 0;
            position: absolute;
            background-color: var(--color-primary-950);
            color: #fff;
            text-align: left;
            padding: 12px;
            border-radius: 8px;
            z-index: 99999;
            width: 300px;
            font-size: 13px;
            line-height: 1.5;
            box-shadow: 0 12px 24px rgba(4, 16, 59, 0.4);
            transition: opacity 0.3s, visibility 0.3s;
            pointer-events: none;
            left: 26px;
            top: 0;
            white-space: normal;
        }

        .benchmark-info-icon.tooltip-top .benchmark-tooltip {
            top: auto;
            bottom: 100%;
            left: 0;
            margin-bottom: 8px;
            transform: none;
        }

        .benchmark-info-icon.tooltip-top .benchmark-tooltip::after {
            top: auto;
            bottom: -12px;
            right: auto;
            left: 10px;
            border-color: var(--color-primary-950) transparent transparent transparent;
        }

        .benchmark-info-icon:hover .benchmark-tooltip {
            visibility: visible;
            opacity: 1;
        }

        .benchmark-tooltip::after {
            content: "";
            position: absolute;
            right: 100%;
            top: 10px;
            border-width: 6px;
            border-style: solid;
            border-color: transparent var(--color-primary-950) transparent transparent;
        }

        .benchmark-tooltip-title {
            font-weight: 700;
            margin-bottom: 6px;
            color: var(--color-primary-500);
            font-size: 14px;
        }

        .benchmark-tooltip-content {
            margin-bottom: 8px;
        }

        .benchmark-tooltip-realworld {
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            font-style: italic;
            color: rgba(255, 255, 255, 0.85);
        }

        .loading {
            display: inline-block;
            width: 12px;
            height: 12px;
            border: 2px solid rgba(255, 255, 255, 0.45);
            border-top: 2px solid var(--color-primary-600);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-left: 5px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .error-message {
            color: var(--color-primary-700);
            font-weight: bold;
            padding: 5px;
        }

        @media (max-width: 768px) {
            body { font-size: 12px; }
            .container { padding: 20px; }
            
            /* Make tab content scrollable horizontally */
            .tab-content {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                position: relative;
            }

            /* Wrap all tables in scrollable container */
            .tab-content > table {
                position: relative;
            }

            .tab-content::before {
                content: '';
                display: block;
                width: 100%;
            }

            .table-wrapper {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                margin-left: -20px;
                margin-right: -20px;
                padding-left: 20px;
                padding-right: 20px;
                width: calc(100% + 40px);
            }

            /* Make tables scrollable on mobile */
            table {
                min-width: 600px;
                font-size: 12px;
                display: table;
                width: auto;
                max-width: none;
            }

            /* Ensure tables don't break layout */
            .tab-content table {
                margin-left: 0;
                margin-right: 0;
            }

            td { 
                padding: 8px 10px; 
                white-space: nowrap;
            }
            
            th { 
                font-size: 12px; 
                padding: 10px 12px;
                white-space: nowrap;
            }

            /* Allow cells with colspan to wrap */
            td[colspan],
            th[colspan] {
                white-space: normal;
            }
            
            .btn { padding: 6px 12px; font-size: 12px; }
            .summary-grid {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }
        }

        .bg-light {
            background: rgba(249, 249, 249, 0.8);
        }

        body.dark-mode .bg-light {
            background: rgba(30, 41, 59, 0.5);
        }

        .bg-section {
            background: rgba(233, 236, 239, 0.8);
        }

        body.dark-mode .bg-section {
            background: rgba(51, 65, 85, 0.5);
        }

        .bg-warning-light {
            background: #fff3cd;
            color: #856404;
        }

        body.dark-mode .bg-warning-light {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
        }

        .text-muted-inline {
            color: #666;
        }

        body.dark-mode .text-muted-inline {
            color: #94a3b8;
        }

        .bg-category-header {
            background: #ddd;
        }

        body.dark-mode .bg-category-header {
            background: rgba(51, 65, 85, 0.5);
        }

        .btn-success-custom {
            background: #4CAF50 !important;
        }

        .btn-success-custom:hover {
            background: #45a049 !important;
        }

        .btn-danger-custom {
            background: #d9534f !important;
        }

        .btn-danger-custom:hover {
            background: #c9302c !important;
        }

        .btn-info-custom {
            background: #5bc0de !important;
        }

        .btn-info-custom:hover {
            background: #31b0d5 !important;
        }
        </style>
            </head>
            <body>

            <div class="container">
                <!-- Dashboard Header -->
                <div class="dashboard-header">
                    <div class="dashboard-title">
                        <span class="icon icon-server" style="font-size: 32px; color: var(--color-primary-600);"></span>
                        <div>
                            <h1>Hosting Benchmark Dashboard</h1>
                            <span class="version-badge">v1.0.1</span>
                        </div>
                    </div>
                    <div class="header-actions">
                        <button class="theme-toggle" onclick="toggleDarkMode()" title="Toggle Dark Mode">
                            <span class="icon icon-moon" id="theme-icon"></span>
                            <span id="theme-text">Dark Mode</span>
                        </button>
                        <a href="?logout=1" class="theme-toggle" style="text-decoration: none; color: var(--text-primary);" title="Logout">
                            <span>🚪</span>
                            <span>Logout</span>
                        </a>
                    </div>
                </div>

                <!-- Tab Navigation -->
                <div class="tab-navigation">
                    <button class="tab-button active" onclick="switchTab('dashboard')" data-tab="dashboard">
                        <span class="icon icon-dashboard"></span>
                        Dashboard
                    </button>
                    <button class="tab-button" onclick="switchTab('benchmarks')" data-tab="benchmarks">
                        <span class="icon icon-chart"></span>
                        Benchmarks
                    </button>
                    <button class="tab-button" onclick="switchTab('php-config')" data-tab="php-config">
                        <span class="icon icon-php"></span>
                        PHP Configuration
                    </button>
                    <button class="tab-button" onclick="switchTab('system-details')" data-tab="system-details">
                        <span class="icon icon-info"></span>
                        System Details
                    </button>
                </div>

                <!-- Dashboard Tab Content -->
                <div id="tab-dashboard" class="tab-content active">
                    <!-- Security Warning Banner -->
                    <div class="alert" style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(220, 38, 38, 0.05)); border-left: 4px solid #ef4444; margin-bottom: 20px;">
                        <span style="font-size: 24px;">🔒</span>
                        <div>
                            <strong style="color: #dc2626;">SECURITY REMINDER: Evaluation Tool Only</strong><br>
                            <small>This is a diagnostic/benchmarking tool with intentional error reporting. <strong>Delete this file after completing your server evaluation.</strong> Do not leave it accessible on a production website. For security: change default credentials, restrict access via .htaccess, or remove the file entirely when done.</small>
                        </div>
                    </div>

                    <?php if ($hosting_env['type'] == 'shared'): ?>
                    <div class="alert alert-warning">
                        <span class="icon icon-warning"></span>
                        <div>
                            <strong>Shared Hosting Detected</strong><br>
                            <small>Some system information (CPU model, system memory, server uptime) may not be available due to hosting restrictions. This is normal for shared hosting environments.</small>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Summary Cards with Visualizations -->
                    <div class="section-header">
                        <div class="section-title">
                            <span class="icon icon-pie"></span>
                            Server Health Snapshot
                        </div>
                    </div>

                    <div class="summary-grid">
                        <!-- CPU Usage Card -->
                        <div class="summary-card">
                            <div class="summary-card-header">
                                <div class="summary-card-icon" style="background: linear-gradient(135deg, #8b5cf6, #7c3aed);">
                                    <span class="icon icon-cpu"></span>
                                </div>
                            </div>
                            <div class="summary-label">CPU Usage</div>
                            <div class="summary-value"><?php echo round($cpu_usage['user'] + $cpu_usage['sys'], 1); ?>%</div>
                            <div class="summary-meta">
                                <span>User: <?php echo $cpu_usage['user']; ?>%</span>
                                <span>Sys: <?php echo $cpu_usage['sys']; ?>%</span>
                                <span>Idle: <?php echo $cpu_usage['idle']; ?>%</span>
                            </div>
                            <div class="gauge-container">
                                <?php 
                                $cpu_percent = round($cpu_usage['user'] + $cpu_usage['sys'], 1);
                                $gauge_color = $cpu_percent > 80 ? '#ef4444' : ($cpu_percent > 60 ? '#f59e0b' : '#8b5cf6');
                                ?>
                                <div class="circular-progress" style="--gauge-percent: <?php echo $cpu_percent; ?>; --gauge-color: <?php echo $gauge_color; ?>;">
                                </div>
                                <div class="gauge-value">
                                    <div class="gauge-value-number"><?php echo $cpu_percent; ?></div>
                                    <div class="gauge-value-label">%</div>
                                </div>
                            </div>
                            <div class="summary-chip">
                                <span class="icon icon-cpu"></span> <?php echo $cpu_info['cores']; ?> Cores
                            </div>
                        </div>

                        <!-- Memory Usage Card -->
                        <div class="summary-card">
                            <div class="summary-card-header">
                                <div class="summary-card-icon" style="background: linear-gradient(135deg, #06b6d4, #0891b2);">
                                    <span class="icon icon-memory"></span>
                                </div>
                            </div>
                            <div class="summary-label">Memory Usage</div>
                            <div class="summary-value"><?php echo $memory_info['percent']; ?>%</div>
                            <div class="summary-meta">
                                <span>Used: <?php echo round($memory_info['used'], 1); ?> MB</span>
                                <span>Free: <?php echo round($memory_info['free'], 1); ?> MB</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill progress-blue" style="width: <?php echo $memory_info['percent']; ?>%">
                                    <?php echo $memory_info['percent']; ?>%
                                </div>
                            </div>
                            <div class="summary-chip">
                                <span class="icon icon-database"></span> Total: <?php echo round($memory_info['total'], 1); ?> MB
                            </div>
                        </div>

                        <!-- Disk Space Card -->
                        <div class="summary-card">
                            <div class="summary-card-header">
                                <div class="summary-card-icon" style="background: linear-gradient(135deg, #f59e0b, #d97706);">
                                    <span class="icon icon-disk"></span>
                                </div>
                            </div>
                            <div class="summary-label">Disk Space</div>
                            <div class="summary-value"><?php echo $disk_percent; ?>%</div>
                            <div class="summary-meta">
                                <span>Used: <?php echo formatsize($disk_used); ?></span>
                                <span>Free: <?php echo formatsize($disk_free); ?></span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill progress-orange" style="width: <?php echo $disk_percent; ?>%">
                                    <?php echo $disk_percent; ?>%
                                </div>
                            </div>
                            <div class="summary-chip">
                                <span class="icon icon-pie"></span> Total: <?php echo formatsize($disk_total); ?>
                            </div>
                        </div>

                        <!-- Server Load Card -->
                        <div class="summary-card">
                            <div class="summary-card-header">
                                <div class="summary-card-icon" style="background: linear-gradient(135deg, #10b981, #059669);">
                                    <span class="icon icon-dashboard"></span>
                                </div>
                            </div>
                            <div class="summary-label">System Load</div>
                            <div class="summary-value"><?php echo $load_avg; ?></div>
                            <div class="summary-meta">
                                <?php 
                                $load_parts = explode(', ', $load_avg);
                                $load_1min = floatval($load_parts[0]);
                                $load_per_core = $load_1min / max($cpu_info['cores'], 1);
                                $load_status = 'healthy';
                                $load_icon = 'check-circle';
                                if ($load_per_core > 0.7) {
                                    $load_status = 'warning';
                                    $load_icon = 'exclamation-triangle';
                                }
                                if ($load_per_core > 1.0) {
                                    $load_status = 'danger';
                                    $load_icon = 'exclamation-circle';
                                }
                                ?>
                                <span class="status-indicator status-<?php echo $load_status; ?>">
                                    <span class="status-indicator-dot"></span>
                                    <?php echo round($load_per_core, 2); ?> per core
                                </span>
                            </div>
                            <div class="summary-meta">
                                <span><span class="icon icon-clock"></span> Uptime: <?php echo $server_info['uptime']; ?></span>
                            </div>
                            <div class="summary-chip">
                                <span class="icon icon-server"></span> <?php echo htmlspecialchars($server_info['hosting_type']); ?>
                            </div>
                        </div>

                        <!-- Network Traffic Card -->
                        <div class="summary-card">
                            <div class="summary-card-header">
                                <div class="summary-card-icon" style="background: linear-gradient(135deg, #3b82f6, #2563eb);">
                                    <span class="icon icon-network"></span>
                                </div>
                            </div>
                            <div class="summary-label">Network Traffic</div>
                            <div class="summary-value"><?php echo formatsize($network_total_rx); ?></div>
                            <div class="summary-meta">
                                <span><span class="icon icon-download"></span> In: <?php echo formatsize($network_total_rx); ?></span>
                                <span><span class="icon icon-upload"></span> Out: <?php echo formatsize($network_total_tx); ?></span>
                            </div>
                            <div class="chart-container" style="height: 80px; margin-top: 10px;">
                                <svg id="networkSparkline" width="100%" height="80" style="display: block;">
                                    <defs>
                                        <linearGradient id="sparklineGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                                            <stop offset="0%" style="stop-color:rgba(59, 130, 246, 0.3);stop-opacity:1" />
                                            <stop offset="100%" style="stop-color:rgba(59, 130, 246, 0.05);stop-opacity:1" />
                                        </linearGradient>
                                    </defs>
                                    <polygon id="networkSparklineArea" fill="url(#sparklineGradient)" stroke="none" points=""/>
                                    <polyline id="networkSparklineLine" fill="none" stroke="#3b82f6" stroke-width="2" points=""/>
                                </svg>
                            </div>
                            <div class="summary-chip">
                                <span class="icon icon-ethernet"></span> <?php echo htmlspecialchars($network_interfaces); ?> Interface(s)
                            </div>
                        </div>
                    </div>

            <!-- Server Parameters -->
            <table>
                <tr><th colspan="4">Server Parameters</th></tr>
                <tr>
                    <td width="15%">Server ID</td>
                    <td colspan="3"><?php echo htmlspecialchars($server_info['server_id']); ?></td>
                </tr>
                <tr>
                    <td>Server OS</td>
                    <td width="35%"><?php echo htmlspecialchars($server_info['server_os']); ?></td>
                    <td width="15%">Web Server</td>
                    <td width="35%"><?php echo htmlspecialchars($server_info['server_software']); ?></td>
                </tr>
                <tr>
                    <td>Access Level</td>
                    <td><?php
                        if ($hosting_env['type'] == 'shared') {
                            echo '<span class="text-orange">Limited system access</span>';
                        } else {
                            echo '<span class="text-blue">Full access</span>';
                        }
                    ?></td>
                    <td>Restrictions</td>
                    <td><?php 
                        if (!empty($hosting_env['restrictions'])) {
                            echo '<span class="text-orange">' . implode(', ', $hosting_env['restrictions']) . '</span>';
                        } else {
                            echo '<span class="text-green">None detected</span>';
                        }
                    ?></td>
                </tr>
                <tr>
                    <td>Server Language</td>
                    <td><?php echo htmlspecialchars($server_info['server_language']); ?></td>
                    <td>Server Port</td>
                    <td><?php echo htmlspecialchars($server_info['server_port']); ?></td>
                </tr>
                <tr>
                    <td>Server Hostname</td>
                    <td><?php echo htmlspecialchars($server_info['server_hostname']); ?></td>
                    <td>Root Path</td>
                    <td><?php echo htmlspecialchars($server_info['root_path']); ?></td>
                </tr>
                <tr>
                    <td>Server Admin</td>
                    <td><?php echo htmlspecialchars($server_info['server_admin']); ?></td>
                    <td>Prober Path</td>
                    <td><?php echo htmlspecialchars($server_info['prober_path']); ?></td>
                </tr>
            </table>

            <!-- Server Real time Data -->
            <table>
                <tr><th colspan="6">Server Real time Data</th></tr>
                <tr>
                    <td width="15%">Current Time</td>
                    <td width="35%"><span id="current_time"><?php echo $server_info['current_time']; ?></span></td>
                    <td width="15%">Server Uptime</td>
                    <td width="35%" colspan="3"><span id="uptime"><?php echo $server_info['uptime']; ?></span></td>
                </tr>
                <tr>
                    <td>CPU Model [<?php echo $cpu_info['cores']; ?>Core]</td>
                    <td colspan="5">
                        <?php 
                        if ($cpu_info['restricted']) {
                            echo '<span class="text-orange">' . htmlspecialchars($cpu_info['model']) . '</span> <small>(System info not available on shared hosting)</small>';
                        } else {
                            echo htmlspecialchars($cpu_info['model']);
                            if ($cpu_info['mhz']) echo ' | frequency:' . $cpu_info['mhz'] . 'GHz';
                            if ($cpu_info['cache']) echo ' | Secondary cache:' . $cpu_info['cache'] . ' KB';
                            if ($cpu_info['bogomips']) echo ' | Bogomips:' . $cpu_info['bogomips'];
                            if ($cpu_info['cores'] > 1) echo ' ×' . $cpu_info['cores'];
                        }
                        ?>
                    </td>
                </tr>
                <tr>
                    <td>CPU Usage</td>
                    <td colspan="5">
                        <span id="cpu_usage">
                            <?php echo $cpu_usage['user']; ?>%us, 
                            <?php echo $cpu_usage['sys']; ?>%sy, 
                            <?php echo $cpu_usage['nice']; ?>%ni, 
                            <?php echo $cpu_usage['idle']; ?>%id, 
                            <?php echo $cpu_usage['iowait']; ?>%wa, 
                            <?php echo $cpu_usage['irq']; ?>%irq, 
                            <?php echo $cpu_usage['softirq']; ?>%softirq
                        </span>
                    </td>
                </tr>
                <tr>
                    <td>Space Usage</td>
                    <td colspan="5">
                        Total Space <?php echo round($disk_total / (1024*1024*1024), 3); ?> G,
                        Used <span id="disk_used" class="text-red"><?php echo round($disk_used / (1024*1024*1024), 3); ?></span> G,
                        Free <span id="disk_free" class="text-green"><?php echo round($disk_free / (1024*1024*1024), 3); ?></span> G,
                        Rate <span id="disk_percent"><?php echo $disk_percent; ?></span>%
                        <div class="progress-bar">
                            <div id="disk_progress" class="progress-fill progress-orange" style="width: <?php echo $disk_percent; ?>%"></div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td>Memory Usage</td>
                    <td colspan="5">
                        <?php if ($memory_info['restricted'] && $memory_info['is_php_limit']): ?>
                            <span class="text-orange">⚠ System memory not accessible on shared hosting</span><br>
                            <small>Showing PHP Script Memory Limit instead:</small><br>
                        <?php endif; ?>

                        <?php if ($memory_info['is_php_limit']): ?>
                        PHP Memory Limit: <span class="text-red"><?php echo $mem_format['total']; ?></span>,
                        <?php else: ?>
                        Total Memory: <span class="text-red"><?php echo $mem_format['total']; ?></span>,
                        <?php endif; ?>
                        Used <span id="mem_used" class="text-red"><?php echo $mem_format['used']; ?></span>,
                        Free <span id="mem_free" class="text-red"><?php echo $mem_format['free']; ?></span>,
                        Rate <span id="mem_percent"><?php echo $memory_info['percent']; ?></span>%
                        <div class="progress-bar">
                            <div id="mem_progress" class="progress-fill progress-green" style="width: <?php echo $memory_info['percent']; ?>%"></div>
                        </div>

                        <?php if (!$memory_info['restricted']): ?>
                        Cache Memory <span id="mem_cached"><?php echo $mem_format['cached']; ?></span>,
                        Rate <span id="mem_cached_percent"><?php echo round(($memory_info['cached'] / $memory_info['total']) * 100, 2); ?></span>% |
                        Buffers <span id="mem_buffers"><?php echo $mem_format['buffers']; ?></span>
                        <div class="progress-bar">
                            <div id="mem_cached_progress" class="progress-fill progress-blue" style="width: <?php echo round(($memory_info['cached'] / $memory_info['total']) * 100, 2); ?>%"></div>
                        </div>

                        Real Memory Used <span id="mem_real_used"><?php echo $mem_format['real_used']; ?></span>,
                        Real Memory Free <span id="mem_real_free"><?php echo $mem_format['real_free']; ?></span>,
                        Rate <span id="mem_real_percent"><?php echo $memory_info['real_percent']; ?></span>%
                        <div class="progress-bar">
                            <div id="mem_real_progress" class="progress-fill progress-blue" style="width: <?php echo $memory_info['real_percent']; ?>%"></div>
                        </div>

                        <?php if ($memory_info['swap_total'] > 0): ?>
                        SWAP: <?php echo $mem_format['swap_total']; ?>,
                        Used <span id="swap_used"><?php echo $mem_format['swap_used']; ?></span>,
                        Free <span id="swap_free"><?php echo $mem_format['swap_free']; ?></span>,
                        Rate <span id="swap_percent"><?php echo $memory_info['swap_percent']; ?></span>%
                        <div class="progress-bar">
                            <div id="swap_progress" class="progress-fill progress-red" style="width: <?php echo $memory_info['swap_percent']; ?>%"></div>
                        </div>
                        <?php endif; ?>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td>System Load</td>
                    <td colspan="5"><span id="load_avg" class="text-blue"><?php echo $load_avg; ?></span></td>
                </tr>
            </table>

            <!-- Network -->
            <?php if (!empty($network_info)): ?>
            <table>
                <tr><th colspan="5">Network</th></tr>
                <?php foreach ($network_info as $iface => $data): ?>
                <tr>
                    <td width="15%"><?php echo htmlspecialchars($iface); ?>:</td>
                    <td width="25%">In: <span class="text-red" id="net_in_<?php echo $iface; ?>"><?php echo formatsize($data['rx']); ?></span></td>
                    <td width="20%">Real time: <span class="text-red" id="net_in_speed_<?php echo $iface; ?>">0B/s</span></td>
                    <td width="25%">Out: <span class="text-red" id="net_out_<?php echo $iface; ?>"><?php echo formatsize($data['tx']); ?></span></td>
                    <td width="20%">Real time: <span class="text-red" id="net_out_speed_<?php echo $iface; ?>">0B/s</span></td>
                </tr>
                <?php endforeach; ?>
            </table>
            <?php endif; ?>

                </div>
                <!-- End Dashboard Tab -->

                <!-- Benchmarks Tab Content -->
                <div id="tab-benchmarks" class="tab-content">
                    <div class="section-header">
                        <div class="section-title">
                            <span class="icon icon-chart"></span>
                            Performance Benchmarking
                        </div>
                    </div>

            <!-- Latency Testing Tool -->
            <div class="section-header" style="margin-top: 30px;">
                <div class="section-title">
                    <span class="icon icon-stopwatch"></span>
                    Custom Latency Test (TCP Ping)
                </div>
            </div>

            <div class="alert alert-info">
                <span class="icon icon-info"></span>
                <div>
                    <strong>About This Test</strong><br>
                    Test network latency to any server or IP address using TCP connection time. This uses TCP connections (not ICMP ping) which works without special privileges. Results may differ slightly from traditional ping but are still accurate for latency measurement.
                </div>
            </div>

            <div style="background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 24px;">
                <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 15px;">
                    <div style="flex: 1; min-width: 200px;">
                        <label for="ping_target" style="display: block; margin-bottom: 5px; font-weight: bold;">Target (IP or Hostname):</label>
                        <input type="text" id="ping_target" value="1.1.1.1" placeholder="e.g., google.com or 1.1.1.1" 
                            style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                    </div>
                    <div style="width: 120px;">
                        <label for="ping_port" style="display: block; margin-bottom: 5px; font-weight: bold;">Port:</label>
                        <select id="ping_port" style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                            <option value="80" selected>80 (HTTP)</option>
                            <option value="443">443 (HTTPS)</option>
                            <option value="53">53 (DNS)</option>
                            <option value="3306">3306 (MySQL)</option>
                        </select>
                    </div>
                    <div style="width: 100px;">
                        <label for="ping_count" style="display: block; margin-bottom: 5px; font-weight: bold;">Count:</label>
                        <select id="ping_count" style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                            <option value="4" selected>4</option>
                            <option value="5">5</option>
                            <option value="10">10</option>
                        </select>
                    </div>
                    <div>
                        <button class="btn btn-info" onclick="runPingTest()" id="ping_btn">
                            <span class="icon icon-play"></span> Run Test
                        </button>
                    </div>
                </div>

                <!-- Quick Presets -->
                <div style="margin-bottom: 15px; padding: 12px; background: rgba(59, 130, 246, 0.05); border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.1);">
                    <strong style="display: block; margin-bottom: 10px;"><span class="icon icon-star"></span> Quick Presets:</strong>
                    <button class="btn btn-secondary" onclick="setPingTarget('8.8.8.8', 53)" style="padding: 6px 12px; margin: 2px; font-size: 12px;">Google DNS</button>
                    <button class="btn btn-secondary" onclick="setPingTarget('1.1.1.1', 80)" style="padding: 6px 12px; margin: 2px; font-size: 12px;">Cloudflare DNS</button>
                    <button class="btn btn-secondary" onclick="setPingTarget('google.com', 443)" style="padding: 6px 12px; margin: 2px; font-size: 12px;">Google</button>
                    <button class="btn btn-secondary" onclick="setPingTarget('github.com', 443)" style="padding: 6px 12px; margin: 2px; font-size: 12px;">GitHub</button>
                    <button class="btn btn-secondary" onclick="setPingTarget('amazon.com', 443)" style="padding: 6px 12px; margin: 2px; font-size: 12px;">Amazon</button>
                </div>

                <!-- Results Display -->
                <div id="ping_results" style="display: none;">
                    <div style="background: var(--surface); padding: 15px; border-radius: 8px; border: 1px solid var(--border-color);">
                        <h3 style="margin: 0 0 10px 0; color: var(--text-primary);">
                            Results for <span id="ping_results_target">-</span>:<span id="ping_results_port">-</span>
                        </h3>

                        <div id="ping_packets" style="font-family: 'Courier New', monospace; margin: 10px 0; padding: 12px; background: var(--bg-primary); border-radius: 6px; max-height: 200px; overflow-y: auto;"></div>

                        <div style="margin-top: 15px; padding: 12px; background: rgba(69, 100, 228, 0.05); border-radius: 6px; border: 1px solid rgba(69, 100, 228, 0.1);">
                            <strong>Summary:</strong><br>
                            <div style="margin-top: 8px; line-height: 1.8;">
                                Packets: Sent = <span id="ping_sent">-</span>, Received = <span id="ping_received" class="text-green">-</span>, Lost = <span id="ping_lost" class="text-red">-</span> (<span id="ping_loss">-</span>% loss)<br>
                                <span id="ping_stats_rtt" style="display: none;">
                                    Round-trip times: Min = <span id="ping_min" class="text-green">-</span>ms, Max = <span id="ping_max" class="text-red">-</span>ms, Avg = <span id="ping_avg" class="text-blue">-</span>ms
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Comprehensive Hosting Performance Benchmark -->
            <table>
                <tr><th colspan="2">🏆 Comprehensive Hosting Performance Benchmark</th></tr>
                <tr>
                    <td colspan="2" class="bg-light" style="padding: 15px;">
                        <p style="margin: 0 0 10px 0; line-height: 1.6;">
                            This comprehensive benchmark evaluates your hosting environment across multiple dimensions including 
                            CPU performance, memory operations, filesystem I/O, database performance, caching capabilities, and network operations. 
                            Perfect for comparing shared hosting providers and identifying performance bottlenecks.
                        </p>
                        <p class="text-muted-inline" style="margin: 0; font-size: 13px;">
                            <strong>Note:</strong> Tests are designed for shared hosting environments and use only standard PHP functions. 
                            No external dependencies required. Each test runs safely within typical hosting limits.
                        </p>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" style="padding: 0 15px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin: 15px 0; padding: 15px; background: rgba(59, 130, 246, 0.05); border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.1);">
                            <div>
                                <strong>Scoring Mode:</strong>
                                <select id="scoring_mode" onchange="updateScoringMode()" style="margin-left: 10px; padding: 8px; border-radius: 6px; border: 1px solid var(--border-color);">
                                    <option value="modern" selected>2025 Modern (Strict)</option>
                                    <option value="light">Light (Legacy)</option>
                                </select>
                            </div>
                            <div style="font-size: 13px; color: var(--text-muted);">
                                <span id="scoring_description">
                                    <strong>Modern:</strong> Reflects 2025 hosting standards with NVMe and modern CPUs
                                </span>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" style="text-align: center; padding: 20px;">
                        <div style="margin-bottom: 15px;">
                            <button class="btn btn-success-custom" onclick="runComprehensiveBenchmark()" id="comp_bench_btn" style="font-size: 16px; padding: 12px 30px;">
                                🚀 Run Benchmark
                            </button>
                            <button class="btn btn-info" onclick="downloadBenchmarkTXT()" id="download_txt_btn" title="Download Benchmark Results" style="font-size: 16px; padding: 12px 30px; margin-left: 10px; display: none;">
                                📄 Download Benchmark
                            </button>
                            <button class="btn btn-danger-custom" onclick="stopBenchmark()" id="stop_bench_btn" style="font-size: 14px; padding: 10px 20px; display: none;">
                                ⏹ Stop Benchmark
                            </button>
                        </div>
                        <div id="overall_progress" style="display: none;">
                            <div style="font-weight: bold; margin-bottom: 5px;">
                                Overall Progress: <span id="overall_percent">0</span>% 
                                <span id="current_test_name" class="text-muted-inline" style="font-weight: normal; font-size: 13px;"></span>
                            </div>
                            <div class="progress-bar" style="height: 30px;">
                                <div id="overall_progress_bar" class="progress-fill progress-blue" style="width: 0%; font-size: 16px; line-height: 30px;"></div>
                            </div>
                        </div>
                    </td>
                </tr>
            </table>

            <table id="benchmark_results_table" style="display: none;">
                <tr><th colspan="4">Benchmark Results</th></tr>

                <!-- CPU & Memory Performance -->
                <tr>
                    <td colspan="4" class="bg-section" style="font-weight: bold; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>💻 CPU & Memory Performance</span>
                            <div class="bg-category-header" style="width: 200px; height: 20px; border-radius: 5px; overflow: hidden;">
                                <div id="cat_cpu_progress" class="progress-fill progress-green" style="width: 0%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td width="50%"><span class="benchmark-info-icon" title="Integer Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Integer Operations</div><div class="benchmark-tooltip-content">Performs 20 million integer arithmetic operations (addition, subtraction, multiplication) to measure raw CPU computational speed.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Reflects performance in applications that do heavy number crunching, calculations, loops, and data processing. Important for e-commerce price calculations, analytics, and mathematical operations.</div></span></span>Integer Operations (5M calculations)</td>
                    <td width="15%" style="text-align: center;"><span id="result_cpu_int">-</span>s</td>
                    <td width="15%" style="text-align: center;"><span id="score_cpu_int" class="score-badge">-</span></td>
                    <td width="20%" style="text-align: center; font-size: 12px;">Basic CPU speed</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Float Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Float Operations</div><div class="benchmark-tooltip-content">Executes 10 million floating-point operations including square roots, powers, logarithms, and trigonometric functions (sin, cos).</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Critical for scientific computing, graphics rendering, financial calculations, game engines, and any application requiring precise decimal math. Affects performance of image processing, 3D rendering, and statistical analysis.</div></span></span>Float Operations (5M sqrt calculations)</td>
                    <td style="text-align: center;"><span id="result_cpu_float">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cpu_float" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Math performance</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Large Text Processing">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Large Text Processing</div><div class="benchmark-tooltip-content">Processes large text blocks (2000 sentences) with 50K operations including case conversion, string length, search, replace, and HTML encoding.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how well your server handles content management, text parsing, search functionality, and string manipulation. Important for CMS platforms, blog systems, and applications that process user-generated content.</div></span></span>Large Text Processing (10K operations)</td>
                    <td style="text-align: center;"><span id="result_cpu_text">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cpu_text" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">String handling</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Binary Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Binary Operations</div><div class="benchmark-tooltip-content">Performs 2 million bitwise operations (AND, OR, XOR, bit shifts) and modulo operations to test low-level CPU performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Essential for encryption, hashing, compression algorithms, and binary data processing. Affects security operations, data encoding/decoding, and performance of cryptographic functions.</div></span></span>Binary Operations (500K bitwise ops)</td>
                    <td style="text-align: center;"><span id="result_cpu_binary">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cpu_binary" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Binary processing</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="String Manipulation">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">String Manipulation</div><div class="benchmark-tooltip-content">Executes 500K string operations including case conversion, substring extraction, search, replace, and trimming operations.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Directly impacts form validation, data sanitization, URL processing, and text transformation. Critical for web applications that process user input, generate dynamic content, or manipulate text data.</div></span></span>String Manipulation (100K operations)</td>
                    <td style="text-align: center;"><span id="result_string">-</span>s</td>
                    <td style="text-align: center;"><span id="score_string" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">String functions</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Array Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Array Operations</div><div class="benchmark-tooltip-content">Performs 200K array operations including reversing, summing, filtering, mapping, merging, and sorting on arrays of 500 elements.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures performance of data manipulation, list processing, and collection operations. Important for applications that work with datasets, process lists, filter/search data, or perform data transformations.</div></span></span>Array Operations (50K operations)</td>
                    <td style="text-align: center;"><span id="result_array">-</span>s</td>
                    <td style="text-align: center;"><span id="score_array" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Array processing</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Hash Functions">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Hash Functions</div><div class="benchmark-tooltip-content">Executes 200K hashing operations using MD5, SHA1, SHA256, SHA512, and CRC32 algorithms on varying data.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Critical for password security, data integrity checks, cache keys, and unique identifiers. Affects authentication performance, file verification, and any system using cryptographic hashing.</div></span></span>Hash Functions (50K MD5/SHA1/SHA256)</td>
                    <td style="text-align: center;"><span id="result_hash">-</span>s</td>
                    <td style="text-align: center;"><span id="score_hash" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Hashing speed</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="JSON Processing">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">JSON Processing</div><div class="benchmark-tooltip-content">Performs 200K JSON encode/decode operations on complex nested data structures with arrays, objects, and metadata.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Essential for API performance, data serialization, and modern web applications. Directly impacts REST API response times, AJAX operations, configuration file parsing, and data exchange between services.</div></span></span>JSON Encode/Decode (50K operations)</td>
                    <td style="text-align: center;"><span id="result_json">-</span>s</td>
                    <td style="text-align: center;"><span id="score_json" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">JSON processing</td>
                </tr>

                <!-- Filesystem I/O -->
                <tr>
                    <td colspan="4" class="bg-section" style="font-weight: bold; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>📁 Filesystem I/O Performance</span>
                            <div class="bg-category-header" style="width: 200px; height: 20px; border-radius: 5px; overflow: hidden;">
                                <div id="cat_fs_progress" class="progress-fill progress-green" style="width: 0%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="File I/O Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">File I/O Operations</div><div class="benchmark-tooltip-content">Performs 10K sequential file read operations (1KB chunks) with file pointer rewinding to test disk read performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how quickly your server can read files from disk. Critical for applications that load templates, read configuration files, serve static assets, or process log files. Affects page load times and file-serving performance.</div></span></span>File I/O Operations (10K reads)</td>
                    <td style="text-align: center;"><span id="result_io">-</span>s</td>
                    <td style="text-align: center;"><span id="score_io" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Read performance</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Sequential Write">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Sequential Write</div><div class="benchmark-tooltip-content">Writes 5K sequential file operations (10KB each) to test disk write throughput and I/O performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Important for applications that generate files, write logs, create cache files, or save user uploads. Affects performance of content management systems, logging systems, and file-based caching.</div></span></span>Sequential Write (1K × 1KB)</td>
                    <td style="text-align: center;"><span id="result_fs_write">-</span>s</td>
                    <td style="text-align: center;"><span id="score_fs_write" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Write throughput</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="File Copy & Access">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">File Copy & Access</div><div class="benchmark-tooltip-content">Performs 2K file copy operations followed by content verification to test file system copy performance and data integrity.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures backup performance, file migration speed, and file duplication operations. Important for content replication, backup systems, and applications that need to duplicate or move files.</div></span></span>File Copy & Access (500 operations)</td>
                    <td style="text-align: center;"><span id="result_fs_copy">-</span>s</td>
                    <td style="text-align: center;"><span id="score_fs_copy" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Copy speed</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Small File I/O">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Small File I/O</div><div class="benchmark-tooltip-content">Executes 8K small file write/read cycles (simulating session files and cache entries) with JSON encoding/decoding.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Simulates real-world scenarios like session file handling, cache file operations, and log entry writes. Critical for applications with high session activity, file-based caching, and frequent small file operations.</div></span></span>Small File I/O (2K write/read cycles)</td>
                    <td style="text-align: center;"><span id="result_fs_small">-</span>s</td>
                    <td style="text-align: center;"><span id="score_fs_small" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">IOPS capability</td>
                </tr>

                <!-- Database Performance -->
                <tr>
                    <td colspan="4" class="bg-section" style="font-weight: bold; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>🗄️ Database Performance (SQLite - Disk I/O & Driver)</span>
                            <div class="bg-category-header" style="width: 200px; height: 20px; border-radius: 5px; overflow: hidden;">
                                <div id="cat_db_progress" class="progress-fill progress-green" style="width: 0%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Database Insert">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Database Insert</div><div class="benchmark-tooltip-content">Performs bulk insert of 1K records into SQLite database with indexes to test database write performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how quickly your server can insert data into databases. Critical for applications that import data, log events, store user-generated content, or perform batch operations. Affects data ingestion performance.</div></span></span>Bulk Insert (1K records)</td>
                    <td style="text-align: center;"><span id="result_db_import">-</span>s</td>
                    <td style="text-align: center;"><span id="score_db_import" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Write performance</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Simple Queries">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Simple Queries</div><div class="benchmark-tooltip-content">Executes 500 simple SELECT queries with WHERE clauses to test basic database read performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Essential for any application that queries databases. Affects page load times, search functionality, and data retrieval. Critical for content management systems, e-commerce platforms, and any data-driven application.</div></span></span>Simple Queries (500 SELECT statements)</td>
                    <td style="text-align: center;"><span id="result_db_simple">-</span>s</td>
                    <td style="text-align: center;"><span id="score_db_simple" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Read performance</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Complex Queries">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Complex Queries</div><div class="benchmark-tooltip-content">Performs 200 complex queries with GROUP BY, ORDER BY, JOINs, and aggregations to test query optimization capabilities.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures performance of advanced database operations like reporting, analytics, data aggregation, and complex searches. Important for dashboards, reporting systems, and applications with sophisticated data queries.</div></span></span>Complex Queries (200 GROUP BY with ORDER)</td>
                    <td style="text-align: center;"><span id="result_db_complex">-</span>s</td>
                    <td style="text-align: center;"><span id="score_db_complex" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Query optimization</td>
                </tr>

                <!-- Object Cache & Memory -->
                <tr>
                    <td colspan="4" class="bg-section" style="font-weight: bold; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>⚡ Object Cache & Memory Operations</span>
                            <div class="bg-category-header" style="width: 200px; height: 20px; border-radius: 5px; overflow: hidden;">
                                <div id="cat_cache_progress" class="progress-fill progress-green" style="width: 0%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="OPcache Status">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">OPcache Status</div><div class="benchmark-tooltip-content">Checks if OPcache (PHP bytecode cache) is enabled on the server.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> OPcache can improve PHP performance by 3-10x by caching compiled bytecode. Essential for production environments. Without OPcache, PHP recompiles scripts on every request.</div></span></span>OPcache Enabled</td>
                    <td style="text-align: center;"><span id="result_opcache_enabled">-</span></td>
                    <td style="text-align: center;"><span id="score_opcache_enabled" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Bytecode cache</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="OPcache Performance">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">OPcache Performance</div><div class="benchmark-tooltip-content">Tests OPcache effectiveness by including a PHP file 1000 times and measuring execution speed.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how well OPcache accelerates PHP execution. Faster times indicate better caching and improved application response times.</div></span></span>OPcache Performance (1K includes)</td>
                    <td style="text-align: center;"><span id="result_opcache_performance">-</span>s</td>
                    <td style="text-align: center;"><span id="score_opcache_performance" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Cache effectiveness</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Cache Availability">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Object Cache Availability</div><div class="benchmark-tooltip-content">Checks if Redis or Memcached caching extensions are available and working on the server.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Indicates whether your server supports high-performance object caching systems. Object caching dramatically improves application performance by reducing database load and speeding up data retrieval.</div></span></span>Object Cache (Redis/Memcached)</td>
                    <td style="text-align: center;"><span id="result_cache_enabled">-</span></td>
                    <td style="text-align: center;"><span id="score_cache_enabled" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Object cache support</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Cache Write">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Cache Write</div><div class="benchmark-tooltip-content">Performs 5K cache write operations with data serialization to test cache write performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how quickly your server can store data in cache. Critical for applications that cache database queries, API responses, or computed results. Affects cache warming and data storage performance.</div></span></span>Cache Write (5K serialize operations)</td>
                    <td style="text-align: center;"><span id="result_cache_write">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cache_write" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Write speed</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Cache Read">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Cache Read</div><div class="benchmark-tooltip-content">Performs 5K cache read operations with data unserialization from random cache keys to test cache retrieval speed.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures cache hit performance. Essential for reducing database load and improving response times. Critical for high-traffic applications, API caching, and systems that rely heavily on cached data.</div></span></span>Cache Read (5K unserialize operations)</td>
                    <td style="text-align: center;"><span id="result_cache_read">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cache_read" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Read speed</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Mixed Cache Operations">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Mixed Cache Operations</div><div class="benchmark-tooltip-content">Simulates realistic cache usage with 3K operations using a 70% read / 30% write ratio to test mixed workload performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Represents real-world cache usage patterns. Most applications read from cache more often than they write. This test reflects actual performance in production environments with typical cache access patterns.</div></span></span>Mixed Cache Operations (3K read/write mix)</td>
                    <td style="text-align: center;"><span id="result_cache_mixed">-</span>s</td>
                    <td style="text-align: center;"><span id="score_cache_mixed" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Real-world usage</td>
                </tr>

                <!-- Network Operations -->
                <tr>
                    <td colspan="4" class="bg-section" style="font-weight: bold; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span>🌐 Network Operations</span>
                            <div class="bg-category-header" style="width: 200px; height: 20px; border-radius: 5px; overflow: hidden;">
                                <div id="cat_network_progress" class="progress-fill progress-green" style="width: 0%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Internet & DNS Speed">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Internet & DNS Speed</div><div class="benchmark-tooltip-content">Tests DNS resolution speed, TCP connection latency to multiple servers, and downloads a 100KB test file to measure overall network performance.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures your server's ability to communicate with external services. Critical for applications that call APIs, fetch external data, integrate with third-party services, or perform webhooks. Affects API response times and external service integration performance.</div></span></span>Internet & DNS Speed (DNS, TCP latency, download)</td>
                    <td style="text-align: center;"><span id="result_network">-</span>s</td>
                    <td style="text-align: center;"><span id="score_network" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Real-world network performance</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Network Latency">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Network Latency</div><div class="benchmark-tooltip-content">Measures average network latency by testing DNS resolution times and HTTP connection establishment times to multiple reliable servers.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Indicates how quickly your server can establish connections to external services. Lower latency means faster API calls, quicker external data fetching, and better performance for applications that depend on network communication.</div></span></span>Network Latency (DNS + HTTP connection time)</td>
                    <td style="text-align: center;"><span id="result_network_latency">-</span>ms</td>
                    <td style="text-align: center;"><span id="score_network_latency" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Response time</td>
                </tr>
                <tr>
                    <td><span class="benchmark-info-icon" title="Concurrency Stress Test">ℹ<span class="benchmark-tooltip"><div class="benchmark-tooltip-title">Concurrency Stress Test</div><div class="benchmark-tooltip-content">Tests server concurrency by making 15 parallel AJAX requests simultaneously. Each request performs CPU work and disk I/O to simulate real load.</div><div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> Measures how well your web server (Nginx/Apache) and PHP-FPM handle multiple simultaneous connections. Critical for high-traffic applications. Good concurrency handling means faster response times under load, while poor handling leads to request queuing and timeouts.</div></span></span>Concurrency Stress Test (15 parallel requests)</td>
                    <td style="text-align: center;"><span id="result_concurrency">-</span></td>
                    <td style="text-align: center;"><span id="score_concurrency" class="score-badge">-</span></td>
                    <td style="text-align: center; font-size: 12px;">Avg response time</td>
                </tr>

                <!-- Total Score -->
                <tr>
                    <td colspan="4" style="background: #4CAF50; color: white; font-weight: bold; padding: 15px; text-align: center;">
                        <div style="font-size: 20px; margin-bottom: 8px;">
                            <span style="font-size: 16px;">Overall Server Performance Score:</span><br>
                            <span id="total_score" style="font-size: 36px; font-weight: bold;">-</span> <span style="font-size: 24px;">/ 10</span>
                        </div>
                        <div style="font-size: 14px; margin-top: 5px;" id="score_message">Run the benchmark to see your score</div>
                        <div style="font-size: 12px; margin-top: 8px; opacity: 0.9;" id="score_details">
                            Tests completed: <span id="tests_completed">0</span> | Total time: <span id="avg_time">-</span>s
                        </div>
                    </td>
                </tr>
            </table>

            <!-- MySQL / MariaDB Performance Test -->
            <div class="section-header" style="margin-top: 40px;">
                <div class="section-title">
                    <span class="icon icon-database"></span>
                    MySQL / MariaDB Performance Test
                </div>
            </div>

            <div class="alert alert-info">
                <span class="icon icon-info"></span>
                <div>
                    <strong>About This Test</strong><br>
                    Test the performance of your MySQL or MariaDB database server. This benchmark will create a temporary table, test write/read throughput, run aggregation queries, and clean up after itself. No permanent changes are made to your database.
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px;">
                <!-- Left Column: Form -->
                <div style="background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px;">
                    <h3 style="margin: 0 0 20px 0; color: var(--text-primary); font-size: 18px;">
                        <span class="icon icon-database"></span> Database Connection
                    </h3>
                    <form id="db_bench_form">
                        <div style="margin-bottom: 15px;">
                            <label for="db_host" style="display: block; margin-bottom: 5px; font-weight: bold;">Host:</label>
                            <input type="text" id="db_host" name="db_host" value="localhost" required
                                style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label for="db_port" style="display: block; margin-bottom: 5px; font-weight: bold;">Port:</label>
                            <input type="number" id="db_port" name="db_port" value="3306" required min="1" max="65535"
                                style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label for="db_name" style="display: block; margin-bottom: 5px; font-weight: bold;">Database Name:</label>
                            <input type="text" id="db_name" name="db_name" required
                                style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label for="db_user" style="display: block; margin-bottom: 5px; font-weight: bold;">Username:</label>
                            <input type="text" id="db_user" name="db_user" required
                                style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                        </div>
                        <div style="margin-bottom: 20px;">
                            <label for="db_pass" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
                            <input type="password" id="db_pass" name="db_pass"
                                style="width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 14px; background: var(--surface); color: var(--text-primary);">
                        </div>
                        <button type="submit" id="btn_db_test" class="btn btn-success-custom" style="width: 100%; padding: 12px; font-size: 16px;">
                            <span class="icon icon-play"></span> Run Database Test
                        </button>
                    </form>
                </div>

                <!-- Right Column: Results -->
                <div>
                    <!-- State A: Placeholder -->
                    <div id="db_test_placeholder" style="background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 40px; text-align: center; height: 100%; display: flex; align-items: center; justify-content: center; flex-direction: column;">
                        <span class="icon icon-database" style="font-size: 64px; opacity: 0.3; margin-bottom: 20px;">🗄️</span>
                        <p style="color: var(--text-muted); font-size: 16px; margin: 0;">Results will appear here after running the test</p>
                    </div>

                    <!-- State B: Results -->
                    <div id="db_test_results" style="display: none; background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px;">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <div style="font-size: 16px; color: var(--text-muted); margin-bottom: 10px;">Database Performance Score</div>
                            <div id="db_score_display" style="font-size: 72px; font-weight: bold; color: #4CAF50;">-</div>
                            <div style="font-size: 18px; color: var(--text-muted);">out of 10</div>
                        </div>

                        <!-- Metrics Grid -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                            <!-- Connection Latency -->
                            <div style="background: rgba(59, 130, 246, 0.05); padding: 16px; border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.1);">
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; font-weight: bold;">Connection Latency</div>
                                <div id="db_res_latency" style="font-size: 28px; font-weight: bold; color: var(--text-primary);">-</div>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">Lower is better · <span style="opacity: 0.7;">🔬 5 samples averaged</span></div>
                            </div>

                            <!-- CPU Time -->
                            <div style="background: rgba(139, 92, 246, 0.05); padding: 16px; border-radius: 8px; border: 1px solid rgba(139, 92, 246, 0.1);">
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; font-weight: bold;">CPU Time</div>
                                <div id="db_res_cpu" style="font-size: 28px; font-weight: bold; color: var(--text-primary);">-</div>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">SHA2 crypto + aggregation · <span style="opacity: 0.7;">🔬 5 samples averaged</span></div>
                            </div>

                            <!-- Write IOPS -->
                            <div style="background: rgba(16, 185, 129, 0.05); padding: 16px; border-radius: 8px; border: 1px solid rgba(16, 185, 129, 0.1);">
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; font-weight: bold;">Write Throughput</div>
                                <div id="db_res_write" style="font-size: 28px; font-weight: bold; color: var(--text-primary);">-</div>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">Rows per second · <span style="opacity: 0.7;">🔬 5 samples averaged</span></div>
                            </div>

                            <!-- Read IOPS -->
                            <div style="background: rgba(245, 158, 11, 0.05); padding: 16px; border-radius: 8px; border: 1px solid rgba(245, 158, 11, 0.1);">
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 5px; text-transform: uppercase; font-weight: bold;">Read Throughput</div>
                                <div id="db_res_read" style="font-size: 28px; font-weight: bold; color: var(--text-primary);">-</div>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 5px;">Queries per second · <span style="opacity: 0.7;">🔬 5 samples averaged</span></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

                </div>
                <!-- End Benchmarks Tab -->

                <!-- PHP Configuration Tab Content -->
                <div id="tab-php-config" class="tab-content">
                    <div class="section-header">
                        <div class="section-title">
                            <span class="icon icon-php"></span>
                            PHP Configuration & Extensions
                        </div>
                    </div>

            <!-- OPcache Information -->
            <table>
                <tr><th colspan="4">🚀 OPcache Status (Critical for PHP Performance)</th></tr>
                <tr>
                    <td width="25%">Status</td>
                    <td width="25%">
                        <?php 
                        if ($opcache_info['enabled']) {
                            echo '<span class="text-green">✓ ' . htmlspecialchars($opcache_info['status']) . '</span>';
                            if ($opcache_info['jit_enabled'] ?? false) {
                                echo ' <span class="text-blue">(JIT Enabled)</span>';
                            }
                        } else {
                            echo '<span class="text-red">✗ ' . htmlspecialchars($opcache_info['status']) . '</span>';
                        }
                        ?>
                    </td>
                    <td width="25%">Hit Rate</td>
                    <td width="25%"><?php echo htmlspecialchars($opcache_info['hit_rate'] ?? 'N/A'); ?></td>
                </tr>
                <?php if ($opcache_info['enabled']): ?>
                <tr>
                    <td>Memory Used</td>
                    <td><?php echo htmlspecialchars($opcache_info['memory_used'] ?? 'N/A'); ?></td>
                    <td>Memory Free</td>
                    <td><?php echo htmlspecialchars($opcache_info['memory_free'] ?? 'N/A'); ?></td>
                </tr>
                <tr>
                    <td>Cached Scripts</td>
                    <td><?php echo number_format($opcache_info['cached_scripts'] ?? 0); ?></td>
                    <td>Cache Keys</td>
                    <td><?php echo number_format($opcache_info['cached_keys'] ?? 0); ?> / <?php echo number_format($opcache_info['max_cached_keys'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td>Cache Hits</td>
                    <td><?php echo number_format($opcache_info['hits'] ?? 0); ?></td>
                    <td>Cache Misses</td>
                    <td><?php echo number_format($opcache_info['misses'] ?? 0); ?></td>
                </tr>
                <?php if ($opcache_info['jit_enabled'] ?? false): ?>
                <tr>
                    <td>JIT Buffer Size</td>
                    <td colspan="3"><?php echo htmlspecialchars($opcache_info['jit_buffer_size'] ?? 'N/A'); ?></td>
                </tr>
                <?php endif; ?>
                <?php else: ?>
                <tr>
                    <td colspan="4" class="bg-warning-light" style="text-align: center; padding: 15px;">
                        <strong>⚠️ Warning:</strong> OPcache is not enabled. Enabling OPcache can improve PHP performance by 3-10x!
                        <br><small>Add <code>opcache.enable=1</code> to your php.ini file.</small>
                    </td>
                </tr>
                <?php endif; ?>
            </table>

            <!-- PHP Limits -->
            <table>
                <tr><th colspan="4">PHP Limits & Configuration</th></tr>
                <?php 
                $limits_array = array_chunk($php_limits, 2, true);
                foreach ($limits_array as $row): 
                ?>
                <tr>
                    <?php foreach ($row as $name => $value): ?>
                    <td width="25%"><?php echo htmlspecialchars($name); ?></td>
                    <td width="25%"><?php echo htmlspecialchars($value); ?></td>
                    <?php endforeach; ?>
                    <?php if (count($row) < 2): ?>
                    <td colspan="2"></td>
                    <?php endif; ?>
                </tr>
                <?php endforeach; ?>
            </table>

            <!-- Timezone Information -->
            <table>
                <tr><th colspan="4">Timezone Information</th></tr>
                <tr>
                    <td width="25%">Current Timezone</td>
                    <td width="25%"><?php echo htmlspecialchars($timezone_info['current']); ?></td>
                    <td width="25%">UTC Offset</td>
                    <td width="25%"><?php echo htmlspecialchars($timezone_info['offset']); ?></td>
                </tr>
                <tr>
                    <td>Timezone Abbreviation</td>
                    <td><?php echo htmlspecialchars($timezone_info['abbreviation']); ?></td>
                    <td>Daylight Saving Time</td>
                    <td><?php echo htmlspecialchars($timezone_info['dst']); ?></td>
                </tr>
            </table>

            <!-- Database Support -->
            <table>
                <tr><th colspan="2">Database Support</th></tr>
                <?php 
                $db_support = benchmark_database_support();
                foreach ($db_support as $db => $status): 
                ?>
                <tr>
                    <td width="50%"><?php echo htmlspecialchars($db); ?></td>
                    <td width="50%"><?php echo $status; ?></td>
                </tr>
                <?php endforeach; ?>
            </table>

            <!-- Important Functions -->
            <table>
                <tr><th colspan="8">Important Functions Availability</th></tr>
                <?php 
                $func_check = check_important_functions();
                foreach ($func_check as $category => $functions): 
                ?>
                <tr>
                    <td colspan="8" class="bg-section" style="font-weight: bold;"><?php echo htmlspecialchars($category); ?></td>
                </tr>
                <?php 
                $func_array = array_chunk($functions, 4, true);
                foreach ($func_array as $row): 
                ?>
                <tr>
                    <?php foreach ($row as $func => $available): ?>
                    <td width="12.5%"><?php echo htmlspecialchars($func); ?></td>
                    <td width="12.5%"><?php echo $available ? '<span class="text-green">✓</span>' : '<span class="text-red">✗</span>'; ?></td>
                    <?php endforeach; ?>
                    <?php for ($i = count($row); $i < 4; $i++): ?>
                    <td colspan="2"></td>
                    <?php endfor; ?>
                </tr>
                <?php endforeach; ?>
                <?php endforeach; ?>
            </table>

            <!-- PHP Modules -->
            <table>
                <tr><th colspan="4">PHP Extensions (<?php echo count(get_loaded_extensions()); ?>)</th></tr>
                <tr>
                    <td colspan="4" class="module-list">
                        <?php
                        $extensions_detailed = get_php_extensions_detailed();
                        $count = 0;
                        foreach ($extensions_detailed as $ext => $ver) {
                            echo htmlspecialchars($ext);
                            if ($ver !== 'loaded') echo ' (' . htmlspecialchars($ver) . ')';
                            echo '  ';
                            $count++;
                            if ($count % 10 == 0) echo '<br>';
                        }
                        ?>
                    </td>
                </tr>
            </table>

            <!-- PHP Parameters -->
            <table>
                <tr><th colspan="4">PHP Parameters</th></tr>
                <tr>
                    <td width="30%">PHP information</td>
                    <td width="20%"><a href="?act=phpinfo" target="_blank">PHPINFO</a></td>
                    <td width="30%">PHP Version</td>
                    <td width="20%"><?php echo PHP_VERSION; ?></td>
                </tr>
                <tr>
                    <td>Run PHP</td>
                    <td><?php echo strtoupper(php_sapi_name()); ?></td>
                    <td>Memory Limit</td>
                    <td><?php echo ini_get('memory_limit'); ?></td>
                </tr>
                <tr>
                    <td>POST Max Size</td>
                    <td><?php echo ini_get('post_max_size'); ?></td>
                    <td>Upload Max Filesize</td>
                    <td><?php echo ini_get('upload_max_filesize'); ?></td>
                </tr>
                <tr>
                    <td>Max Execution Time</td>
                    <td><?php echo ini_get('max_execution_time'); ?> Second</td>
                    <td>Socket TimeOut</td>
                    <td><?php echo ini_get('default_socket_timeout'); ?> Second</td>
                </tr>
                <tr>
                    <td>Display Errors</td>
                    <td><?php echo ini_get('display_errors') ? '✓' : '✗'; ?></td>
                    <td>Allow URL fopen</td>
                    <td><?php echo ini_get('allow_url_fopen') ? '✓' : '✗'; ?></td>
                </tr>
                <tr>
                    <td>Disable Functions</td>
                    <td colspan="3" style="word-break: break-all;">
                        <?php 
                        $disabled = ini_get('disable_functions');
                        echo $disabled ? htmlspecialchars($disabled) : '<span class="text-red">None</span>';
                        ?>
                    </td>
                </tr>
            </table>

                </div>
                <!-- End PHP Configuration Tab -->

                <!-- System Details Tab Content -->
                <div id="tab-system-details" class="tab-content">
                    <div class="section-header">
                        <div class="section-title">
                            <span class="icon icon-info"></span>
                            System & Server Information
                        </div>
                    </div>

            <!-- Software Versions -->
            <table>
                <tr><th colspan="4">Software Versions</th></tr>
                <?php 
                $vers_array = array_chunk($versions, 2, true);
                foreach ($vers_array as $row): 
                ?>
                <tr>
                    <?php foreach ($row as $name => $version): ?>
                    <td width="25%"><?php echo htmlspecialchars($name); ?></td>
                    <td width="25%"><?php echo htmlspecialchars($version); ?></td>
                    <?php endforeach; ?>
                    <?php if (count($row) < 2): ?>
                    <td colspan="2"></td>
                    <?php endif; ?>
                </tr>
                <?php endforeach; ?>
            </table>

            <!-- Connection Information -->
            <table>
                <tr><th colspan="4">Connection Information</th></tr>
                <?php 
                $conn_array = array_chunk($connection_info, 2, true);
                foreach ($conn_array as $row): 
                ?>
                <tr>
                    <?php foreach ($row as $name => $value): ?>
                    <td width="25%"><?php echo htmlspecialchars($name); ?></td>
                    <td width="25%" style="word-break: break-all;"><?php echo htmlspecialchars($value); ?></td>
                    <?php endforeach; ?>
                    <?php if (count($row) < 2): ?>
                    <td colspan="2"></td>
                    <?php endif; ?>
                </tr>
                <?php endforeach; ?>
            </table>

            <!-- Footer -->
            <table>
                <tr>
                    <td style="text-align: center;">
                        Hosting Benchmark v1.0.0 Dashboard | 
                        Processed in <?php echo number_format(microtime(true) - $time_start, 4); ?> seconds | 
                        <?php echo memory_usage(); ?> memory usage
                    </td>
                </tr>
            </table>

                </div>
                <!-- End System Details Tab -->

            </div>
            <!-- End Container -->

            <script>
            let currentScoringMode = 'modern';

            function updateScoringMode() {
                const selector = document.getElementById('scoring_mode');
                const desc = document.getElementById('scoring_description');
                if (selector && desc) {
                    currentScoringMode = selector.value;
                    if (currentScoringMode === 'modern') {
                        desc.innerHTML = '<strong>Modern:</strong> Reflects 2025 hosting standards with NVMe and modern CPUs';
                    } else {
                        desc.innerHTML = '<strong>Light:</strong> Legacy scoring with generous thresholds for older hardware';
                    }
                    
                    // If we have results, recalculate the total score interpretation
                    if (typeof calculateTotalScore === 'function' && typeof testCount !== 'undefined' && testCount > 0) {
                        calculateTotalScore();
                    }
                }
            }

        function switchTab(tabName) {

                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });

        document.querySelectorAll('.tab-button').forEach(btn => {
                    btn.classList.remove('active');
                });

        const selectedTab = document.getElementById('tab-' + tabName);
                if (selectedTab) {
                    selectedTab.classList.add('active');
                }

        const activeButton = document.querySelector('[data-tab="' + tabName + '"]');
                if (activeButton) {
                    activeButton.classList.add('active');
                }

        localStorage.setItem('activeTab', tabName);
            }

        function toggleDarkMode() {
                document.body.classList.toggle('dark-mode');
                const isDark = document.body.classList.contains('dark-mode');

        const icon = document.getElementById('theme-icon');
                const text = document.getElementById('theme-text');
                if (icon) {
                    icon.className = isDark ? 'icon icon-sun' : 'icon icon-moon';
                }
                if (text) {
                    text.textContent = isDark ? 'Light Mode' : 'Dark Mode';
                }

        localStorage.setItem('darkMode', isDark ? 'enabled' : 'disabled');

        if (typeof initializeCharts !== 'undefined') {
                    initializeCharts();
                }

        if (window.networkSparklineUpdate && window.networkSparklineData) {
                    window.networkSparklineUpdate(window.networkSparklineData);
                }
            }

        document.addEventListener('DOMContentLoaded', function() {

                if (localStorage.getItem('darkMode') === 'enabled') {
                    document.body.classList.add('dark-mode');
                    const icon = document.getElementById('theme-icon');
                    const text = document.getElementById('theme-text');
                    if (icon) icon.className = 'icon icon-sun';
                    if (text) text.textContent = 'Light Mode';
                }

        const savedTab = localStorage.getItem('activeTab');
                if (savedTab) {
                    switchTab(savedTab);
                }

        initializeCharts();

        function fixTooltipPositions() {
                    const benchmarkTable = document.getElementById('benchmark_results_table');
                    if (!benchmarkTable) return;

                    const rows = benchmarkTable.querySelectorAll('tr');
                    const tooltipIcons = benchmarkTable.querySelectorAll('.benchmark-info-icon');

                    if (tooltipIcons.length >= 2) {

                        const lastTwo = Array.from(tooltipIcons).slice(-2);
                        lastTwo.forEach(icon => {
                            icon.classList.add('tooltip-top');
                        });
                    }
                }

        setTimeout(fixTooltipPositions, 100);

        const observer = new MutationObserver(function(mutations) {
                    const benchmarkTable = document.getElementById('benchmark_results_table');
                    if (benchmarkTable && benchmarkTable.style.display !== 'none') {
                        fixTooltipPositions();
                    }
                });

                const benchmarkTable = document.getElementById('benchmark_results_table');
                if (benchmarkTable) {
                    observer.observe(benchmarkTable, { attributes: true, attributeFilter: ['style'] });
                }

                // Setup database benchmark form event listener
                const dbBenchForm = document.getElementById('db_bench_form');
                if (dbBenchForm) {
                    dbBenchForm.addEventListener('submit', function(e) {
                        e.preventDefault();
                        runDbBenchmark();
                    });
                }
            });

        function initializeCharts() {

                const isDark = document.body.classList.contains('dark-mode');
                const textColor = isDark ? '#f1f5f9' : '#1a2332';
                const gridColor = isDark ? 'rgba(148, 163, 184, 0.1)' : 'rgba(23, 54, 135, 0.1)';

        initCPUGauge();

        initNetworkSparkline();
            }

            function initCPUGauge() {

        }

            function initNetworkSparkline() {
                const svg = document.getElementById('networkSparkline');
                if (!svg) return;

                const line = document.getElementById('networkSparklineLine');
                const area = document.getElementById('networkSparklineArea');
                if (!line || !area) return;

                const updateChart = function() {
                    const width = svg.clientWidth || svg.getBoundingClientRect().width || 400;
                    const height = 80;
                    const padding = 5;
                    const chartWidth = width - (padding * 2);
                    const chartHeight = height - (padding * 2);

        const dataPoints = 20;
                    const data = Array.from({length: dataPoints}, () => Math.random() * 100);

        const points = data.map((value, index) => {
                        const x = padding + (index / (dataPoints - 1)) * chartWidth;
                        const y = padding + chartHeight - (value / 100) * chartHeight;
                        return `${x},${y}`;
                    });

        const areaPoints = [
                        `${padding},${height - padding}`,
                        ...points,
                        `${width - padding},${height - padding}`
                    ].join(' ');

                    line.setAttribute('points', points.join(' '));
                    area.setAttribute('points', areaPoints);

        window.networkSparklineData = data;
                    window.networkSparklineUpdate = function(newData) {
                        if (!line || !area || !svg) return;
                        const width = svg.clientWidth || svg.getBoundingClientRect().width || 400;
                        const height = 80;
                        const padding = 5;
                        const chartWidth = width - (padding * 2);
                        const chartHeight = height - (padding * 2);
                        const points = newData.map((value, index) => {
                            const x = padding + (index / (newData.length - 1)) * chartWidth;
                            const y = padding + chartHeight - (value / 100) * chartHeight;
                            return `${x},${y}`;
                        });
                        const areaPoints = [
                            `${padding},${height - padding}`,
                            ...points,
                            `${width - padding},${height - padding}`
                        ].join(' ');
                        line.setAttribute('points', points.join(' '));
                        area.setAttribute('points', areaPoints);
                    };
                };

        updateChart();

        if (window.ResizeObserver) {
                    const resizeObserver = new ResizeObserver(updateChart);
                    resizeObserver.observe(svg);
                }
            }

        /**
         * Generate and auto-download simple TXT report after benchmark completes
         */
        function downloadBenchmarkTXT() {
            // Build simple text report
            let txtReport = '========================================\n';
            txtReport += '  HOSTING BENCHMARK REPORT\n';
            txtReport += '========================================\n';
            txtReport += 'Generated: ' + new Date().toLocaleString() + '\n';
            txtReport += 'Scoring Mode: ' + (currentScoringMode === 'modern' ? 'Modern (Strict)' : 'Light (Legacy)') + '\n\n';
            
            // System info
            txtReport += '--- SYSTEM OVERVIEW ---\n';
            txtReport += 'PHP Version: <?php echo PHP_VERSION; ?>\n';
            txtReport += 'Server: <?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'N/A'); ?>\n';
            txtReport += 'OS: <?php echo PHP_OS; ?>\n\n';
            
            // Benchmark results
            const totalScore = document.getElementById('total_score')?.textContent || '-';
            const testsCompleted = document.getElementById('tests_completed')?.textContent || '0';
            const scoreMessage = document.getElementById('score_message')?.textContent || '';
            
            txtReport += '--- BENCHMARK SUMMARY ---\n';
            txtReport += 'Overall Score: ' + totalScore + ' / 10\n';
            txtReport += 'Tests Completed: ' + testsCompleted + '\n';
            txtReport += 'Rating: ' + scoreMessage + '\n\n';
            
            // Category breakdown
            const categoryMap = {
                'cpu': 'CPU & Memory Performance',
                'fs': 'Filesystem I/O Performance',
                'db': 'Database Performance',
                'cache': 'Cache Performance',
                'network': 'Network Performance'
            };
            
            const resultsByCategory = {};
            comprehensiveTests.forEach(test => {
                const resultElem = document.getElementById('result_' + test.type);
                const scoreElem = document.getElementById('score_' + test.type);
                if (resultElem && scoreElem) {
                    const result = resultElem.textContent.trim();
                    const score = scoreElem.textContent.trim();
                    if (result !== '-' && score !== '-') {
                        if (!resultsByCategory[test.cat]) {
                            resultsByCategory[test.cat] = [];
                        }
                        let unit = '';
                        if (test.type !== 'network_latency' && test.type !== 'opcache_enabled' && test.type !== 'cache_enabled' && test.type !== 'concurrency') {
                            unit = 's';
                        }
                        resultsByCategory[test.cat].push({
                            name: test.name,
                            result: result + unit,
                            score: score
                        });
                    }
                }
            });
            
            // Add each category
            Object.keys(resultsByCategory).forEach(cat => {
                txtReport += '--- ' + (categoryMap[cat] || cat).toUpperCase() + ' ---\n';
                resultsByCategory[cat].forEach(test => {
                    txtReport += test.name.padEnd(35) + ' Result: ' + test.result.padEnd(12) + ' Score: ' + test.score + '/10\n';
                });
                txtReport += '\n';
            });
            
            txtReport += '========================================\n';
            txtReport += 'End of Report\n';
            txtReport += '========================================\n';
            
            // Download TXT file
            const blob = new Blob([txtReport], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'benchmark-results-' + new Date().toISOString().slice(0,10) + '.txt';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        }

        const netPrev = <?php echo json_encode($network_info); ?>;

            function formatSpeed(bytes) {
                if (bytes < 1024) return bytes + ' B/s';
                if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB/s';
                return (bytes / 1048576).toFixed(2) + ' MB/s';
            }

            function formatSize(bytes) {
                const units = ['B', 'KB', 'MB', 'GB', 'TB'];
                let size = bytes;
                let unitIndex = 0;

                while (size >= 1024 && unitIndex < units.length - 1) {
                    size /= 1024;
                    unitIndex++;
                }

                return size.toFixed(3) + ' ' + units[unitIndex];
            }

            let updateFailureCount = 0;
            const maxConsecutiveFailures = 3;

            function updateData() {
                const updateController = new AbortController();
                const updateTimeoutId = setTimeout(() => updateController.abort(), 5000);

                fetch('?ajax=update', {
                    signal: updateController.signal
                })
                    .then(response => {
                        clearTimeout(updateTimeoutId);
                        if (!response.ok) {
                            throw new Error('Update request failed');
                        }
                        return response.json();
                    })
                    .then(data => {
                        updateFailureCount = 0; // Reset failure count on success
                        document.getElementById('current_time').textContent = data.time;
                        document.getElementById('uptime').textContent = data.uptime;

                        const cpu = data.cpu;
                        document.getElementById('cpu_usage').innerHTML = 
                            cpu.user + '%us, ' + cpu.sys + '%sy, ' + cpu.nice + '%ni, ' + 
                            cpu.idle + '%id, ' + cpu.iowait + '%wa, ' + cpu.irq + '%irq, ' + 
                            cpu.softirq + '%softirq';

                        document.getElementById('load_avg').textContent = data.load;

                        document.getElementById('disk_used').textContent = data.disk_used.toFixed(3);
                        document.getElementById('disk_free').textContent = data.disk_free.toFixed(3);
                        document.getElementById('disk_percent').textContent = data.disk_percent;
                        document.getElementById('disk_progress').style.width = data.disk_percent + '%';

                        const mem = data.memory;
                        const isGB = mem.total >= 1024;

                        document.getElementById('mem_used').textContent = isGB ? 
                            (mem.used / 1024).toFixed(3) + ' G' : mem.used.toFixed(3) + ' M';
                        document.getElementById('mem_free').textContent = isGB ? 
                            (mem.free / 1024).toFixed(3) + ' G' : mem.free.toFixed(3) + ' M';
                        document.getElementById('mem_percent').textContent = mem.percent;
                        document.getElementById('mem_progress').style.width = mem.percent + '%';

        const cachedElem = document.getElementById('mem_cached');
                        if (cachedElem && !mem.restricted) {
                            document.getElementById('mem_cached').textContent = isGB ? 
                                (mem.cached / 1024).toFixed(3) + ' G' : mem.cached.toFixed(3) + ' M';
                            document.getElementById('mem_buffers').textContent = isGB ? 
                                (mem.buffers / 1024).toFixed(3) + ' G' : mem.buffers.toFixed(3) + ' M';

                            const cachedPercent = mem.total > 0 ? ((mem.cached / mem.total) * 100).toFixed(2) : 0;
                            document.getElementById('mem_cached_percent').textContent = cachedPercent;
                            document.getElementById('mem_cached_progress').style.width = cachedPercent + '%';

                            document.getElementById('mem_real_used').textContent = isGB ? 
                                (mem.real_used / 1024).toFixed(3) + ' G' : mem.real_used.toFixed(3) + ' M';
                            document.getElementById('mem_real_free').textContent = isGB ? 
                                (mem.real_free / 1024).toFixed(3) + ' G' : mem.real_free.toFixed(3) + ' M';
                            document.getElementById('mem_real_percent').textContent = mem.real_percent;
                            document.getElementById('mem_real_progress').style.width = mem.real_percent + '%';
                        }

                        if (mem.swap_total > 0 && document.getElementById('swap_used')) {
                            document.getElementById('swap_used').textContent = isGB ? 
                                (mem.swap_used / 1024).toFixed(3) + ' G' : mem.swap_used.toFixed(3) + ' M';
                            document.getElementById('swap_free').textContent = isGB ? 
                                (mem.swap_free / 1024).toFixed(3) + ' G' : mem.swap_free.toFixed(3) + ' M';
                            document.getElementById('swap_percent').textContent = mem.swap_percent;
                            document.getElementById('swap_progress').style.width = mem.swap_percent + '%';
                        }

                        if (data.network) {
                            for (const iface in data.network) {
                                const current = data.network[iface];
                                const prev = netPrev[iface] || {rx: 0, tx: 0};

                                const rxSpeed = Math.max(0, current.rx - prev.rx);
                                const txSpeed = Math.max(0, current.tx - prev.tx);

                                const inElem = document.getElementById('net_in_' + iface);
                                const outElem = document.getElementById('net_out_' + iface);
                                const inSpeedElem = document.getElementById('net_in_speed_' + iface);
                                const outSpeedElem = document.getElementById('net_out_speed_' + iface);

                                if (inElem) inElem.textContent = formatSize(current.rx);
                                if (outElem) outElem.textContent = formatSize(current.tx);
                                if (inSpeedElem) inSpeedElem.textContent = formatSpeed(rxSpeed);
                                if (outSpeedElem) outSpeedElem.textContent = formatSpeed(txSpeed);

                                netPrev[iface] = current;
                            }
                        }
                    })
                    .catch(err => {
                        clearTimeout(updateTimeoutId);
                        updateFailureCount++;
                        // Only log to console after multiple consecutive failures to reduce spam
                        if (updateFailureCount <= maxConsecutiveFailures) {
                            console.warn('Update failed (attempt ' + updateFailureCount + '):', err.message || err);
                        }
                    });
            }

            setInterval(updateData, 1000);

        function setPingTarget(target, port) {
                document.getElementById('ping_target').value = target;
                const portSelect = document.getElementById('ping_port');
                const portValue = String(port);

        let found = false;
                for (let i = 0; i < portSelect.options.length; i++) {
                    if (portSelect.options[i].value === portValue) {
                        portSelect.value = portValue;
                        found = true;
                        break;
                    }
                }

        if (!found && portSelect.options.length > 0) {
                    portSelect.value = portSelect.options[0].value;
                }
            }

            function runPingTest() {
                const target = document.getElementById('ping_target').value.trim();
                const portSelect = document.getElementById('ping_port');
                const port = portSelect.value;
                const count = document.getElementById('ping_count').value;
                const btn = document.getElementById('ping_btn');
                const resultsDiv = document.getElementById('ping_results');
                const packetsDiv = document.getElementById('ping_packets');

                if (!target) {
                    alert('Please enter a target IP or hostname');
                    return;
                }

        resultsDiv.style.display = 'block';
                packetsDiv.innerHTML = '<div style="color: #5bc0de;">Running ping test...</div>';

                document.getElementById('ping_results_target').textContent = target;
                document.getElementById('ping_results_port').textContent = port;
                document.getElementById('ping_sent').textContent = '-';
                document.getElementById('ping_received').textContent = '-';
                document.getElementById('ping_lost').textContent = '-';
                document.getElementById('ping_loss').textContent = '-';
                document.getElementById('ping_stats_rtt').style.display = 'none';

                btn.disabled = true;
                btn.textContent = 'Testing...';

                fetch('?act=ping&target=' + encodeURIComponent(target) + '&port=' + encodeURIComponent(port) + '&count=' + encodeURIComponent(count))
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }
                        return response.json();
                    })
                    .then(data => {
                        btn.disabled = false;
                        btn.textContent = '🎯 Run Test';

                        if (data.error) {
                            packetsDiv.innerHTML = '<div style="color: #d9534f;">Error: ' + data.error + '</div>';
                            return;
                        }

        let html = '';
                        data.results.forEach(result => {
                            if (result.success) {
                                html += '<div style="color: #5cb85c;">Reply from ' + target + ':' + port + 
                                        ' seq=' + result.seq + ' time=' + result.time + 'ms</div>';
                            } else {
                                html += '<div style="color: #d9534f;">Request timeout seq=' + result.seq + 
                                        ' (' + result.error + ')</div>';
                            }
                        });
                        packetsDiv.innerHTML = html;

        const summary = data.summary;
                        document.getElementById('ping_sent').textContent = summary.sent;
                        document.getElementById('ping_received').textContent = summary.received;
                        document.getElementById('ping_lost').textContent = summary.lost;
                        document.getElementById('ping_loss').textContent = summary.loss_percent;

                        if (summary.min !== undefined) {
                            document.getElementById('ping_min').textContent = summary.min;
                            document.getElementById('ping_max').textContent = summary.max;
                            document.getElementById('ping_avg').textContent = summary.avg;
                            document.getElementById('ping_stats_rtt').style.display = 'inline';
                        }
                    })
                    .catch(err => {
                        btn.disabled = false;
                        btn.textContent = '🎯 Run Test';
                        packetsDiv.innerHTML = '<div style="color: #d9534f;">Error: ' + err.message + '</div>';
                        console.error('Ping test failed:', err);
                    });
            }

        const benchmarkDescriptions = {
                'cpu_int': {
                    title: 'Integer Operations',
                    description: 'Performs 20 million integer arithmetic operations (addition, subtraction, multiplication) to measure raw CPU computational speed.',
                    realworld: 'Reflects performance in applications that do heavy number crunching, calculations, loops, and data processing. Important for e-commerce price calculations, analytics, and mathematical operations.'
                },
                'cpu_float': {
                    title: 'Float Operations',
                    description: 'Executes 10 million floating-point operations including square roots, powers, logarithms, and trigonometric functions (sin, cos).',
                    realworld: 'Critical for scientific computing, graphics rendering, financial calculations, game engines, and any application requiring precise decimal math. Affects performance of image processing, 3D rendering, and statistical analysis.'
                },
                'cpu_text': {
                    title: 'Large Text Processing',
                    description: 'Processes large text blocks (2000 sentences) with 50K operations including case conversion, string length, search, replace, and HTML encoding.',
                    realworld: 'Measures how well your server handles content management, text parsing, search functionality, and string manipulation. Important for CMS platforms, blog systems, and applications that process user-generated content.'
                },
                'cpu_binary': {
                    title: 'Binary Operations',
                    description: 'Performs 2 million bitwise operations (AND, OR, XOR, bit shifts) and modulo operations to test low-level CPU performance.',
                    realworld: 'Essential for encryption, hashing, compression algorithms, and binary data processing. Affects security operations, data encoding/decoding, and performance of cryptographic functions.'
                },
                'string': {
                    title: 'String Manipulation',
                    description: 'Executes 500K string operations including case conversion, substring extraction, search, replace, and trimming operations.',
                    realworld: 'Directly impacts form validation, data sanitization, URL processing, and text transformation. Critical for web applications that process user input, generate dynamic content, or manipulate text data.'
                },
                'array': {
                    title: 'Array Operations',
                    description: 'Performs 200K array operations including reversing, summing, filtering, mapping, merging, and sorting on arrays of 500 elements.',
                    realworld: 'Measures performance of data manipulation, list processing, and collection operations. Important for applications that work with datasets, process lists, filter/search data, or perform data transformations.'
                },
                'hash': {
                    title: 'Hash Functions',
                    description: 'Executes 200K hashing operations using MD5, SHA1, SHA256, SHA512, and CRC32 algorithms on varying data.',
                    realworld: 'Critical for password security, data integrity checks, cache keys, and unique identifiers. Affects authentication performance, file verification, and any system using cryptographic hashing.'
                },
                'json': {
                    title: 'JSON Processing',
                    description: 'Performs 200K JSON encode/decode operations on complex nested data structures with arrays, objects, and metadata.',
                    realworld: 'Essential for API performance, data serialization, and modern web applications. Directly impacts REST API response times, AJAX operations, configuration file parsing, and data exchange between services.'
                },
                'io': {
                    title: 'File I/O Operations',
                    description: 'Performs 10K sequential file read operations (1KB chunks) with file pointer rewinding to test disk read performance.',
                    realworld: 'Measures how quickly your server can read files from disk. Critical for applications that load templates, read configuration files, serve static assets, or process log files. Affects page load times and file-serving performance.'
                },
                'fs_write': {
                    title: 'Sequential Write',
                    description: 'Writes 5K sequential file operations (10KB each) to test disk write throughput and I/O performance.',
                    realworld: 'Important for applications that generate files, write logs, create cache files, or save user uploads. Affects performance of content management systems, logging systems, and file-based caching.'
                },
                'fs_copy': {
                    title: 'File Copy & Access',
                    description: 'Performs 2K file copy operations followed by content verification to test file system copy performance and data integrity.',
                    realworld: 'Measures backup performance, file migration speed, and file duplication operations. Important for content replication, backup systems, and applications that need to duplicate or move files.'
                },
                'fs_small': {
                    title: 'Small File I/O',
                    description: 'Executes 8K small file write/read cycles (simulating session files and cache entries) with JSON encoding/decoding.',
                    realworld: 'Simulates real-world scenarios like session file handling, cache file operations, and log entry writes. Critical for applications with high session activity, file-based caching, and frequent small file operations.'
                },
                'db_import': {
                    title: 'Database Insert',
                    description: 'Performs bulk insert of 1K records into SQLite database with indexes to test database write performance.',
                    realworld: 'Measures how quickly your server can insert data into databases. Critical for applications that import data, log events, store user-generated content, or perform batch operations. Affects data ingestion performance.'
                },
                'db_simple': {
                    title: 'Simple Queries',
                    description: 'Executes 500 simple SELECT queries with WHERE clauses to test basic database read performance.',
                    realworld: 'Essential for any application that queries databases. Affects page load times, search functionality, and data retrieval. Critical for content management systems, e-commerce platforms, and any data-driven application.'
                },
                'db_complex': {
                    title: 'Complex Queries',
                    description: 'Performs 200 complex queries with GROUP BY, ORDER BY, JOINs, and aggregations to test query optimization capabilities.',
                    realworld: 'Measures performance of advanced database operations like reporting, analytics, data aggregation, and complex searches. Important for dashboards, reporting systems, and applications with sophisticated data queries.'
                },
                'opcache_enabled': {
                    title: 'OPcache Status',
                    description: 'Checks if OPcache (PHP bytecode cache) is enabled on the server.',
                    realworld: 'OPcache can improve PHP performance by 3-10x by caching compiled bytecode. Essential for production environments. Without OPcache, PHP recompiles scripts on every request, wasting CPU cycles.'
                },
                'opcache_performance': {
                    title: 'OPcache Performance',
                    description: 'Tests OPcache effectiveness by including a PHP file 1000 times and measuring execution speed.',
                    realworld: 'Measures how well OPcache accelerates PHP execution. Faster times indicate better caching and improved application response times. Critical for high-traffic websites.'
                },
                'cache_enabled': {
                    title: 'Object Cache Availability',
                    description: 'Checks if Redis or Memcached object caching extensions are available and working on the server.',
                    realworld: 'Indicates whether your server supports high-performance object caching systems. Object caching dramatically improves application performance by reducing database load and speeding up data retrieval.'
                },
                'cache_write': {
                    title: 'Cache Write',
                    description: 'Performs 5K cache write operations with data serialization to test cache write performance.',
                    realworld: 'Measures how quickly your server can store data in cache. Critical for applications that cache database queries, API responses, or computed results. Affects cache warming and data storage performance.'
                },
                'cache_read': {
                    title: 'Cache Read',
                    description: 'Performs 5K cache read operations with data unserialization from random cache keys to test cache retrieval speed.',
                    realworld: 'Measures cache hit performance. Essential for reducing database load and improving response times. Critical for high-traffic applications, API caching, and systems that rely heavily on cached data.'
                },
                'cache_mixed': {
                    title: 'Mixed Cache Operations',
                    description: 'Simulates realistic cache usage with 3K operations using a 70% read / 30% write ratio to test mixed workload performance.',
                    realworld: 'Represents real-world cache usage patterns. Most applications read from cache more often than they write. This test reflects actual performance in production environments with typical cache access patterns.'
                },
                'network': {
                    title: 'Internet & DNS Speed',
                    description: 'Tests DNS resolution speed, TCP connection latency to multiple servers, and downloads a 100KB test file to measure overall network performance.',
                    realworld: 'Measures your server\'s ability to communicate with external services. Critical for applications that call APIs, fetch external data, integrate with third-party services, or perform webhooks. Affects API response times and external service integration performance.'
                },
                'network_latency': {
                    title: 'Network Latency',
                    description: 'Measures average network latency by testing DNS resolution times and HTTP connection establishment times to multiple reliable servers.',
                    realworld: 'Indicates how quickly your server can establish connections to external services. Lower latency means faster API calls, quicker external data fetching, and better performance for applications that depend on network communication.'
                },
                'concurrency': {
                    title: 'Concurrency Stress Test',
                    description: 'Tests server concurrency by making 15 parallel AJAX requests simultaneously. Each request performs CPU work and disk I/O to simulate real load.',
                    realworld: 'Measures how well your web server (Nginx/Apache) and PHP-FPM handle multiple simultaneous connections. Critical for high-traffic applications. Good concurrency handling means faster response times under load, while poor handling leads to request queuing and timeouts.'
                }
            };

        const testWeights = {

                'cpu_int': 1, 'cpu_float': 2, 'cpu_text': 2, 'cpu_binary': 1,
                'string': 2, 'array': 2, 'hash': 2, 'json': 2,

                'io': 2, 'fs_write': 3, 'fs_copy': 2, 'fs_small': 3,

                'db_import': 2, 'db_simple': 3, 'db_complex': 4, 

                'opcache_enabled': 3, 'opcache_performance': 3, 
                'cache_enabled': 1, 'cache_write': 1, 'cache_read': 1, 'cache_mixed': 1,

                'network': 2, 'network_latency': 1, 'concurrency': 4
            };

            const comprehensiveTests = [

                { cat: 'cpu', type: 'cpu_int', name: 'Integer Operations', baseline: 0.15 },
                { cat: 'cpu', type: 'cpu_float', name: 'Float Operations', baseline: 0.20 },
                { cat: 'cpu', type: 'cpu_text', name: 'Text Processing', baseline: 0.1 },
                { cat: 'cpu', type: 'cpu_binary', name: 'Binary Operations', baseline: 0.15 },
                { cat: 'cpu', type: 'string', name: 'String Manipulation', baseline: 0.08 },
                { cat: 'cpu', type: 'array', name: 'Array Operations', baseline: 0.5 },
                { cat: 'cpu', type: 'hash', name: 'Hash Functions', baseline: 0.12 },
                { cat: 'cpu', type: 'json', name: 'JSON Processing', baseline: 0.08 },

                { cat: 'fs', type: 'io', name: 'File I/O', baseline: 0.5 },
                { cat: 'fs', type: 'fs_write', name: 'Sequential Write', baseline: 0.05 },
                { cat: 'fs', type: 'fs_copy', name: 'File Copy', baseline: 0.08 },
                { cat: 'fs', type: 'fs_small', name: 'Small File I/O', baseline: 1.0 },

                { cat: 'db', type: 'db_import', name: 'Database Insert', baseline: 0.15 },
                { cat: 'db', type: 'db_simple', name: 'Simple Queries', baseline: 0.05 },
                { cat: 'db', type: 'db_complex', name: 'Complex Queries', baseline: 0.1 },

                { cat: 'cache', type: 'opcache_enabled', name: 'OPcache Check', baseline: 0 },
                { cat: 'cache', type: 'opcache_performance', name: 'OPcache Performance', baseline: 0.5 },
                { cat: 'cache', type: 'cache_enabled', name: 'Object Cache Check', baseline: 0 },
                { cat: 'cache', type: 'cache_write', name: 'Object Cache Write', baseline: 0.02 },
                { cat: 'cache', type: 'cache_read', name: 'Object Cache Read', baseline: 0.015 },
                { cat: 'cache', type: 'cache_mixed', name: 'Object Cache Mixed', baseline: 0.02 },

                { cat: 'network', type: 'network', name: 'Internet & DNS Speed', baseline: 0.5 },
                { cat: 'network', type: 'network_latency', name: 'Network Latency', baseline: 0.05 },
                { cat: 'network', type: 'concurrency', name: 'Concurrency Stress Test', baseline: 0.5 }
            ];

            let currentTestIndex = 0;
            let totalWeightedScore = 0;
            let totalWeight = 0;
            let totalScore = 0;
            let testCount = 0;
            let totalTime = 0;
            let timeBasedTestCount = 0; 
            let benchmarkStopped = false;
            let categoryScores = { cpu: 0, fs: 0, db: 0, cache: 0, network: 0 };
            let categoryCounts = { cpu: 0, fs: 0, db: 0, cache: 0, network: 0 };

        function getBenchmarkInfoIcon(testType) {
                const desc = benchmarkDescriptions[testType];
                if (!desc) return '';

                return '<span class="benchmark-info-icon" title="' + desc.title + '">ℹ' +
                    '<span class="benchmark-tooltip">' +
                    '<div class="benchmark-tooltip-title">' + desc.title + '</div>' +
                    '<div class="benchmark-tooltip-content">' + desc.description + '</div>' +
                    '<div class="benchmark-tooltip-realworld"><strong>Real-world impact:</strong> ' + desc.realworld + '</div>' +
                    '</span></span>';
            }

            function getScoreClass(score) {
                if (score < 2) return 'score-0-2';
                if (score < 5) return 'score-2-5';
                if (score < 6) return 'score-5-6';
                if (score < 7) return 'score-6-7';
                if (score < 8) return 'score-7-8';
                if (score < 9) return 'score-8-9';
                return 'score-9-10';
            }

            function updateCategoryProgress(category) {
                const catTests = comprehensiveTests.filter(t => t.cat === category);
                if (catTests.length > 0) {
                    const percent = (categoryCounts[category] / catTests.length) * 100;
                    const elem = document.getElementById('cat_' + category + '_progress');
                    if (elem) elem.style.width = percent + '%';
                }
            }

            function updateOverallProgress() {
                const percent = Math.round((currentTestIndex / comprehensiveTests.length) * 100);
                const percentElem = document.getElementById('overall_percent');
                const barElem = document.getElementById('overall_progress_bar');
                if (percentElem) percentElem.textContent = percent;
                if (barElem) {
                    barElem.style.width = percent + '%';
                    barElem.textContent = percent + '%';
                }
            }

            function updateScoreDisplay(type, result, score) {
                const resultElem = document.getElementById('result_' + type);
                const scoreElem = document.getElementById('score_' + type);

                if (resultElem) {
                    if (type === 'opcache_enabled') {
                        resultElem.textContent = result ? 'Enabled' : 'Disabled';
                    } else if (type === 'cache_enabled') {

                        if (result === 'redis') {
                            resultElem.textContent = 'Redis';
                        } else if (result === 'memcached') {
                            resultElem.textContent = 'Memcached';
                        } else {
                            resultElem.textContent = 'None';
                        }
                    } else if (type === 'network_latency') {

                        resultElem.textContent = result > 0 ? result.toFixed(2) + 'ms' : 'N/A';
                    } else if (type === 'concurrency') {
                        // For concurrency test, result is already formatted as a string
                        resultElem.textContent = result;
                    } else {
                        resultElem.textContent = result;
                    }
                }

                if (scoreElem) {
                    scoreElem.textContent = score.toFixed(1);
                    scoreElem.className = 'score-badge ' + getScoreClass(score);
                }
            }

            function calculateTotalScore() {
                if (testCount === 0 || totalWeight === 0) {
                    const totalScoreElem = document.getElementById('total_score');
                    if (totalScoreElem) totalScoreElem.textContent = '0.0';
                    const messageElem = document.getElementById('score_message');
                    if (messageElem) messageElem.textContent = 'No tests completed';
                    return;
                }

        const avgScore = totalWeightedScore / totalWeight;

                const totalTimeVal = totalTime;

                const totalScoreElem = document.getElementById('total_score');
                if (totalScoreElem) totalScoreElem.textContent = avgScore.toFixed(1);

        const testsCompletedElem = document.getElementById('tests_completed');
                if (testsCompletedElem) testsCompletedElem.textContent = testCount;

                const avgTimeElem = document.getElementById('avg_time');
                if (avgTimeElem) {
                    if (timeBasedTestCount === 0) {
                        avgTimeElem.textContent = '-';
                    } else {
                        avgTimeElem.textContent = totalTimeVal.toFixed(3);
                    }
                }

                let message = '';
                if (currentScoringMode === 'modern') {
                    // Stricter interpretation for modern scoring
                    if (avgScore >= 9) message = '🏆 Excellent! Enterprise-grade hosting';
                    else if (avgScore >= 7) message = '✨ Very Good! Premium VPS/Cloud level';
                    else if (avgScore >= 5) message = '👍 Good - Budget VPS or premium shared';
                    else if (avgScore >= 3) message = '⚠️ Average - Typical shared hosting';
                    else message = '❌ Poor - Consider upgrading immediately';
                } else {
                    // Original messages for light scoring
                    if (avgScore >= 9) message = '🏆 Excellent! Top-tier hosting performance';
                    else if (avgScore >= 7) message = '✨ Very Good! Great hosting performance';
                    else if (avgScore >= 5) message = '👍 Good - Decent hosting performance';
                    else if (avgScore >= 3) message = '⚠️ Average - Consider upgrading';
                    else message = '❌ Poor - Significant performance issues';
                }

                const messageElem = document.getElementById('score_message');
                if (messageElem) messageElem.textContent = message;

        const totalContainer = totalScoreElem ? totalScoreElem.parentElement.parentElement : null;
                if (totalContainer) {
                    if (avgScore >= 9) {
                        totalContainer.style.background = '#1e40ad'; 
                    } else if (avgScore >= 7) {
                        totalContainer.style.background = '#4564e4'; 
                    } else if (avgScore >= 5) {
                        totalContainer.style.background = '#7685e4'; 
                    } else {
                        totalContainer.style.background = '#9ba4e6'; 
                    }
                }
            }

            function stopBenchmark() {
                benchmarkStopped = true;
                const btn = document.getElementById('comp_bench_btn');
                const stopBtn = document.getElementById('stop_bench_btn');

                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '🚀 Run Benchmark';
                }
                if (stopBtn) {
                    stopBtn.style.display = 'none';
                }

        if (testCount > 0) {
                    calculateTotalScore();
                }

                const currentTestNameElem = document.getElementById('current_test_name');
                if (currentTestNameElem) {
                    currentTestNameElem.textContent = ' (Stopped by user)';
                }
            }

            function exportResults() {
                const results = {
                    timestamp: new Date().toISOString(),
                    server: {
                        hostname: document.body.textContent.match(/Server Hostname.*?([^\s]+)/)?.[1] || 'unknown',
                        php_version: '<?php echo PHP_VERSION; ?>',
                        os: '<?php echo PHP_OS; ?>'
                    },
                    score: {
                        overall_weighted: totalWeight > 0 ? (totalWeightedScore / totalWeight).toFixed(2) : '0.00',
                        overall_unweighted: testCount > 0 ? (totalScore / testCount).toFixed(2) : '0.00',
                        total_tests: testCount,
                        total_time: totalTime.toFixed(3),
                        scoring_method: 'weighted'
                    },
                    categories: {},
                    tests: []
                };

        for (const cat in categoryScores) {
                    if (categoryCounts[cat] > 0) {
                        results.categories[cat] = {
                            score: (categoryScores[cat] / categoryCounts[cat]).toFixed(2),
                            tests: categoryCounts[cat]
                        };
                    }
                }

        comprehensiveTests.forEach((test, idx) => {
                    if (idx < currentTestIndex) {
                        const resultElem = document.getElementById('result_' + test.type);
                        const scoreElem = document.getElementById('score_' + test.type);
                        if (resultElem && scoreElem) {
                            results.tests.push({
                                name: test.name,
                                category: test.cat,
                                time: resultElem.textContent,
                                score: scoreElem.textContent
                            });
                        }
                    }
                });

        const dataStr = JSON.stringify(results, null, 2);
                const dataBlob = new Blob([dataStr], {type: 'application/json'});
                const url = URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'server-benchmark-' + Date.now() + '.json';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
            }

            function runDbBenchmark() {
                const form = document.getElementById('db_bench_form');
                const btn = document.getElementById('btn_db_test');
                const placeholder = document.getElementById('db_test_placeholder');
                const resultsDiv = document.getElementById('db_test_results');
                
                // Store original button text
                const originalBtnText = btn.innerHTML;
                
                // Disable button and show loading state
                btn.disabled = true;
                btn.innerHTML = '<span class="loading"></span> Testing...';
                
                // Hide results, show placeholder
                if (resultsDiv) resultsDiv.style.display = 'none';
                if (placeholder) placeholder.style.display = 'flex';
                
                // Create FormData from form
                const formData = new FormData(form);
                
                // Send request
                fetch('?act=db_custom_bench', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Hide placeholder, show results
                        if (placeholder) placeholder.style.display = 'none';
                        if (resultsDiv) resultsDiv.style.display = 'block';
                        
                        // Update score
                        const scoreDisplay = document.getElementById('db_score_display');
                        if (scoreDisplay) {
                            scoreDisplay.textContent = data.score.toFixed(2);
                            // Color based on score
                            if (data.score >= 8) scoreDisplay.style.color = '#4CAF50';
                            else if (data.score >= 6) scoreDisplay.style.color = '#8BC34A';
                            else if (data.score >= 4) scoreDisplay.style.color = '#FFC107';
                            else scoreDisplay.style.color = '#F44336';
                        }
                        
                        // Update metrics
                        const metrics = data.metrics;
                        
                        // Connection Latency
                        const latencyElem = document.getElementById('db_res_latency');
                        if (latencyElem && metrics.connection_latency !== undefined) {
                            latencyElem.textContent = metrics.connection_latency.toFixed(2) + ' ms';
                            if (metrics.connection_latency < 2) {
                                latencyElem.style.color = '#4CAF50';  // Lightning fast
                            } else if (metrics.connection_latency < 5) {
                                latencyElem.style.color = '#8BC34A';  // Fast localhost
                            } else if (metrics.connection_latency < 10) {
                                latencyElem.style.color = '#FFC107';  // OK
                            } else {
                                latencyElem.style.color = '#F44336';  // Slow
                            }
                        }
                        
                        // CPU Time
                        const cpuElem = document.getElementById('db_res_cpu');
                        if (cpuElem && metrics.cpu_time !== undefined) {
                            cpuElem.textContent = metrics.cpu_time.toFixed(2) + ' ms';
                            if (metrics.cpu_time < 200) {
                                cpuElem.style.color = '#4CAF50';  // Elite
                            } else if (metrics.cpu_time < 500) {
                                cpuElem.style.color = '#8BC34A';  // Very good
                            } else if (metrics.cpu_time < 800) {
                                cpuElem.style.color = '#FFC107';  // Good
                            } else {
                                cpuElem.style.color = '#F44336';  // Slow
                            }
                        }
                        
                        // Write Throughput
                        const writeElem = document.getElementById('db_res_write');
                        if (writeElem && metrics.write_throughput !== undefined) {
                            writeElem.textContent = metrics.write_throughput.toFixed(2) + ' rows/s';
                            if (metrics.write_throughput > 10000) {
                                writeElem.style.color = '#4CAF50';  // NVMe beast
                            } else if (metrics.write_throughput > 7500) {
                                writeElem.style.color = '#8BC34A';  // Fast SSD
                            } else if (metrics.write_throughput > 5000) {
                                writeElem.style.color = '#FFC107';  // Good SSD
                            } else {
                                writeElem.style.color = '#F44336';  // Slow
                            }
                        }
                        
                        // Read Throughput
                        const readElem = document.getElementById('db_res_read');
                        if (readElem && metrics.read_throughput !== undefined) {
                            readElem.textContent = metrics.read_throughput.toFixed(2) + ' q/s';
                            if (metrics.read_throughput > 8000) {
                                readElem.style.color = '#4CAF50';  // Elite
                            } else if (metrics.read_throughput > 6000) {
                                readElem.style.color = '#8BC34A';  // Excellent
                            } else if (metrics.read_throughput > 4000) {
                                readElem.style.color = '#FFC107';  // Very good
                            } else {
                                readElem.style.color = '#F44336';  // Slow
                            }
                        }
                    } else {
                        // Show error
                        alert('Database Benchmark Error: ' + (data.error || 'Unknown error occurred'));
                    }
                })
                .catch(error => {
                    console.error('Database benchmark error:', error);
                    alert('Error: ' + error.message);
                })
                .finally(() => {
                    // Re-enable button and restore text
                    btn.disabled = false;
                    btn.innerHTML = originalBtnText;
                });
            }

            function runComprehensiveBenchmark() {
                const btn = document.getElementById('comp_bench_btn');
                const stopBtn = document.getElementById('stop_bench_btn');
                const downloadBtn = document.getElementById('download_txt_btn');

                if (btn) {
                    btn.disabled = true;
                    btn.textContent = 'Running Comprehensive Benchmark...';
                }
                if (stopBtn) {
                    stopBtn.style.display = 'inline-block';
                }
                if (downloadBtn) {
                    downloadBtn.style.display = 'none';
                }

        const progressElem = document.getElementById('overall_progress');
                const resultsTable = document.getElementById('benchmark_results_table');
                if (progressElem) progressElem.style.display = 'block';
                if (resultsTable) resultsTable.style.display = 'table';

        currentTestIndex = 0;
                totalWeightedScore = 0;
                totalWeight = 0;
                totalScore = 0;
                testCount = 0;
                totalTime = 0;
                timeBasedTestCount = 0;
                benchmarkStopped = false;
                categoryScores = { cpu: 0, fs: 0, db: 0, cache: 0, network: 0 };
                categoryCounts = { cpu: 0, fs: 0, db: 0, cache: 0, network: 0 };

        ['cpu', 'fs', 'db', 'cache', 'network'].forEach(cat => {
                    const elem = document.getElementById('cat_' + cat + '_progress');
                    if (elem) elem.style.width = '0%';
                });

        const testsCompletedElem = document.getElementById('tests_completed');
                if (testsCompletedElem) testsCompletedElem.textContent = '0';
                const avgTimeElem = document.getElementById('avg_time');
                if (avgTimeElem) avgTimeElem.textContent = '-';

                runNextComprehensiveTest();
            }

        /**
         * Run concurrency stress test
         * Now triggers a server-side concurrency test using curl_multi for consistent results
         */
        function runConcurrencyTest(test) {
            const startTime = performance.now();
            
            // Single request to the manager, which handles the parallel load internally
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 60000); // Longer timeout for batch test

            fetch('?act=benchmark&type=concurrency&scoring=' + currentScoringMode, {
                signal: controller.signal
            })
            .then(response => {
                clearTimeout(timeoutId);
                if (!response.ok) throw new Error('Network response was not ok');
                return response.json();
            })
            .then(data => {
                if (benchmarkStopped) return;

                if (data.error) {
                    console.warn('Concurrency test failed:', data.error);
                    updateScoreDisplay(test.type, 0, 0);
                } else {
                    // The server returns the average time per request (or total batch time depending on implementation)
                    // Our PHP implementation returns the Total Batch Time for 15 requests.
                    const resultValue = parseFloat(data.result);
                    const score = data.score;
                    
                    // Display: show the result
                    // If result is Total Batch Time, we can estimate RPS
                    const rps = resultValue > 0 ? (15 / resultValue).toFixed(1) : 0;
                    const displayResult = resultValue.toFixed(4) + 's batch (' + rps + ' req/s)';
                    
                    updateScoreDisplay(test.type, displayResult, score);

                    // Update totals
                    const weight = testWeights[test.type] || 1;
                    totalWeightedScore += score * weight;
                    totalWeight += weight;
                    totalScore += score;
                    testCount++;
                    totalTime += resultValue; // Use the batch time for total time
                    timeBasedTestCount++;

                    categoryScores[test.cat] += score;
                    categoryCounts[test.cat]++;
                }

                updateCategoryProgress(test.cat);
                currentTestIndex++;

                // Continue with next test
                setTimeout(runNextComprehensiveTest, 100);
            });
        }

        /**
         * Client-side score calculation (mirrors PHP calculate_score function)
         */
        function calculate_score_js(time, excellent, good, average, poor) {
            if (time <= 0) return 0;
            
            const aggressive = (currentScoringMode === 'modern');
            
            if (aggressive) {
                // Modern 2025 scoring curve - stricter
                if (time <= excellent) {
                    const ratio = time / excellent;
                    return 10 - (ratio * 1.0);  // 10 to 9
                } else if (time <= good) {
                    const ratio = (time - excellent) / (good - excellent);
                    return 9 - (ratio * 2);  // 9 to 7
                } else if (time <= average) {
                    const ratio = (time - good) / (average - good);
                    return 7 - (ratio * 3);  // 7 to 4
                } else if (time <= poor) {
                    const ratio = (time - average) / (poor - average);
                    return 4 - (ratio * 3);  // 4 to 1
                } else {
                    return Math.max(0, 1 - ((time - poor) / poor));  // 1 to 0
                }
            } else {
                // Legacy scoring curve - more generous
                if (time <= excellent) {
                    const ratio = time / excellent;
                    return Math.min(10, 9 + (1 - ratio));
                } else if (time <= good) {
                    const ratio = (time - excellent) / (good - excellent);
                    return 9 - (ratio * 2);
                } else if (time <= average) {
                    const ratio = (time - good) / (average - good);
                    return 7 - (ratio * 2);
                } else if (time <= poor) {
                    const ratio = (time - average) / (poor - average);
                    return 5 - (ratio * 3);
                } else {
                    const ratio = Math.min((time - poor) / poor, 1);
                    return Math.max(0, 2 - (ratio * 2));
                }
            }
        }

        function runNextComprehensiveTest() {
            if (benchmarkStopped) {
                return;
            }

            if (currentTestIndex >= comprehensiveTests.length) {
                // All tests completed
                calculateTotalScore();
                const btn = document.getElementById('comp_bench_btn');
                const stopBtn = document.getElementById('stop_bench_btn');
                const downloadBtn = document.getElementById('download_txt_btn');

                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '🚀 Run Complete Benchmark';
                }
                if (stopBtn) {
                    stopBtn.style.display = 'none';
                }
                if (downloadBtn) {
                    downloadBtn.style.display = 'inline-block';
                }

                const currentTestNameElem = document.getElementById('current_test_name');
                if (currentTestNameElem) {
                    currentTestNameElem.textContent = ' (Completed!)';
                }
                updateOverallProgress();
                return;
            }

            const test = comprehensiveTests[currentTestIndex];

            const currentTestNameElem = document.getElementById('current_test_name');
            if (currentTestNameElem) {
                currentTestNameElem.textContent = ' - Running: ' + test.name;
            }

            updateOverallProgress();

            // Special handling for concurrency test
            if (test.type === 'concurrency') {
                runConcurrencyTest(test);
                return;
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); 

            fetch('?act=benchmark&type=' + encodeURIComponent(test.type) + '&scoring=' + currentScoringMode, {
                signal: controller.signal
            })
            .then(response => {
                clearTimeout(timeoutId);
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (benchmarkStopped) {
                    return;
                }

                if (data.error) {
                    console.warn('Test ' + test.type + ' failed:', data.error);
                    updateScoreDisplay(test.type, 0, 0);
                } else {
                    let score = data.score || 0;
                    let resultValue = data.result;

                    // Handle Unsupported Features:
                    // If result is 0 for DB, Image, or Cache tests, it means the extension is missing.
                    // We should NOT count this towards the total score.
                    const isUnsupported = (resultValue === 0 || resultValue === '0' || resultValue === 'None') && 
                                         (test.cat === 'db' || test.type === 'image' || 
                                          test.type === 'cache_enabled' || test.type === 'cache_write' || 
                                          test.type === 'cache_read' || test.type === 'cache_mixed');

                    if (isUnsupported) {
                        // Update display to show N/A
                        const resultElem = document.getElementById('result_' + test.type);
                        const scoreElem = document.getElementById('score_' + test.type);
                        if (resultElem) resultElem.innerHTML = '<span style="color:gray; font-size:0.9em">Not Supported</span>';
                        if (scoreElem) {
                            scoreElem.textContent = 'N/A';
                            scoreElem.className = 'score-badge';
                            scoreElem.style.background = '#cbd5e1';
                            scoreElem.style.color = '#64748b';
                        }
                        // Do not add to totalWeightedScore or totalWeight
                    } else {
                        // Normal scoring logic
                        if (score === 0 && resultValue > 0 && test.baseline > 0) {
                            const ratio = test.baseline / resultValue;
                            score = Math.min(10, Math.max(0, ratio * 10));
                        }

                        let displayResult = resultValue;
                        if (test.type === 'network_latency' && resultValue > 0) {
                            displayResult = resultValue; 
                        } else if (test.type === 'opcache_enabled' || test.type === 'cache_enabled') {
                            // Status check
                        } else {
                            if (typeof resultValue === 'number' && resultValue >= 0) {
                                totalTime += resultValue;
                                timeBasedTestCount++;
                            }
                        }

                        updateScoreDisplay(test.type, displayResult, score);

                        const weight = testWeights[test.type] || 1;
                        totalWeightedScore += score * weight;
                        totalWeight += weight;
                        totalScore += score;
                        testCount++;
                        categoryScores[test.cat] += score;
                        categoryCounts[test.cat]++;
                    }
                    // Logic handling ends
                }

                updateCategoryProgress(test.cat);
                currentTestIndex++;
                setTimeout(runNextComprehensiveTest, 100);
            })
            .catch(err => {
                clearTimeout(timeoutId);
                if (!benchmarkStopped) {
                    console.error('Test ' + test.type + ' failed:', err);
                    updateScoreDisplay(test.type, 0, 0);
                    currentTestIndex++;
                    setTimeout(runNextComprehensiveTest, 100);
                }
            });
        }
            </script>

            </body>
            </html>
