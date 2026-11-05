<?php

// Cross-site request forgery guard for the upload endpoints. config.php loads
// this file, so both submit.php and the vendored FilePond index.php enforce it.
//
// A browser that attaches a logged-in user's credentials (basic/LDAP auth, or a
// session cookie) to a request also tells us where that request came from:
// Sec-Fetch-Site on every current browser, and Origin on any browser that makes
// a non-GET request. Origin is compared as a full origin (scheme, host and
// port), so a page on another port of the same hostname is rejected too. A
// request carrying neither header did not come from a web page in a browser
// (e.g. curl), so it cannot be a forgery on someone else's behalf. This is the
// same policy as Go's net/http CrossOriginProtection.

function same_origin_first_header_value($key) {
    if (!isset($_SERVER[$key])) return '';
    $values = explode(',', $_SERVER[$key]);
    return strtolower(trim($values[0]));
}

function same_origin_split_host_port($hostport) {
    $hostport = strtolower(trim($hostport));
    if (preg_match('/^\[([^\]]+)\](?::(\d+))?$/', $hostport, $m)) {
        return array($m[1], isset($m[2]) ? intval($m[2]) : 0);
    }
    if (preg_match('/^([^:]+):(\d+)$/', $hostport, $m)) {
        return array($m[1], intval($m[2]));
    }
    return array($hostport, 0);
}

function same_origin_normalize($scheme, $host, $port) {
    $scheme = strtolower($scheme);
    if (($port === 0) || (($scheme === 'https') && ($port === 443)) || (($scheme === 'http') && ($port === 80))) {
        return $scheme . '://' . $host;
    }
    return $scheme . '://' . $host . ':' . $port;
}

// The origin(s) this deployment is being addressed as, as seen by the browser.
// Malcolm's nginx proxy forwards the client's Host as Host and X-Forwarded-Host
// (without the port), the external scheme as X-Forwarded-Proto and its own
// listening port as X-Forwarded-Port. If a deployment publishes the proxy on a
// different port than it listens on, only the Origin fallback below is
// affected (browsers with Sec-Fetch-Site never reach it) and the result is a
// 403 for that browser, never an accepted forgery.
function same_origin_expected_origins() {
    $scheme = same_origin_first_header_value('HTTP_X_FORWARDED_PROTO');
    if (($scheme !== 'http') && ($scheme !== 'https')) {
        $scheme = (!empty($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) !== 'off')) ? 'https' : 'http';
    }
    $default_port = intval(same_origin_first_header_value('HTTP_X_FORWARDED_PORT'));
    if ($default_port === 0) {
        $default_port = intval($_SERVER['SERVER_PORT'] ?? 0);
    }

    $origins = array();
    foreach (array('HTTP_X_FORWARDED_HOST', 'HTTP_HOST') as $key) {
        if (!isset($_SERVER[$key])) continue;
        foreach (explode(',', $_SERVER[$key]) as $candidate) {
            list($host, $port) = same_origin_split_host_port($candidate);
            if (strlen($host) === 0) continue;
            $origins[] = same_origin_normalize($scheme, $host, ($port > 0) ? $port : $default_port);
        }
    }
    return $origins;
}

function same_origin_origin_matches($origin) {
    $parts = @parse_url(strtolower(trim($origin)));
    if (!is_array($parts) || !isset($parts['scheme']) || !isset($parts['host']) || (strlen($parts['host']) === 0)) {
        return false;
    }
    $normalized = same_origin_normalize($parts['scheme'], trim($parts['host'], '[]'), isset($parts['port']) ? intval($parts['port']) : 0);
    return in_array($normalized, same_origin_expected_origins(), true);
}

function same_origin_reject($reason) {
    $client = $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    error_log(sprintf('Rejected cross-site %s %s from %s (%s)',
        $_SERVER['REQUEST_METHOD'] ?? '?', $_SERVER['SCRIPT_NAME'] ?? '?', $client, $reason));
    http_response_code(403);
    header('Content-Type: text/plain');
    header('Cache-Control: no-store');
    echo "Forbidden: cross-site requests are not accepted by this endpoint\n";
    exit;
}

function same_origin_enforce() {
    // this endpoint is same-origin only, so never advertise cross-origin access
    header_remove('Access-Control-Allow-Origin');
    header_remove('Access-Control-Allow-Methods');
    header_remove('Access-Control-Allow-Headers');

    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    if (in_array($method, array('GET', 'HEAD', 'OPTIONS'), true)) return;

    if (isset($_SERVER['HTTP_SEC_FETCH_SITE'])) {
        $site = strtolower(trim($_SERVER['HTTP_SEC_FETCH_SITE']));
        if (($site === 'same-origin') || ($site === 'none')) return;
        same_origin_reject('Sec-Fetch-Site: ' . $site);
    }

    if (isset($_SERVER['HTTP_ORIGIN'])) {
        if (same_origin_origin_matches($_SERVER['HTTP_ORIGIN'])) return;
        same_origin_reject('Origin: ' . $_SERVER['HTTP_ORIGIN']);
    }
}

same_origin_enforce();
