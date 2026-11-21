<?php

// A router for `php -S`, used by tests/run.php to exercise the real transports.
// Echoes what it received; a few paths answer in other ways.

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$headers = function_exists('getallheaders') ? getallheaders() : [];

if ($path === '/slow') {
    usleep(1500000);
    header('Content-Type: application/json');
    echo '{"ok":true}';
    return true;
}
if ($path === '/redirect') {
    header('Location: http://127.0.0.1:1/elsewhere', true, 302);
    return true;
}
if ($path === '/html') {
    http_response_code(502);
    header('Content-Type: text/html');
    echo '<html><body>Bad gateway</body></html>';
    return true;
}
if ($path === '/denied') {
    http_response_code(401);
    header('Content-Type: application/json');
    echo '{"error":"unknown secret"}';
    return true;
}

$lower = [];
foreach ($headers as $name => $value) {
    $lower[strtolower($name)] = $value;
}
header('Content-Type: application/json');
echo json_encode([
    'ok' => true,
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => $path,
    'query' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
    'headers' => $lower,
    'body' => file_get_contents('php://input'),
]);
return true;
