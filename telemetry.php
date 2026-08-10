<?php
header('Content-Type: application/json');
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    exit();
}

$token = isset($_POST['token']) ? trim($_POST['token']) : null;
$action = isset($_POST['action']) ? trim($_POST['action']) : null;
$logData = isset($_POST['log']) ? trim($_POST['log']) : null;

if (!$token || !$action || !$logData) {
    exit();
}

$stmt = $pdo->prepare("SELECT node_id FROM system_sessions WHERE access_token = :token AND expiration_stamp > NOW() LIMIT 1");
$stmt->execute(['token' => $token]);
$session = $stmt->fetch();

if ($session) {
    $logStmt = $pdo->prepare("INSERT INTO system_logs (node_id, event_type, details_payload) VALUES (:node_id, :event_type, :details)");
    $logStmt->execute([
        'node_id'    => $session['node_id'],
        'event_type' => htmlspecialchars($action),
        'details'    => htmlspecialchars($logData)
    ]);
    echo json_encode(["status" => "recorded"]);
} else {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(["status" => "expired"]);
}
