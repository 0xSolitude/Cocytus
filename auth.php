<?php
header('Content-Type: application/json');
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('HTTP/1.1 405 Method Not Allowed');
    echo json_encode(["status" => "error", "message" => "POST required"]);
    exit();
}

$rawHwid = isset($_POST['hwid']) ? trim($_POST['hwid']) : null;
if (!$rawHwid || strlen($rawHwid) < 16) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode(["status" => "error", "message" => "Parameter verification criteria failed"]);
    exit();
}

$hashedHwid = hash('sha256', $rawHwid);

$stmt = $pdo->prepare("SELECT id, status_state, tracking_group FROM system_nodes WHERE identity_hash = :hash LIMIT 1");
$stmt->execute(['hash' => $hashedHwid]);
$node = $stmt->fetch();

if ($node) {
    if ($node['status_state'] === 'AUTHORIZED') {
        $generatedToken = bin2hex(random_bytes(32));
        $expiration = date('Y-m-d H:i:s', strtotime('+8 hours'));
        
        $updateStmt = $pdo->prepare("INSERT INTO system_sessions (node_id, access_token, expiration_stamp) VALUES (:node_id, :token, :expiry)");
        $updateStmt->execute([
            'node_id' => $node['id'],
            'token'   => $generatedToken,
            'expiry'  => $expiration
        ]);

        echo json_encode([
            "status" => "success",
            "token"  => $generatedToken,
            "group"  => $node['tracking_group']
        ]);
    } else {
        echo json_encode(["status" => "revoked", "message" => "Assigned hardware access state terminated"]);
    }
} else {
    echo json_encode(["status" => "unregistered", "message" => "Node validation signature absent"]);
}
