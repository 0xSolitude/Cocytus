<?php
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('HTTP/1.1 405 Method Not Allowed');
    echo json_encode(["status" => "error", "message" => "POST methodology required"]);
    exit();
}

$rawHwid = isset($_POST['hwid']) ? trim($_POST['hwid']) : null;

if (!$rawHwid || strlen($rawHwid) < 16 || strlen($rawHwid) > 256) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode(["status" => "error", "message" => "Invalid validation footprint constraints"]);
    exit();
}

$hashedHwid = hash('sha256', $rawHwid);

try {
    $stmt = $pdo->prepare("SELECT id, status_state, tracking_group FROM system_nodes WHERE identity_hash = :hash LIMIT 1");
    $stmt->execute(['hash' => $hashedHwid]);
    $node = $stmt->fetch();

    if (!$node) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(["status" => "unregistered", "message" => "Hardware registration signatures absent"]);
        exit();
    }

    if ($node['status_state'] !== 'AUTHORIZED') {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(["status" => "revoked", "message" => "Assigned operational clearance terminated"]);
        exit();
    }

    $generatedToken = bin2hex(random_bytes(32));
    $expiration = date('Y-m-d H:i:s', strtotime('+8 hours'));

    $pdo->beginTransaction();

    $cleanupStmt = $pdo->prepare("DELETE FROM system_sessions WHERE node_id = :node_id OR expiration_stamp <= NOW()");
    $cleanupStmt->execute(['node_id' => $node['id']]);

    $sessionStmt = $pdo->prepare("INSERT INTO system_sessions (node_id, access_token, expiration_stamp) VALUES (:node_id, :token, :expiry)");
    $sessionStmt->execute([
        'node_id' => $node['id'],
        'token'   => $generatedToken,
        'expiry'  => $expiration
    ]);

    $pdo->commit();

    echo json_encode([
        "status" => "success",
        "token"  => $generatedToken,
        "group"  => $node['tracking_group'],
        "cipher" => "AES-256-GCM"
    ]);

} catch (\Exception $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode(["status" => "error", "message" => "Infrastructure serialization breakdown"]);
    exit();
}
