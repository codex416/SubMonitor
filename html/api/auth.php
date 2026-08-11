<?php
session_start();
if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    header('Content-Type: application/json');
    echo json_encode(['code' => 401, 'message' => '未授权']);
    exit;
}
