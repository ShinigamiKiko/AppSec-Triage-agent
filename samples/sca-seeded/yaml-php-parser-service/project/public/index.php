<?php

require __DIR__ . '/../vendor/autoload.php';

use App\Service\Importer;

header('Content-Type: application/json');
$rows = (new Importer())->load((string) ($_POST['document'] ?? ''));
echo (string) json_encode(['rows' => count($rows)]);
