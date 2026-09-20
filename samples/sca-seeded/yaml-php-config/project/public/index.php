<?php

require __DIR__ . '/../vendor/autoload.php';

use App\Config;

header('Content-Type: application/json');
$config = Config::load();
$name = (string) ($_GET['name'] ?? 'guest');
echo (string) json_encode(['service' => $config['service'] ?? 'unknown', 'hello' => $name]);
