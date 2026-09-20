<?php

require __DIR__ . '/../vendor/autoload.php';

use App\Greeter;

header('Content-Type: text/plain');
echo (new Greeter())->greet((string) ($_GET['name'] ?? 'guest'));
