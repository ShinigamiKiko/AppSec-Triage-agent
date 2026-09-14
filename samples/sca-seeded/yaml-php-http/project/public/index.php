<?php

require __DIR__ . '/../vendor/autoload.php';

use App\ImportController;

header('Content-Type: application/json');
echo (new ImportController())->import((string) ($_POST['document'] ?? ''));
