<?php
require __DIR__ . '/../vendor/autoload.php';

use App\Importer;

$importer = new Importer();
echo $importer->run($_GET['file'] ?? 'data/default.yaml');
