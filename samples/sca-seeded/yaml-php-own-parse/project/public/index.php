<?php

require __DIR__ . '/../vendor/autoload.php';

use App\DateParser;
use App\Exporter;

header('Content-Type: text/yaml');
$when = DateParser::parse((string) ($_GET['date'] ?? 'now'));
echo Exporter::export(['requested' => $when->format(DATE_ATOM)]);
