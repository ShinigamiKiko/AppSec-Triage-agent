<?php
namespace App;

use Symfony\Component\Yaml\Yaml;

final class Importer
{
    public function run(string $path): string
    {
        $parsed = Yaml::parseFile($path);
        return json_encode($parsed);
    }
}
