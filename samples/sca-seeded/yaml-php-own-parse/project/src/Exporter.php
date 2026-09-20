<?php

namespace App;

use Symfony\Component\Yaml\Yaml;

final class Exporter
{
    /** @param array<array-key, mixed> $data */
    public static function export(array $data): string
    {
        return Yaml::dump($data);
    }
}
