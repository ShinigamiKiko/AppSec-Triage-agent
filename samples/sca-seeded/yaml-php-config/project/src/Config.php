<?php

namespace App;

use Symfony\Component\Yaml\Yaml;

final class Config
{
    /** @return array<array-key, mixed> */
    public static function load(): array
    {
        return (array) Yaml::parseFile(__DIR__ . '/../config/app.yaml');
    }
}
