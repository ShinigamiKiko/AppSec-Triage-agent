<?php

namespace App;

use Symfony\Component\Yaml\Yaml;

final class ImportController
{
    public function import(string $document): string
    {
        $data = Yaml::parse($document);

        return (string) json_encode(['keys' => array_keys((array) $data)]);
    }
}
