<?php

namespace App\Service;

use Symfony\Component\Yaml\Parser;

final class Importer
{
    private Parser $parser;

    public function __construct()
    {
        $this->parser = new Parser();
    }

    /** @return array<array-key, mixed> */
    public function load(string $text): array
    {
        return (array) $this->parser->parse($text);
    }
}
