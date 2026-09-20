<?php

namespace App\Tests;

use App\Greeter;
use Symfony\Component\Yaml\Yaml;

final class GreeterTest
{
    public function testGreetingsFromFixture(): void
    {
        $cases = (array) Yaml::parse((string) file_get_contents(__DIR__ . '/fixtures/greetings.yaml'));
        foreach ($cases as $name => $expected) {
            assert((new Greeter())->greet((string) $name) === $expected);
        }
    }
}
