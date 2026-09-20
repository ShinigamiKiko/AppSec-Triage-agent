<?php

namespace App;

final class DateParser
{
    public static function parse(string $value): \DateTimeImmutable
    {
        return new \DateTimeImmutable($value);
    }
}
