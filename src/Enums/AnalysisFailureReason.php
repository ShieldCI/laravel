<?php

declare(strict_types=1);

namespace ShieldCI\Enums;

enum AnalysisFailureReason: string
{
    case InvalidOptions = 'invalid_options';
    case AllCategoriesDisabled = 'all_categories_disabled';
    case NoAnalyzersRan = 'no_analyzers_ran';
    case UncaughtException = 'uncaught_exception';

    public function label(): string
    {
        return match ($this) {
            self::InvalidOptions => 'Invalid command options',
            self::AllCategoriesDisabled => 'All analyzer categories are disabled',
            self::NoAnalyzersRan => 'No analyzers were executed',
            self::UncaughtException => 'Uncaught exception during analysis',
        };
    }
}
