<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Answers one question: is this class declaration an Eloquent model?
 *
 * Three-valued on purpose. `true` = model, `false` = definitively not (the class
 * extends nothing, or its `extends` chain terminates at a non-model), `null` = unknown
 * (the chain leaves the project into vendor code we cannot read). Callers choose what
 * `unknown` means for their polarity via isModel(..., unknownIs:).
 *
 * Resolves parent class names itself from the declaring file's use statements and
 * namespace, so it is correct whether or not the caller ran NameResolver: an already
 * resolved FullyQualified parent contains a backslash and passes through untouched.
 */
final class EloquentModelDetector
{
    /**
     * Sub-namespaces of a Models namespace that hold helpers rather than models.
     *
     * @var array<int, string>
     */
    private const NON_MODEL_SUBNAMESPACES = [
        'Scopes', 'Observers', 'Casts', 'Collections', 'Traits', 'Concerns', 'Builders', 'Enums',
    ];

    /**
     * Whether a namespace denotes Eloquent models.
     *
     * Accepts any exact `Models` segment — App\Models, App\Models\Admin, and modular
     * layouts such as Modules\Billing\Models — while excluding the helper sub-namespaces
     * that live alongside models. `App\ViewModels` never qualifies: the match is on a
     * whole segment, not a suffix.
     */
    public function namespaceLooksLikeModels(?string $namespace): bool
    {
        if ($namespace === null || $namespace === '') {
            return false;
        }

        $segments = explode('\\', $namespace);
        $index = array_search('Models', $segments, true);

        if (! is_int($index)) {
            return false;
        }

        $next = $segments[$index + 1] ?? null;

        return $next === null || ! in_array($next, self::NON_MODEL_SUBNAMESPACES, true);
    }
}
