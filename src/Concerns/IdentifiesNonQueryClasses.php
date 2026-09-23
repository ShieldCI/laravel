<?php

declare(strict_types=1);

namespace ShieldCI\Concerns;

use PhpParser\Node;

/**
 * Tells a facade read apart from a database query.
 *
 * Several analyzers have to answer the same question: does a chain rooted at this
 * class name reach the database? Cache, Config, Session and friends all expose
 * query-shaped methods (get(), all(), find()) that never issue SQL, so a rule that
 * matches on the method name alone reports them as queries.
 *
 * The list lives here rather than on each visitor because two private copies had
 * already drifted apart: one carried auth/guzzle/soap/curl, the other carried
 * route/blade/lang/date/vite/context and a dozen more, and neither knew about the
 * other. Analyzer-specific entries are still possible through $extra, which is the
 * honest way to express a difference that is real (see Auth, below).
 *
 * Matching is on the fully qualified name. `App\Models\Event` and
 * `Illuminate\Support\Facades\Event` share a last segment, and only the first of
 * them reads rows, so a short-name match silently exempts an application's own
 * models from the very check these analyzers exist to perform. Callers that want
 * the FQN must run the AST through ParserInterface::resolveNames() first; the bare
 * short name still matches when a name is unqualified, which covers both the
 * container alias spelling and a caller that has not resolved names.
 *
 * DB and Schema are deliberately absent: DB::table(...)->get() is a real query.
 * Auth is absent too, because Auth::user()->orders()->get() reads real rows, and
 * belongs in $extra for the analyzers that only ask whether the static call itself
 * is a query (Auth::user() is memoized, and is not).
 */
trait IdentifiesNonQueryClasses
{
    /**
     * True when a chain rooted at $class cannot reach the database.
     *
     * @param  array<int, string>  $extra  Analyzer-specific additions, as fully
     *                                     qualified names, or as a bare name when the
     *                                     class has no single canonical namespace.
     */
    private function isNonQueryClass(Node\Name $class, array $extra = []): bool
    {
        $fqn = $this->resolvedClassFqn($class);
        $known = array_merge($this->sharedNonQueryClasses(), $extra);

        if (in_array($fqn, $known, true)) {
            return true;
        }

        // An unqualified single-segment name is either the container alias spelling
        // (`Cache::get()` in a file with no namespace) or a caller that never resolved
        // names. Fall back to the short name there, and only there, so that a resolved
        // App\Models\Event cannot borrow the exemption meant for the Event facade.
        if (str_contains($fqn, '\\')) {
            return false;
        }

        $short = strtolower($fqn);

        foreach ($known as $name) {
            $parts = explode('\\', $name);
            if (strtolower((string) end($parts)) === $short) {
                return true;
            }
        }

        return false;
    }

    /**
     * The fully qualified name behind a class reference, preferring the attribute
     * NameResolver leaves behind when it runs with ['replaceNodes' => false], and
     * falling back to the name as written when it has not run.
     */
    private function resolvedClassFqn(Node\Name $class): string
    {
        $resolved = $class->getAttribute('resolvedName');

        $fqn = $resolved instanceof Node\Name\FullyQualified
            ? $resolved->toString()
            : $class->toString();

        return ltrim($fqn, '\\');
    }

    /**
     * @return array<int, string>
     */
    private function sharedNonQueryClasses(): array
    {
        return [
            // Laravel facades
            'Illuminate\Support\Facades\Cache',
            'Illuminate\Support\Facades\Config',
            'Illuminate\Support\Facades\Session',
            'Illuminate\Support\Facades\Cookie',
            'Illuminate\Support\Facades\Storage',
            'Illuminate\Support\Facades\File',
            'Illuminate\Support\Facades\Log',
            'Illuminate\Support\Facades\Event',
            'Illuminate\Support\Facades\Mail',
            'Illuminate\Support\Facades\Notification',
            'Illuminate\Support\Facades\Queue',
            'Illuminate\Support\Facades\Bus',
            'Illuminate\Support\Facades\Broadcast',
            'Illuminate\Support\Facades\Http',
            'Illuminate\Support\Facades\Redis',
            'Illuminate\Support\Facades\Validator',
            'Illuminate\Support\Facades\Gate',
            'Illuminate\Support\Facades\Hash',
            'Illuminate\Support\Facades\Crypt',
            'Illuminate\Support\Facades\Password',
            'Illuminate\Support\Facades\Artisan',
            'Illuminate\Support\Facades\View',
            'Illuminate\Support\Facades\Blade',
            'Illuminate\Support\Facades\Response',
            'Illuminate\Support\Facades\Redirect',
            'Illuminate\Support\Facades\URL',
            'Illuminate\Support\Facades\Lang',
            'Illuminate\Support\Facades\Date',
            'Illuminate\Support\Facades\Vite',
            'Illuminate\Support\Facades\Context',
            'Illuminate\Support\Facades\Process',
            'Illuminate\Support\Facades\Pipeline',
            'Illuminate\Support\Facades\RateLimiter',

            // Value and utility classes with query-shaped method names
            'Illuminate\Support\Arr',
            'Illuminate\Support\Str',
            'Illuminate\Support\Collection',
            'Carbon\Carbon',
            'Carbon\CarbonImmutable',
            'DateTime',
            'DateTimeImmutable',
        ];
    }
}
