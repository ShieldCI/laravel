<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\DataProvider;
use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\ParseFailureCause;
use ShieldCI\AnalyzersCore\Enums\Severity;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Support\BladeCompilerFactory;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneBladeTest extends AnalyzerTestCase
{
    private const CITY_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }";

    private const AIRPORT_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Airport extends Model {}";

    private const CITY_CONTROLLER = "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }";

    private const SHELF_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(Book::class); } public function curator(){ return \$this->belongsTo(Curator::class); } }";

    private const BOOK_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Book extends Model { public function publisher(){ return \$this->belongsTo(Publisher::class); } }";

    private const SHELF_VIEW = "@foreach(\$shelves as \$shelf)\n  {{ \$shelf->curator->name }}\n@endforeach";

    private const NESTED_SHELF_VIEW = "@foreach(\$shelves as \$shelf)\n  @foreach(\$shelf->books as \$book)\n    {{ \$book->publisher->name }}\n  @endforeach\n@endforeach";

    /**
     * A template that compiles cleanly but whose compiled PHP will not parse: Blade copies a
     * block body through verbatim, so an incomplete assignment inside one survives compilation
     * and only fails at the parser.
     *
     * The relationship access on line 5 is not decoration. Without it the template would
     * report nothing even if it parsed, and the "nothing was reported" assertion below would
     * hold for the wrong reason.
     */
    private const BROKEN_VIEW = "@foreach(\$cities as \$city)\n  @php\n    \$total = ;\n  @endphp\n  {{ \$city->airports->count() }}\n@endforeach\n";

    protected function createAnalyzer(): AnalyzerInterface
    {
        return new EloquentNPlusOneAnalyzer($this->parser);
    }

    /**
     * @param  array<string,string>  $files
     * @param  list<string>  $paths
     */
    private function analyze(array $files, array $paths = ['app', 'resources/views']): ResultInterface
    {
        $dir = $this->createTempDirectory($files);
        $analyzer = new EloquentNPlusOneAnalyzer(new AstParser);
        $analyzer->setBasePath($dir);
        $analyzer->setPaths($paths);

        return $analyzer->analyze();
    }

    /** @return list<Issue> */
    private function airportIssues(ResultInterface $result): array
    {
        return array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'airports')));
    }

    /**
     * Findings produced from `NPlusOneVisitor::getQueryIssues()` — an actual query executed
     * per loop iteration, as opposed to a lazy relationship access. Filtered by the `query`
     * metadata key rather than message content, since it is set only on this finding kind.
     *
     * @return list<Issue>
     */
    private function queryExecutionIssues(ResultInterface $result): array
    {
        return array_values(array_filter($result->getIssues(), fn (Issue $i): bool => array_key_exists('query', $i->metadata)));
    }

    /**
     * Each finding's relationship and Blade line, in report order.
     *
     * @return list<array{string, int|null}>
     */
    private function relationFindings(ResultInterface $result): array
    {
        $findings = [];
        foreach ($result->getIssues() as $issue) {
            $relationship = $issue->metadata['relationship'] ?? null;
            if (is_string($relationship)) {
                $findings[] = [$relationship, $issue->location?->line];
            }
        }

        return $findings;
    }

    public function test_flags_lazy_relation_when_controller_does_not_eager_load(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }",
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('index.blade.php', $location->file);
        $this->assertStringContainsString('CityController::index', $issues[0]->recommendation);
    }

    public function test_silent_when_controller_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }",
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::with('airports')->get(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: two controllers render the same view. Only one eager-loads the
     * relationship the view reads — a relation eager-loaded on ANY render path must be
     * treated as loaded on all, so the finding is suppressed even though the other
     * controller does not eager-load it.
     */
    public function test_silent_when_only_one_of_two_render_sites_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityIndexController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityIndexController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'app/Http/Controllers/CityMembershipController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityMembershipController { public function membership(){ \$cities = City::with('airports')->get(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: a view with no resolvable render site (no controller anywhere in the
     * project calls `view('partials._row', ...)`) must be skipped entirely — `resolve()`
     * returns null and `analyzeBladeFile` bails before ever compiling or scanning it.
     */
    public function test_silent_when_partial_has_no_render_site(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'resources/views/partials/_row.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Merge policy: when a render-bound variable's type is never inferred (built via
     * `collect()` and populated inside a `chunk()` callback, rather than a direct model
     * query assignment), the variable is dropped entirely rather than analyzed — false
     * negatives are preferred to false positives on code the scanner cannot understand.
     */
    public function test_silent_when_variable_type_is_never_inferred(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityChunkController.php' => <<<'PHP'
                <?php
                namespace App\Http\Controllers;
                use App\Models\City;
                class CityChunkController
                {
                    public function index()
                    {
                        $cities = collect();
                        City::with('airports')->chunk(200, function ($c) use (&$cities) {
                            foreach ($c as $x) {
                                $cities->push($x);
                            }
                        });

                        return view('cities.chunked', compact('cities'));
                    }
                }
                PHP,
            'resources/views/cities/chunked.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * A relationship accessed via an explicit method call chain ending in a query-execution
     * method (`$city->airports()->count()`, as opposed to the lazy-loading property access
     * `$city->airports->count()` in the other fixtures) is caught by two distinct branches of
     * the visitor once the render-bound type is known: the inner `airports()` call itself
     * reads as a lazy relationship access (`getIssues()`), and the full `->count()` chain
     * reads as an executed query (`getQueryIssues()`) — both now surface from a Blade view.
     */
    public function test_flags_method_call_query_chain_inside_view_loop(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/MethodChainController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass MethodChainController { public function index(){ \$cities = City::all(); return view('cities.methodchain', compact('cities')); } }",
            'resources/views/cities/methodchain.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(2, $issues);
        $this->assertStringContainsString('MethodChainController::index', $issues[0]->recommendation);
    }

    /**
     * A query executed inside a Blade loop (`$city->airports()->count()`) is the most severe
     * shape of N+1 — an actual query per iteration, not just a lazy access — and must be
     * flagged from a Blade view exactly like the plain-PHP path already does. This requires
     * the controller to actually bind `$cities` (`compact('cities')`): a bare `view('x')` call
     * with no data leaves the render-bound variable's type unknown, and `analyzeBladeFile()`
     * skips a view with no resolvable render site entirely — neither `getIssues()` nor
     * `getQueryIssues()` can fire without a known type, so that variant would stay silent
     * regardless of this wiring.
     */
    public function test_flags_query_executed_inside_blade_loop(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $issues = $this->queryExecutionIssues($result);
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('executing', $issues[0]->message);
        $this->assertSame('$city->airports()->count()', $issues[0]->metadata['query']);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('index.blade.php', $location->file);
    }

    /**
     * A template reaches for a model the same way a PHP file does, so the facade list has to
     * see the same fully qualified name. `Event` shares a last segment with the Event facade,
     * and matching on that segment used to exempt the model from the check entirely.
     *
     * The Event model is here to make the import coherent, not to carry the assertion: this
     * finding comes from the query chain, which never consults the relationship registry.
     * The colliding-imports test below does depend on its Airport model being registered.
     */
    public function test_flags_a_facade_named_model_a_template_imports(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Event.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Event extends Model {}",
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@php use App\\Models\\Event; @endphp\n@foreach(\$cities as \$city)\n  {{ Event::where('city_id', \$city->id)->count() }}\n@endforeach",
        ]);

        $issues = $this->queryExecutionIssues($result);
        $this->assertCount(1, $issues);
        $this->assertSame('Event::where()->...count()', $issues[0]->metadata['query']);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('index.blade.php', $location->file);
    }

    /**
     * The counterpart: compiled output carries no namespace, so a name a template writes bare
     * is the container alias, and the facade keeps its exemption there.
     */
    public function test_silent_when_a_template_names_the_facade_itself(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ Cache::get('city_' . \$city->id) }}\n@endforeach",
        ]);

        $this->assertSame([], $this->queryExecutionIssues($result));
    }

    /**
     * Resolving names throws on an import set PHP would reject, and a template carries its own
     * through @php use. Only the facade resolution degrades there: the template is still
     * analysed, because dropping it would lose a relationship finding that never depended on
     * an import, and leave nothing behind saying the view had been skipped.
     */
    public function test_still_analyzes_a_template_whose_imports_collide(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } public function broken(){ \$cities = City::all(); return view('cities.broken', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
            'resources/views/cities/broken.blade.php' => "@php use App\\Models\\Airport; @endphp\n@php use App\\Other\\Airport; @endphp\n@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertFailed($result);

        $files = array_map(fn (Issue $i): string => basename((string) $i->location?->file), $this->airportIssues($result));
        sort($files);
        $this->assertSame(['broken.blade.php', 'index.blade.php'], $files);
    }

    /**
     * The guard around name resolution covers that one call and nothing else. A fault anywhere
     * else in the Blade path is a bug in this analyzer, and has to reach the error channel
     * #343 added rather than be reported as a project with clean views.
     */
    public function test_does_not_swallow_a_fault_in_the_blade_path(): void
    {
        $parser = new class extends AstParser
        {
            public function parseCode(string $code, ?string $origin = null, ?callable $translateLine = null): array
            {
                // Only the compiled-template call, so that scanning the project's own PHP
                // files still works and the analyzer reaches the Blade path at all.
                if ($origin !== null && str_ends_with($origin, BladeCompilerFactory::COMPILED_ORIGIN_SUFFIX)) {
                    throw new \RuntimeException('compiled template exploded');
                }

                return parent::parseCode($code, $origin, $translateLine);
            }
        };

        $dir = $this->createTempDirectory([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $analyzer = new EloquentNPlusOneAnalyzer($parser);
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['app', 'resources/views']);

        $result = $analyzer->analyze();

        $this->assertError($result);
        $this->assertSame('RuntimeException', $result->getMetadata()['exception'] ?? null);
    }

    /**
     * A vendor-published view (e.g. from a Composer package) is always skipped, even when a
     * controller renders it with a non-eager-loaded relationship that would otherwise be
     * flagged in an application view.
     */
    public function test_vendor_view_is_skipped(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/VendorViewController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass VendorViewController { public function index(){ \$cities = City::all(); return view('vendor.pkg.x', compact('cities')); } }",
            'resources/views/vendor/pkg/x.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Part B (nested @foreach): Blade compiles nested loops by reassigning the SAME
     * `$__currentLoopData` synthetic variable at each nesting level. The unresolved N+1
     * access here is `$city->airports` — the data source of the inner loop, accessed while
     * still inside the OUTER loop body — and it is caught before the inner loop's type
     * inference ever comes into play. `$airport` is typed as an Airport, from
     * `hasMany(Airport::class)`, and `name` is not a relation on it.
     */
    public function test_nested_foreach_not_eager_loaded_flags_outer_relationship_access(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/NestedController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass NestedController { public function index(){ \$cities = City::all(); return view('cities.nested', compact('cities')); } }",
            'resources/views/cities/nested.blade.php' => "@foreach(\$cities as \$city)\n  @foreach(\$city->airports as \$airport)\n    {{ \$airport->name }}\n  @endforeach\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertSame(2, $location->line);
        $this->assertStringContainsString('NestedController::index', $issues[0]->recommendation);
    }

    /**
     * Part B (nested @foreach), the design's core promise: eager-loading the relationship
     * that seeds a nested loop must silence the finding, exactly like the single-loop case.
     */
    public function test_nested_foreach_eager_loaded_is_silent(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/NestedController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass NestedController { public function index(){ \$cities = City::with('airports')->get(); return view('cities.nested', compact('cities')); } }",
            'resources/views/cities/nested.blade.php' => "@foreach(\$cities as \$city)\n  @foreach(\$city->airports as \$airport)\n    {{ \$airport->name }}\n  @endforeach\n@endforeach",
        ]);

        $this->assertSame([], $this->airportIssues($result));
    }

    /**
     * Regression test for the real-corpus false positive: Config defines zero
     * relationships, so it never enters the relationship registry and previously fell
     * through to the property-name heuristic, which has no accessor awareness and flagged
     * `value_preview` (a `getValuePreviewAttribute()` accessor) as a probable relationship.
     */
    public function test_silent_when_property_is_an_accessor_on_a_model_with_no_relationships(): void
    {
        $result = $this->analyze([
            'app/Models/Config.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Config extends Model { public function getValuePreviewAttribute(): string { return str(\$this->value)->limit(50)->toString(); } }",
            'app/Http/Controllers/ConfigController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Config;\nclass ConfigController { public function index(){ \$configs = Config::all(); return view('configs.index', compact('configs')); } }",
            'resources/views/configs/index.blade.php' => "@foreach(\$configs as \$config)\n  {{ \$config->value_preview }}\n@endforeach",
        ]);

        $issues = array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'value_preview')));
        $this->assertSame([], $issues);
    }

    /**
     * FP-A (critical, real-corpus false positive): Blade compiles nested `@foreach` by
     * reassigning the SAME synthetic `$__currentLoopData` variable at each nesting level. The
     * inner reassignment (`$__currentLoopData = $post->comments;`) is a PropertyFetch, not a
     * bare Variable, so before the fix it failed to invalidate the stale entry the OUTER loop
     * left behind — `$comment` inherited `$post`'s type (`Post`) and eager-loaded relations
     * (`['comments', 'comments.author']`). `Post` happens to declare its own `author()`
     * relation, so the mistaken type made `$comment->author` look like an un-eager-loaded
     * relationship on `Post`, even though `comments.author` IS eager-loaded — on `Comment`,
     * the correct model, which the inner loop now infers from `comments()`. This is the
     * canonical nested-Blade shape and exactly the false-positive class this analyzer exists
     * to prevent.
     */
    public function test_nested_foreach_relation_eager_loaded_via_dot_notation_is_silent(): void
    {
        $result = $this->analyze([
            'app/Models/Post.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Post extends Model { public function comments(){ return \$this->hasMany(Comment::class); } public function author(){ return \$this->belongsTo(User::class); } }",
            'app/Models/Comment.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Comment extends Model { public function author(){ return \$this->belongsTo(User::class); } }",
            'app/Http/Controllers/PostController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nclass PostController { public function index(){ \$posts = Post::with('comments.author')->get(); return view('posts.index', compact('posts')); } }",
            'resources/views/posts/index.blade.php' => "@foreach(\$posts as \$post)\n  @foreach(\$post->comments as \$comment)\n    {{ \$comment->author->name }}\n  @endforeach\n@endforeach",
        ]);

        $issues = array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'author')));
        $this->assertSame([], $issues);
    }

    /**
     * FP-C: two SEQUENTIAL, non-nested `@foreach` blocks. The first's source is a bare
     * variable (`$cities`), which sets the synthetic `$__currentLoopData`'s type to `City`.
     * The second's source is a property fetch (`$region->airports`) rather than a bare
     * variable, so before the fix `$__currentLoopData` kept its STALE `City` type from the
     * first loop, and `$airport` wrongly inherited it. `City` alone declares a `mayor()`
     * relation, so `$airport->mayor` was wrongly flagged as an un-eager-loaded relationship
     * even though the real (unrelated, never-typed) second-loop variable has nothing to do
     * with `City` at all.
     */
    public function test_sequential_non_nested_foreach_does_not_leak_stale_type_to_second_loop_var(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function mayor(){ return \$this->belongsTo(Mayor::class); } }",
            'app/Http/Controllers/RegionController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass RegionController { public function index(){ \$cities = City::all(); return view('regions.index', compact('cities')); } }",
            'resources/views/regions/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->name }}\n@endforeach\n@foreach(\$region->airports as \$airport)\n  {{ \$airport->mayor }}\n@endforeach",
        ]);

        $issues = array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'mayor')));
        $this->assertSame([], $issues);
    }

    /**
     * Regression for `ModelVariableScanner::copyContext()`'s merge-vs-assignment bug: compiled
     * Blade copies every `@foreach` from the SAME synthetic `$__currentLoopData` key, so when a
     * template reuses a loop-variable name (`$item`) across two loops and the second loop's
     * source is a relation property fetch (`$user->posts`, not type-inferable), the freshly
     * cleared `$__currentLoopData` has nothing to copy — `copyContext()` must still clear
     * `$item`'s OWN previous (first-loop) type/eager-loads/origin rather than leaving them in
     * place. `User` declares its own `author()` relation purely so the stale `User` type — if
     * it leaks through — passes the registry's precise-lookup check exactly like the real
     * `Post::author()` would, making the false positive this test guards against reproducible:
     * pre-fix, `$item` keeps loop one's `User` type and its eager-load list (`['posts',
     * 'posts.author']`), which does not contain the bare `'author'` entry, so `$item->author`
     * (really a `Post`, reached via `$user->posts`, and genuinely eager-loaded through
     * `posts.author`) is wrongly flagged.
     */
    public function test_reused_loop_variable_name_across_two_loops_stays_silent_when_eager_loaded(): void
    {
        $result = $this->analyze([
            'app/Models/User.php' => <<<'PHP'
                <?php
                namespace App\Models;
                use Illuminate\Database\Eloquent\Model;
                class User extends Model
                {
                    public function posts(){ return $this->hasMany(Post::class); }
                    public function author(){ return $this->belongsTo(User::class, 'created_by'); }
                }
                PHP,
            'app/Models/Post.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Post extends Model { public function author(){ return \$this->belongsTo(User::class); } }",
            'app/Http/Controllers/FeedController.php' => <<<'PHP'
                <?php
                namespace App\Http\Controllers;
                use App\Models\User;
                class FeedController
                {
                    public function index()
                    {
                        $users = User::with('posts.author')->get();

                        return view('feed.index', compact('users'));
                    }
                }
                PHP,
            'resources/views/feed/index.blade.php' => <<<'BLADE'
                @foreach($users as $item)
                  {{ $item->name }}
                @endforeach

                @foreach($users as $user)
                  @foreach($user->posts as $item)
                    {{ $item->author->name }}
                  @endforeach
                @endforeach
                BLADE,
        ]);

        $issues = array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'author')));
        $this->assertSame([], $issues);
    }

    /**
     * The other side of the merge-vs-assignment bug: a stale eager-load list must not
     * SUPPRESS a genuine finding either. Loop one's `$item` (`User::with('author')`) leaves
     * eager loads `['author']` behind; loop two reuses `$item` for a DIFFERENT, non-eager-loaded
     * `Post` collection. Pre-fix, `$item`'s type is correctly overwritten to `Post` (its source,
     * `$posts`, IS a bare, type-inferable variable), but the STALE `['author']` eager-load list
     * survives because `copyContext()` only overwrites `eagerLoads[$to]` when the source has an
     * entry — and here the source (`$posts`, never eager-loaded) has none. That stale, coincidentally
     * matching list wrongly suppresses a real N+1 on `$item->author`.
     */
    public function test_reused_loop_variable_name_flags_genuine_lazy_relation_not_masked_by_stale_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/User.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass User extends Model { public function author(){ return \$this->belongsTo(User::class, 'created_by'); } }",
            'app/Models/Post.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Post extends Model { public function author(){ return \$this->belongsTo(User::class); } }",
            'app/Http/Controllers/FeedController.php' => <<<'PHP'
                <?php
                namespace App\Http\Controllers;
                use App\Models\User;
                use App\Models\Post;
                class FeedController
                {
                    public function index()
                    {
                        $users = User::with('author')->get();
                        $posts = Post::all();

                        return view('feed.mixed', compact('users', 'posts'));
                    }
                }
                PHP,
            'resources/views/feed/mixed.blade.php' => <<<'BLADE'
                @foreach($users as $item)
                  {{ $item->name }}
                @endforeach

                @foreach($posts as $item)
                  {{ $item->author->name }}
                @endforeach
                BLADE,
        ]);

        $issues = array_values(array_filter($result->getIssues(), fn (Issue $i): bool => str_contains($i->message, 'author')));
        $this->assertCount(1, $issues);
        $this->assertStringContainsString('FeedController::index', $issues[0]->recommendation);
    }

    /**
     * Regression test for the polymorphic-column false positive. `subject_type` and
     * `subject_id` are the two halves of a morphTo pair: plain columns on a row that the
     * paginated query already put in memory, with the relation itself named `subject`. The
     * model ships inside a package, so it never enters the relationship registry and the
     * property name reached the naming heuristic instead. Flagging it is worse than noise,
     * because the recommendation this analyzer emits is to eager-load the flagged name and
     * `with('subject_type')` raises RelationNotFoundException.
     */
    public function test_morph_type_column_on_unscanned_model_is_not_flagged(): void
    {
        $result = $this->analyze([
            'app/Http/Controllers/AuditController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Vendor\\Audit\\Models\\AuditEntry;\nclass AuditController { public function index(){ \$entries = AuditEntry::latest()->paginate(10); return view('audit.index', compact('entries')); } }",
            'resources/views/audit/index.blade.php' => "@foreach(\$entries as \$entry)\n  {{ \$entry->subject_type }} : {{ \$entry->subject_id }}\n@endforeach",
        ]);

        $messages = array_map(fn (Issue $i): string => $i->message, $result->getIssues());
        $this->assertSame([], $messages);
    }

    /**
     * The Blade path is seeded from the same scan result as the PHP path, so a
     * relationship the model reaches through a trait has to read the same way in a view as
     * it does in a controller. City declares one relationship of its own here, which is the
     * arrangement that used to hide the trait's: being in the registry at all meant the
     * registry was answered by exact lookup, with no fallback.
     */
    public function test_flags_lazy_relation_declared_in_a_trait(): void
    {
        $result = $this->analyze([
            'app/Models/Concerns/HasAirports.php' => "<?php\nnamespace App\\Models\\Concerns;\nuse App\\Models\\Airport;\ntrait HasAirports { public function airports(){ return \$this->hasMany(Airport::class); } }",
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nuse App\\Models\\Concerns\\HasAirports;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { use HasAirports; public function mayor(){ return \$this->belongsTo(Mayor::class); } }",
            'app/Http/Controllers/CityController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }",
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $location = $issues[0]->location;
        $this->assertNotNull($location);
        $this->assertStringEndsWith('index.blade.php', $location->file);
    }

    /**
     * A template whose compiled PHP will not parse is skipped exactly as before, so nothing
     * is reported from it. What is new is that the skip is recorded: against the Blade file
     * it came from, marked as compiled output, and at the Blade line the failure maps to
     * rather than the compiled-PHP line, which is a line nobody wrote.
     *
     * The render site is load-bearing. analyzeBladeFile() returns before it reads or compiles
     * anything when no scanned file binds a variable into the view, so a fixture without
     * CityController would prove nothing about the parse. compact('cities') is what registers
     * the binding; a bare view('cities.index') registers none.
     *
     * The parser is this test's own rather than the container singleton, which the analyzer's
     * required constructor argument makes possible. The whole log can then be asserted on:
     * three files were parsed and only the compiled template failed.
     */
    public function test_a_template_it_cannot_parse_is_recorded_against_that_template(): void
    {
        $dir = $this->createTempDirectory([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => self::BROKEN_VIEW,
        ]);

        $parser = new AstParser;
        $analyzer = new EloquentNPlusOneAnalyzer($parser);
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['app', 'resources/views']);

        $result = $analyzer->analyze();

        // Unchanged behaviour: no AST means nothing to traverse, so nothing is reported.
        $this->assertSame([], $this->airportIssues($result));

        $failures = $parser->failures();
        $this->assertCount(1, $failures, 'One unparseable template must leave exactly one entry.');

        // Spelled out rather than read off BladeCompilerFactory: a test that reused the
        // constant could not catch the constant changing.
        $suffix = ' (compiled)';
        $path = (string) $failures[0]->path;

        $this->assertStringEndsWith($suffix, $path, 'The origin must say the parsed source was compiled output.');

        // Compared through realpath() because the analyzer records the path it was handed,
        // which on macOS is /var/... where realpath() gives /private/var/....
        $this->assertSame(
            (string) realpath($dir.'/resources/views/cities/index.blade.php'),
            (string) realpath(substr($path, 0, -strlen($suffix))),
            'The unparseable template must be recorded against its own origin.'
        );

        $this->assertSame(ParseFailureCause::SyntaxError, $failures[0]->cause);
        $this->assertSame(3, $failures[0]->line, 'The line must be the Blade line, not the compiled-PHP line.');
    }

    /**
     * Both Blade analyzers compile the same templates, so they have to spell the origin the
     * same way. The failure log keys on that string and keeps the first sighting of each key,
     * so one broken template must leave one entry however many analyzers met it, rather than
     * an attributable entry plus a duplicate keyed by a hash of the compiled PHP.
     *
     * Driven over one parser handed to both, with the same base path and paths, because
     * identical origins are exactly what is being asserted.
     */
    public function test_both_blade_analyzers_leave_one_entry_for_one_broken_template(): void
    {
        $dir = $this->createTempDirectory([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Models/Airport.php' => self::AIRPORT_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => self::BROKEN_VIEW,
        ]);

        $parser = new AstParser;

        $nPlusOne = new EloquentNPlusOneAnalyzer($parser);
        $nPlusOne->setBasePath($dir);
        $nPlusOne->setPaths(['app', 'resources/views']);
        $nPlusOne->analyze();

        $logicInBlade = new LogicInBladeAnalyzer(new Repository([]), $parser);
        $logicInBlade->setBasePath($dir);
        $logicInBlade->setPaths(['app', 'resources/views']);
        $logicInBlade->analyze();

        $failures = $parser->failures();

        $this->assertCount(
            1,
            $failures,
            'Two analyzers over one broken template must agree on its origin, leaving one entry.'
        );
        $this->assertStringEndsWith(
            '/resources/views/cities/index.blade.php (compiled)',
            (string) $failures[0]->path
        );
    }

    /**
     * The Blade half of the attribute-declared column cases: a column a model declares through
     * a class attribute or a casts() method is never a relationship, on a model that uses a
     * trait outside the scanned paths and so is not read in full. The separate Post model's
     * author() relationship is the control that has to keep firing.
     *
     * @dataProvider attributeDeclaredColumnProvider
     */
    #[DataProvider('attributeDeclaredColumnProvider')]
    public function test_silent_on_a_column_declared_by_an_attribute_or_casts_method(string $imports, string $attributes, string $body, string $column): void
    {
        $result = $this->analyzeAttributeDeclaredColumn($imports, $attributes, $body, $column);

        $this->assertSame([], $this->issueMessagesNaming($column, $result));
        $this->assertCount(1, $this->issueMessagesNaming('author', $result));
    }

    /**
     * @return array<string, array{string, string, string, string}>
     */
    public static function attributeDeclaredColumnProvider(): array
    {
        return [
            'Fillable with an array' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable;',
                "#[Fillable(['subject', 'html'])]",
                '',
                'subject',
            ],
            'Fillable with variadic strings' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable;',
                "#[Fillable('subject', 'html')]",
                '',
                'subject',
            ],
            'Fillable imported under an alias' => [
                'use Illuminate\Database\Eloquent\Attributes\Fillable as F;',
                "#[F(['subject', 'html'])]",
                '',
                'subject',
            ],
            'Appends' => [
                'use Illuminate\Database\Eloquent\Attributes\Appends;',
                "#[Appends(['teaser'])]",
                '',
                'teaser',
            ],
            'casts() returning an array literal' => [
                '',
                '',
                "protected function casts(): array { return ['headline' => 'string']; }",
                'headline',
            ],
            'Attribute accessor read by its method name' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function shortTitle(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'shortTitle',
            ],
            'Attribute accessor imported under an alias' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute as Accessor;',
                '',
                'protected function headline(): Accessor { return Accessor::make(get: fn ($value) => strtoupper($value)); }',
                'headline',
            ],
            'Attribute accessor with a nullable union return type' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function headline(): Attribute|null { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'headline',
            ],
            'Attribute accessor read in another case' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function SKU(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'sku',
            ],
            'Multi-word Attribute accessor read in lower case' => [
                'use Illuminate\Database\Eloquent\Casts\Attribute;',
                '',
                'protected function fullHeadline(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
                'fullheadline',
            ],
            'get...Attribute accessor read in another case' => [
                '',
                '',
                'public function getSKUAttribute($value) { return strtoupper($value); }',
                'sku',
            ],
            'default in the attributes property' => [
                '',
                '',
                "protected \$attributes = ['headline' => 'draft'];",
                'headline',
            ],
            'casts() merging an array literal into the parent casts' => [
                '',
                '',
                "protected function casts(): array { return array_merge(parent::casts(), ['headline' => 'string']); }",
                'headline',
            ],
            'casts() adding the parent casts with +' => [
                '',
                '',
                "protected function casts(): array { return ['headline' => 'string'] + parent::casts(); }",
                'headline',
            ],
        ];
    }

    /**
     * A casts() method that returns a variable names no column the scan can read, so the
     * column stays unknown and the name heuristic still answers it.
     */
    public function test_a_casts_method_returning_a_variable_leaves_the_column_unknown(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            '',
            '',
            "protected function casts(): array { \$casts = ['headline' => 'string']; return \$casts; }",
            'headline',
        );

        $this->assertCount(1, $this->issueMessagesNaming('headline', $result));
        $this->assertCount(1, $this->issueMessagesNaming('author', $result));
    }

    /**
     * An Attribute of the same short name from another namespace makes the method an ordinary
     * one, so the name stays unknown and the name heuristic still answers it.
     */
    public function test_an_attribute_accessor_from_another_namespace_is_not_read(): void
    {
        $result = $this->analyzeAttributeDeclaredColumn(
            'use App\Casts\Attribute;',
            '',
            'protected function headline(): Attribute { return Attribute::make(get: fn ($value) => strtoupper($value)); }',
            'headline',
        );

        $this->assertCount(1, $this->issueMessagesNaming('headline', $result));
        $this->assertCount(1, $this->issueMessagesNaming('author', $result));
    }

    /**
     * #[Hidden] and #[Visible] list relationships as well as columns, so a relationship from a
     * trait the scan never read is still flagged when either lists it.
     *
     * @dataProvider serializationAttributeProvider
     */
    #[DataProvider('serializationAttributeProvider')]
    public function test_flags_a_relationship_listed_by_a_serialization_attribute(string $attribute): void
    {
        $result = $this->analyze([
            'app/Models/Widget.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Attributes\\{$attribute};\nuse Illuminate\\Database\\Eloquent\\Model;\n#[{$attribute}(['id', 'gadgets'])]\nclass Widget extends Model { use \\Vendor\\Pkg\\HasGadgets; }",
            'app/Http/Controllers/WidgetController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Widget;\nclass WidgetController { public function index(){ \$widgets = Widget::all(); return view('widgets.index', compact('widgets')); } }",
            'resources/views/widgets/index.blade.php' => "@foreach(\$widgets as \$widget)\n  {{ \$widget->gadgets->count() }}\n@endforeach",
        ]);

        $this->assertCount(1, $this->issueMessagesNaming('gadgets', $result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function serializationAttributeProvider(): array
    {
        return [
            'Hidden' => ['Hidden'],
            'Visible' => ['Visible'],
        ];
    }

    /**
     * A writer() relationship the model declares shadows a trait's writer() Attribute accessor,
     * so it is still flagged.
     */
    public function test_flags_a_relationship_shadowing_a_trait_attribute_accessor(): void
    {
        $result = $this->analyze([
            'app/Models/HasWriterLabel.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Casts\\Attribute;\ntrait HasWriterLabel { protected function writer(): Attribute { return Attribute::make(get: fn (\$value) => strtoupper(\$value)); } }",
            'app/Models/Article.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Illuminate\\Database\\Eloquent\\Relations\\BelongsTo;\nclass Article extends Model { use HasWriterLabel; use \\Vendor\\Pkg\\HasThings; public function writer(): BelongsTo { return \$this->belongsTo(User::class); } }",
            'app/Http/Controllers/ArticleController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Article;\nclass ArticleController { public function index(){ \$articles = Article::all(); return view('articles.index', compact('articles')); } }",
            'resources/views/articles/index.blade.php' => "@foreach(\$articles as \$article)\n  {{ \$article->writer->name }}\n@endforeach",
        ]);

        $this->assertCount(1, $this->issueMessagesNaming('writer', $result));
    }

    /**
     * A get...Attribute() accessor only answers a property read, so calling the relationship
     * method of the same name in a view is still flagged.
     */
    public function test_flags_a_relationship_called_as_a_method_beside_an_accessor(): void
    {
        $result = $this->analyze([
            'app/Models/Member.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Illuminate\\Database\\Eloquent\\Relations\\HasOne;\nclass Member extends Model { public function primaryAddress(): HasOne { return \$this->hasOne(Address::class); } public function getPrimaryAddressAttribute() { return 'x'; } }",
            'app/Http/Controllers/MemberController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Member;\nclass MemberController { public function index(){ \$members = Member::all(); return view('members.index', compact('members')); } }",
            'resources/views/members/index.blade.php' => "@foreach(\$members as \$member)\n  {{ \$member->primaryAddress()->count() }}\n@endforeach",
        ]);

        $this->assertCount(1, $this->issueMessagesNaming('primaryAddress', $result));
        $this->assertCount(1, $this->issueMessagesNaming('$member->primaryAddress()->count()', $result));
    }

    /**
     * A $fillable name is a column Model reads before any relationship, so a relationship of the
     * same name read as a property is not flagged.
     */
    public function test_silent_on_a_fillable_column_beside_a_same_named_relationship(): void
    {
        $result = $this->analyzeItemView(
            "protected \$fillable = ['author']; public function author(): BelongsTo { return \$this->belongsTo(User::class); }",
            '{{ $item->author }}',
        );

        $this->assertSame([], $this->issueMessagesNaming('author', $result));
    }

    /**
     * A column never answers a method call, so a relationship called as a method in a view is
     * flagged even when casts(), $attributes or $fillable also names it.
     *
     * @dataProvider columnBesideCalledRelationshipProvider
     */
    #[DataProvider('columnBesideCalledRelationshipProvider')]
    public function test_flags_a_relationship_called_as_a_method_beside_a_column_of_its_name(string $declaration): void
    {
        $result = $this->analyzeItemView(
            "{$declaration} public function labels(): BelongsToMany { return \$this->belongsToMany(Label::class); }",
            '{{ $item->labels()->count() }}',
        );

        $this->assertCount(1, $this->issueMessagesNaming('labels', $result));
        $this->assertCount(1, $this->issueMessagesNaming('$item->labels()->count()', $result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function columnBesideCalledRelationshipProvider(): array
    {
        return [
            'casts()' => ["protected function casts(): array { return ['labels' => 'array']; }"],
            'attributes property' => ["protected \$attributes = ['labels' => '[]'];"],
            'fillable property' => ["protected \$fillable = ['labels'];"],
        ];
    }

    /**
     * A method declared to return a built-in type cannot be a relationship, so calling it in a
     * view is not flagged on a model not read in full.
     */
    public function test_silent_on_calling_a_method_declared_to_return_a_builtin_type(): void
    {
        $result = $this->analyzeItemView(
            "public function permalink(): string { return '/x'; } public function getPermalinkAttribute() { return '/x'; }",
            '{{ $item->permalink() }}',
        );

        $this->assertSame([], $this->issueMessagesNaming('permalink', $result));
    }

    /**
     * A column name settles a method call in a view too, unless a relationship of that name is
     * proven, so an untyped helper named like a column is not flagged.
     *
     * @dataProvider columnNamedHelperProvider
     */
    #[DataProvider('columnNamedHelperProvider')]
    public function test_silent_on_calling_a_helper_named_like_a_column(string $declaration): void
    {
        $result = $this->analyzeItemView(
            "{$declaration} public function headline() { return strtoupper(\$this->attributes['headline'] ?? ''); }",
            '{{ $item->headline() }}',
        );

        $this->assertSame([], $this->issueMessagesNaming('headline', $result));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function columnNamedHelperProvider(): array
    {
        return [
            'fillable property' => ["protected \$fillable = ['headline'];"],
            'casts()' => ["protected function casts(): array { return ['headline' => 'string']; }"],
        ];
    }

    /**
     * A trait outside the scanned paths overrides the parent's built-in author(), so the read
     * in a view is still flagged.
     */
    public function test_flags_a_parent_method_behind_an_unscanned_trait(): void
    {
        $result = $this->analyze([
            'app/Models/BaseBook.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nabstract class BaseBook extends Model { public function author(): string { return 'x'; } }",
            'app/Models/Book.php' => "<?php\nnamespace App\\Models;\nclass Book extends BaseBook { use \\Acme\\HasWriter; }",
            'app/Http/Controllers/BookController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Book;\nclass BookController { public function index(){ \$books = Book::all(); return view('books.index', compact('books')); } }",
            'resources/views/books/index.blade.php' => "@foreach(\$books as \$book)\n  {{ \$book->author }}\n@endforeach",
        ]);

        $this->assertCount(1, $this->issueMessagesNaming('author', $result));
    }

    /**
     * An Item model with $body, using a trait outside the scanned paths, rendered into a view
     * that runs $expression for each item.
     */
    private function analyzeItemView(string $body, string $expression): ResultInterface
    {
        return $this->analyze([
            'app/Models/Item.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Illuminate\\Database\\Eloquent\\Relations\\BelongsTo;\nuse Illuminate\\Database\\Eloquent\\Relations\\BelongsToMany;\nclass Item extends Model { use \\Vendor\\Pkg\\HasThings; {$body} }",
            'app/Http/Controllers/ItemController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Item;\nclass ItemController { public function index(){ \$items = Item::all(); return view('items.index', compact('items')); } }",
            'resources/views/items/index.blade.php' => "@foreach(\$items as \$item)\n  {$expression}\n@endforeach",
        ]);
    }

    /**
     * spatie/laravel-activitylog's LogsActivity declares only activities(), so a model using it
     * is read in full and a column it does not declare as a method is not a relationship.
     */
    public function test_silent_on_a_column_of_a_model_using_logs_activity(): void
    {
        $result = $this->analyze([
            'app/Models/Newsletter.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Spatie\\Activitylog\\Traits\\LogsActivity;\nclass Newsletter extends Model { use LogsActivity; }",
            'app/Http/Controllers/NewsletterController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Newsletter;\nclass NewsletterController { public function index(){ \$newsletters = Newsletter::all(); return view('newsletters.index', compact('newsletters')); } }",
            'resources/views/newsletters/index.blade.php' => "@foreach(\$newsletters as \$newsletter)\n  {{ \$newsletter->subject }}\n  {{ \$newsletter->activities->count() }}\n@endforeach",
        ]);

        $this->assertSame([], $this->issueMessagesNaming('subject', $result));
        $this->assertCount(1, $this->issueMessagesNaming('activities', $result));
    }

    /** @return list<string> */
    private function issueMessagesNaming(string $name, ResultInterface $result): array
    {
        return array_values(array_filter(
            array_map(fn (Issue $i): string => $i->message, $result->getIssues()),
            fn (string $message): bool => str_contains($message, "'{$name}'"),
        ));
    }

    /**
     * A Newsletter model declaring $column through $attributes or $body, using a trait outside
     * the scanned paths, and a Post model with an author() relationship, each rendered into a
     * view that reads them in a loop.
     */
    private function analyzeAttributeDeclaredColumn(string $imports, string $attributes, string $body, string $column): ResultInterface
    {
        return $this->analyze([
            'app/Models/Newsletter.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Vendor\\Pkg\\HasThings;\n{$imports}\n{$attributes}\nclass Newsletter extends Model { use HasThings; {$body} }",
            'app/Models/Post.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nuse Illuminate\\Database\\Eloquent\\Relations\\BelongsTo;\nclass Post extends Model { public function author(): BelongsTo { return \$this->belongsTo(User::class); } }",
            'app/Http/Controllers/NewsletterController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Newsletter;\nuse App\\Models\\Post;\nclass NewsletterController { public function index(){ \$newsletters = Newsletter::all(); \$posts = Post::all(); return view('newsletters.index', compact('newsletters', 'posts')); } }",
            'resources/views/newsletters/index.blade.php' => "@foreach(\$newsletters as \$newsletter)\n  {{ \$newsletter->{$column} }}\n@endforeach\n@foreach(\$posts as \$post)\n  {{ \$post->author->name }}\n@endforeach",
        ]);
    }

    /**
     * A route file renders views from closures, not controller methods, and the render-site
     * scan used to read only class methods and named functions, so a view rendered this way
     * was never analyzed at all. The recommendation names the route file, which is the only
     * name a closure has.
     */
    public function test_flags_lazy_relation_in_a_view_rendered_from_a_route_closure(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'routes/web.php' => <<<'PHP'
                <?php
                use App\Models\Shelf;
                use Illuminate\Support\Facades\Route;

                Route::get('/shelves', function () {
                    $shelves = Shelf::all();

                    return view('shelves.index', compact('shelves'));
                });
                PHP,
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([['curator', 2]], $this->relationFindings($result));
        $this->assertStringContainsString('web.php', $result->getIssues()[0]->recommendation);
    }

    public function test_silent_when_a_route_closure_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'routes/web.php' => <<<'PHP'
                <?php
                use App\Models\Shelf;
                use Illuminate\Support\Facades\Route;

                Route::get('/shelves', function () {
                    $shelves = Shelf::with('curator')->get();

                    return view('shelves.index', compact('shelves'));
                });
                PHP,
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * Reading a closure changes where a type can come from, not the policy on a variable
     * whose type is never inferred: it is dropped, as it is from a controller.
     */
    public function test_silent_when_a_route_closure_binds_a_variable_of_unknown_type(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'routes/web.php' => <<<'PHP'
                <?php
                use Illuminate\Support\Facades\Route;

                Route::get('/shelves', function () {
                    $shelves = session('recent_shelves');

                    return view('shelves.index', compact('shelves'));
                });
                PHP,
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * Closures nested in a group callback are each their own scope. The sibling route binds
     * the same name to a different model, and if the group callback were read as one scope
     * that assignment would reach the first route's render site, the two sites would
     * disagree on the type, and the merge policy would drop the variable.
     */
    public function test_flags_lazy_relation_in_a_view_rendered_from_a_closure_nested_in_a_route_group(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'routes/web.php' => <<<'PHP'
                <?php
                use App\Models\Book;
                use App\Models\Shelf;
                use Illuminate\Support\Facades\Route;

                Route::prefix('library')->group(function () {
                    Route::get('/shelves', function () {
                        $shelves = Shelf::all();

                        return view('shelves.index', compact('shelves'));
                    });

                    Route::get('/books', function () {
                        $shelves = Book::all();

                        return view('books.index', compact('shelves'));
                    });
                });
                PHP,
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([['curator', 2]], $this->relationFindings($result));
    }

    public function test_flags_lazy_relation_in_a_view_rendered_from_an_arrow_function_route(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'routes/web.php' => <<<'PHP'
                <?php
                use App\Models\Shelf;
                use Illuminate\Support\Facades\Route;

                Route::get('/shelves', fn () => view('shelves.index', ['shelves' => Shelf::all()]));
                PHP,
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([['curator', 2]], $this->relationFindings($result));
    }

    /**
     * A query passed straight into the render array is typed the way the same query
     * assigned to a variable first would be.
     */
    public function test_flags_lazy_relation_bound_inline_in_the_render_array(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ return view('shelves.index', ['shelves' => Shelf::all()]); } }",
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ]);

        $this->assertSame([['curator', 2]], $this->relationFindings($result));
        $this->assertStringContainsString('ShelfController::index', $result->getIssues()[0]->recommendation);
    }

    public function test_flags_lazy_relation_bound_inline_through_with(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ return view('shelves.index')->with('shelves', Shelf::where('open', true)->get()); } }",
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ]);

        $this->assertSame([['curator', 2]], $this->relationFindings($result));
    }

    public function test_silent_when_an_inline_binding_eager_loads(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ return view('shelves.index', ['shelves' => Shelf::with('curator')->get()]); } }",
            'resources/views/shelves/index.blade.php' => self::SHELF_VIEW,
        ]);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * The inner loop iterates a relation the model declares as hasMany(Book::class), so its
     * variable is a Book, and eager-loading only `books` leaves `publisher` lazy on every
     * book. The recommendation names the path to eager-load from the controller, since
     * `with('publisher')` on the shelves query would raise RelationNotFoundException.
     */
    public function test_flags_lazy_relation_on_the_element_of_a_nested_foreach(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$shelves = Shelf::with('books')->get(); return view('shelves.nested', compact('shelves')); } }",
            'resources/views/shelves/nested.blade.php' => self::NESTED_SHELF_VIEW,
        ]);

        $this->assertSame([['publisher', 3]], $this->relationFindings($result));
        $recommendation = $result->getIssues()[0]->recommendation;
        $this->assertStringContainsString('ShelfController::index', $recommendation);
        $this->assertStringContainsString("'books.publisher'", $recommendation);
    }

    public function test_nested_foreach_without_eager_loading_flags_both_levels(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$shelves = Shelf::all(); return view('shelves.nested', compact('shelves')); } }",
            'resources/views/shelves/nested.blade.php' => self::NESTED_SHELF_VIEW,
        ]);

        $this->assertSame([['books', 2], ['publisher', 3]], $this->relationFindings($result));
    }

    /**
     * Only a relation whose related model the declaration names types the inner loop. Here
     * the class comes from a helper the scan cannot follow, so the element stays untyped
     * and silent rather than guessed at.
     */
    public function test_nested_foreach_over_a_relation_with_an_unnamed_related_model_is_silent(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Shelf extends Model { public function books(){ return \$this->hasMany(\$this->bookModel()); } }",
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$shelves = Shelf::with('books')->get(); return view('shelves.nested', compact('shelves')); } }",
            'resources/views/shelves/nested.blade.php' => self::NESTED_SHELF_VIEW,
        ]);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * Rows from the query builder are plain objects, so a binding built from DB::table() is
     * not a model collection and reading a column off a row is not a relationship access.
     *
     * @return array<string, array{string}>
     */
    public static function nonModelBindings(): array
    {
        return [
            'inline query builder rows' => ["use Illuminate\\Support\\Facades\\DB;\nclass RowController { public function index(){ return view('rows.index', ['rows' => DB::table('rows')->get()]); } }"],
            'cache value through with' => ["use Illuminate\\Support\\Facades\\Cache;\nclass RowController { public function index(){ return view('rows.index')->with('rows', Cache::get('rows')); } }"],
            'query builder rows through a variable' => ["use Illuminate\\Support\\Facades\\DB;\nclass RowController { public function index(){ \$rows = DB::table('rows')->get(); return view('rows.index', compact('rows')); } }"],
        ];
    }

    /**
     * @dataProvider nonModelBindings
     */
    #[DataProvider('nonModelBindings')]
    public function test_silent_when_the_binding_is_not_a_model_query(string $controller): void
    {
        $result = $this->analyze([
            'app/Http/Controllers/RowController.php' => "<?php\nnamespace App\\Http\\Controllers;\n".$controller,
            'resources/views/rows/index.blade.php' => "@foreach(\$rows as \$row)\n  {{ \$row->firstname }}\n@endforeach",
        ]);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * A model whose short name is also a facade's is still a model once its import is
     * read, so the binding keeps its type.
     */
    public function test_flags_lazy_relation_on_a_model_sharing_a_facade_name(): void
    {
        $result = $this->analyze([
            'app/Models/Event.php' => "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Event extends Model { public function venue(){ return \$this->belongsTo(Venue::class); } }",
            'app/Http/Controllers/EventController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Event;\nclass EventController { public function index(){ return view('events.index', ['events' => Event::all()]); } }",
            'resources/views/events/index.blade.php' => "@foreach(\$events as \$event)\n  {{ \$event->venue->name }}\n@endforeach",
        ]);

        $this->assertSame([['venue', 2]], $this->relationFindings($result));
    }

    public function test_nested_eager_load_inside_a_closure_keyed_with_is_honoured(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ return view('shelves.nested', ['shelves' => Shelf::with(['books' => fn (\$q) => \$q->with('publisher')])->get()]); } }",
            'resources/views/shelves/nested.blade.php' => self::NESTED_SHELF_VIEW,
        ]);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * The inner loop runs once per shelf, so a lazy relation of the shelf read inside it is
     * one query per shelf, and is reported once.
     */
    public function test_flags_relation_of_the_outer_loop_variable_read_in_the_inner_loop(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$shelves = Shelf::with('books.publisher')->get(); return view('shelves.nested', compact('shelves')); } }",
            'resources/views/shelves/nested.blade.php' => "@foreach(\$shelves as \$shelf)\n  @foreach(\$shelf->books as \$book)\n    {{ \$shelf->curator->name }}\n  @endforeach\n@endforeach",
        ]);

        $this->assertSame([['curator', 3]], $this->relationFindings($result));
    }

    public function test_eager_load_on_the_relation_collection_in_the_template_is_honoured(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$shelves = Shelf::with('books')->get(); return view('shelves.nested', compact('shelves')); } }",
            'resources/views/shelves/nested.blade.php' => "@foreach(\$shelves as \$shelf)\n  @php \$shelf->books->load('publisher'); @endphp\n  @foreach(\$shelf->books as \$book)\n    {{ \$book->publisher->name }}\n  @endforeach\n@endforeach",
        ]);

        $this->assertSame([], $this->relationFindings($result));
    }

    /**
     * Each finding's recommendation names the relation path as it stood when the access was
     * read: a later loop rebinding the same name over a relation does not rewrite it.
     */
    public function test_recommendation_keeps_the_path_of_the_loop_that_read_it(): void
    {
        $result = $this->analyze([
            'app/Models/Shelf.php' => self::SHELF_MODEL,
            'app/Models/Book.php' => self::BOOK_MODEL,
            'app/Http/Controllers/ShelfController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Book;\nuse App\\Models\\Shelf;\nclass ShelfController { public function index(){ \$books = Book::all(); \$shelves = Shelf::with('books')->get(); return view('shelves.mixed', compact('books', 'shelves')); } }",
            'resources/views/shelves/mixed.blade.php' => "@foreach(\$books as \$book)\n  {{ \$book->publisher->name }}\n@endforeach\n@foreach(\$shelves as \$shelf)\n  @foreach(\$shelf->books as \$book)\n    {{ \$book->isbn }}\n  @endforeach\n@endforeach",
        ]);

        $this->assertSame([['publisher', 2]], $this->relationFindings($result));
        $this->assertStringContainsString("Eager-load the 'publisher' relation", $result->getIssues()[0]->recommendation);
    }

    public function test_silent_when_a_route_binds_a_relation_query_rooted_at_the_auth_facade(): void
    {
        $result = $this->analyze([
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Auth;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/', fn () => view('shelves.index', ['shelves' => Auth::user()->shelves()->get()]));",
            'resources/views/shelves/index.blade.php' => "@foreach(\$shelves as \$shelf)\n  {{ \$shelf->subtitle }}\n@endforeach",
        ], ['app', 'routes', 'resources/views']);

        $this->assertSame([], $this->relationFindings($result));
    }

    public function test_proven_relation_read_in_a_view_stays_high(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
    }

    /**
     * City's parent is outside the scanned paths, so the scan holds no relationship set for it
     * and airports is reported on its name alone, at a lower grade than a proven relation.
     */
    public function test_relation_decided_by_the_name_heuristic_in_a_view_is_downgraded(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nclass City extends \\Acme\\Catalog\\RecordBase {}",
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports->count() }}\n@endforeach",
        ]);

        $issues = $this->airportIssues($result);
        $this->assertCount(1, $issues);
        $this->assertSame("Potential N+1 query: accessing 'airports' inside loop", $issues[0]->message);
        $this->assertSame(Severity::Medium, $issues[0]->severity);
    }

    /**
     * The same holds for a query run through that relation: airports() is decided by its name
     * alone, so the query it runs per iteration is graded Medium too.
     */
    public function test_relation_query_decided_by_the_name_heuristic_in_a_view_is_downgraded(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => "<?php\nnamespace App\\Models;\nclass City extends \\Acme\\Catalog\\RecordBase {}",
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $issues = $this->queryExecutionIssues($result);
        $this->assertCount(1, $issues);
        $this->assertSame("N+1 query: executing '\$city->airports()->count()' inside loop", $issues[0]->message);
        $this->assertSame(Severity::Medium, $issues[0]->severity);
    }

    public function test_proven_relation_query_in_a_view_stays_high(): void
    {
        $result = $this->analyze([
            'app/Models/City.php' => self::CITY_MODEL,
            'app/Http/Controllers/CityController.php' => self::CITY_CONTROLLER,
            'resources/views/cities/index.blade.php' => "@foreach(\$cities as \$city)\n  {{ \$city->airports()->count() }}\n@endforeach",
        ]);

        $issues = $this->queryExecutionIssues($result);
        $this->assertCount(1, $issues);
        $this->assertSame(Severity::High, $issues[0]->severity);
    }
}
