<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Analyzers\BestPractices;

use Illuminate\Config\Repository;
use ShieldCI\Analyzers\BestPractices\EloquentNPlusOneAnalyzer;
use ShieldCI\Analyzers\BestPractices\LogicInBladeAnalyzer;
use ShieldCI\AnalyzersCore\Contracts\AnalyzerInterface;
use ShieldCI\AnalyzersCore\Contracts\ResultInterface;
use ShieldCI\AnalyzersCore\Enums\ParseFailureCause;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\AnalyzersCore\ValueObjects\Issue;
use ShieldCI\Tests\AnalyzerTestCase;

class EloquentNPlusOneBladeTest extends AnalyzerTestCase
{
    private const CITY_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass City extends Model { public function airports(){ return \$this->hasMany(Airport::class); } }";

    private const AIRPORT_MODEL = "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Airport extends Model {}";

    private const CITY_CONTROLLER = "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\City;\nclass CityController { public function index(){ \$cities = City::all(); return view('cities.index', compact('cities')); } }";

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

    /** @param array<string,string> $files */
    private function analyze(array $files): ResultInterface
    {
        $dir = $this->createTempDirectory($files);
        $analyzer = new EloquentNPlusOneAnalyzer(new AstParser);
        $analyzer->setBasePath($dir);
        $analyzer->setPaths(['app', 'resources/views']);

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
     * through @php use. One such template must be skipped like an unparseable file: it cannot
     * take the whole analyzer down with it, and the view next to it still has to be reported.
     */
    public function test_survives_a_template_whose_imports_collide(): void
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
        $this->assertSame(['index.blade.php'], $files);
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
     * still inside the OUTER loop body — and it is caught before the inner loop's (buggy)
     * type inference ever comes into play. See the task report for the mistyping this
     * nested compilation causes on `$airport` itself, and why it doesn't produce a false
     * positive for this fixture.
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
     * the correct (but never-inferred, post-fix) model. This is the canonical nested-Blade
     * shape and exactly the false-positive class this analyzer exists to prevent.
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
}
