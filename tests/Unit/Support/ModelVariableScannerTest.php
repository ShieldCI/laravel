<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PhpParser\NodeTraverser;
use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\ModelVariableScanner;

class ModelVariableScannerTest extends TestCase
{
    private function scan(string $code): ModelVariableScanner
    {
        $ast = (new AstParser)->parseCode("<?php\n".$code);
        $scanner = new ModelVariableScanner;
        $traverser = new NodeTraverser;
        $traverser->addVisitor($scanner);
        $traverser->traverse($ast);

        return $scanner;
    }

    public function test_infers_collection_type_from_get(): void
    {
        $s = $this->scan('$cities = City::all();');
        $this->assertSame('Collection<City>', $s->typeOf('cities'));
        $this->assertSame('City', $s->modelOf('cities'));
        $this->assertSame([], $s->eagerLoadsOf('cities'));
    }

    public function test_infers_single_model_from_find(): void
    {
        $s = $this->scan('$city = City::find(1);');
        $this->assertSame('City', $s->typeOf('city'));
        $this->assertSame('City', $s->modelOf('city'));
    }

    public function test_tracks_eager_loads_from_with_chain(): void
    {
        $s = $this->scan("\$cities = City::with(['airports', 'region'])->get();");
        $this->assertSame('Collection<City>', $s->typeOf('cities'));
        $this->assertEqualsCanonicalizing(['airports', 'region'], $s->eagerLoadsOf('cities'));
    }

    public function test_tracks_load_on_existing_variable(): void
    {
        $s = $this->scan("\$cities = City::all();\n\$cities->load('airports');");
        $this->assertEqualsCanonicalizing(['airports'], $s->eagerLoadsOf('cities'));
    }

    public function test_unknown_variable_returns_null(): void
    {
        $s = $this->scan('$x = someHelper();');
        $this->assertNull($s->typeOf('x'));
        $this->assertNull($s->modelOf('x'));
        $this->assertSame([], $s->eagerLoadsOf('x'));
    }
}
